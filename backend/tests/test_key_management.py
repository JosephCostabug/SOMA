import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from app.key_management import (
    DelegationVerificationError,
    KeyConfigurationError,
    KeyPurpose,
    KeyState,
    VerificationKey,
    VerificationKeySet,
    verify_ground_delegation,
)
from app.mission_identity import ActorType, DelegationState, MissionDelegation


UTC = timezone.utc
ISSUER = "beyond-dynamics-ground"
MISSION_ID = "mission-001"
ONBOARD_SERVICE_ID = "onboard-service-001"
GROUND_KEY_ID = "ground-key-01"
ONBOARD_KEY_ID = "onboard-key-01"
GROUND_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
GROUND_PUBLIC_KEY_PEM = GROUND_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("ascii")


def _now():
    return datetime.now(UTC).replace(microsecond=0)


def _verification_key(**overrides):
    now = _now()
    values = {
        "key_id": GROUND_KEY_ID,
        "issuer": ISSUER,
        "purpose": KeyPurpose.GROUND_DELEGATION,
        "state": KeyState.ACTIVE,
        "public_key_pem": GROUND_PUBLIC_KEY_PEM,
        "valid_from": now - timedelta(days=1),
        "signing_not_after": now + timedelta(days=1),
        "verify_not_after": now + timedelta(days=2),
    }
    return VerificationKey(**(values | overrides))


def _key_set(key=None, **overrides):
    key = key or _verification_key()
    values = {
        "issuer": ISSUER,
        "trusted_key_ids": {key.key_id},
        "keys": (key,),
    }
    return VerificationKeySet(**(values | overrides))


def _delegation(now=None, **overrides):
    now = now or _now()
    values = {
        "delegation_id": UUID("c54d86ca-59f9-41b6-9dbb-f18b3976fc31"),
        "mission_id": MISSION_ID,
        "ground_issuer": ISSUER,
        "ground_key_id": GROUND_KEY_ID,
        "onboard_service_id": ONBOARD_SERVICE_ID,
        "onboard_key_id": ONBOARD_KEY_ID,
        "allowed_actor_types": {ActorType.USER, ActorType.DEVICE},
        "permissions": {"readings:read", "sync:write"},
        "astronaut_ids": {"astronaut-01"},
        "policy_id": "mission-policy-v1",
        "state": DelegationState.ACTIVE,
        "issued_at": now - timedelta(minutes=1),
        "valid_from": now - timedelta(seconds=30),
        "expires_at": now + timedelta(minutes=5),
        "max_token_lifetime_seconds": 300,
    }
    return MissionDelegation(**(values | overrides))


def _signed_delegation(delegation=None, *, header_overrides=None, claim_overrides=None):
    delegation = delegation or _delegation()
    claims = {
        "iss": ISSUER,
        "aud": ONBOARD_SERVICE_ID,
        "iat": int(delegation.issued_at.timestamp()),
        "nbf": int(delegation.valid_from.timestamp()),
        "exp": int(delegation.expires_at.timestamp()),
        "jti": str(delegation.delegation_id),
        "delegation": delegation.model_dump(mode="json"),
    }
    claims.update(claim_overrides or {})
    headers = {
        "kid": GROUND_KEY_ID,
        "typ": "mission-delegation+jwt",
    }
    headers.update(header_overrides or {})
    return jwt.encode(
        claims,
        GROUND_PRIVATE_KEY,
        algorithm="RS256",
        headers=headers,
    )


def _replace_header(token, **overrides):
    header_segment, payload_segment, signature_segment = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(header_segment + "=="))
    header.update(overrides)
    encoded_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    return ".".join((encoded_header, payload_segment, signature_segment))


def _verify(token, *, now=None, key_set=None, mission_id=MISSION_ID):
    return verify_ground_delegation(
        token,
        key_set=key_set or _key_set(),
        expected_mission_id=mission_id,
        expected_onboard_service_id=ONBOARD_SERVICE_ID,
        now=now or _now(),
    )


def test_verifies_ground_signed_delegation_against_pinned_key():
    delegation = _delegation()

    verified = _verify(_signed_delegation(delegation))

    assert verified == delegation


@pytest.mark.parametrize(
    ("header_overrides", "claim_overrides", "error"),
    [
        ({"kid": "unknown-key"}, {}, "não está na lista confiável"),
        ({"alg": "HS256"}, {}, "cabeçalho"),
        ({"jku": "https://attacker.invalid/keys"}, {}, "cabeçalho"),
        ({}, {"mission_id": "another-mission"}, "claims"),
        ({}, {"aud": "another-service"}, "claims"),
        ({}, {"iss": "another-ground"}, "claims"),
        ({}, {"extra": "not-allowed"}, "claims"),
    ],
)
def test_rejects_untrusted_headers_and_claims(
    header_overrides, claim_overrides, error
):
    if header_overrides.get("alg") == "HS256":
        token = _replace_header(_signed_delegation(), **header_overrides)
    else:
        token = _signed_delegation(
            header_overrides=header_overrides,
            claim_overrides=claim_overrides,
        )

    with pytest.raises(DelegationVerificationError, match=error):
        _verify(token)


def test_rejects_bad_signature():
    token = _signed_delegation()
    parts = token.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]

    with pytest.raises(DelegationVerificationError, match="assinatura"):
        _verify(".".join(parts))


def test_rejects_expired_or_not_yet_valid_delegation():
    now = _now()
    expired = _delegation(
        now,
        issued_at=now - timedelta(hours=2),
        valid_from=now - timedelta(hours=2),
        expires_at=now - timedelta(seconds=1),
    )
    future = _delegation(
        now,
        issued_at=now + timedelta(minutes=1),
        valid_from=now + timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
    )

    with pytest.raises(DelegationVerificationError, match="ainda não é válida ou expirou"):
        _verify(_signed_delegation(expired), now=now)
    with pytest.raises(DelegationVerificationError, match="ainda não é válida ou expirou"):
        _verify(_signed_delegation(future), now=now)


def test_rejects_delegation_for_another_mission_or_service():
    with pytest.raises(DelegationVerificationError, match="missão"):
        _verify(
            _signed_delegation(),
            mission_id="another-mission",
        )

    delegation = _delegation(onboard_service_id="another-service")
    token = _signed_delegation(delegation)
    with pytest.raises(DelegationVerificationError, match="não corresponde"):
        _verify(token)


@pytest.mark.parametrize(
    "overrides",
    [
        {"public_key_pem": "not-a-public-key"},
        {"public_key_pem": "-----BEGIN PRIVATE KEY-----\\ninvalid\\n-----END PRIVATE KEY-----"},
    ],
)
def test_verification_key_rejects_malformed_pem(overrides):
    with pytest.raises(ValidationError, match="chave pública PEM válida"):
        _verification_key(**overrides)


def test_verification_key_requires_rsa_2048_or_larger():
    small_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    small_public_pem = small_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    with pytest.raises(ValidationError, match="pelo menos 2048 bits"):
        _verification_key(public_key_pem=small_public_pem)


def test_key_set_rejects_duplicate_untrusted_or_wrong_purpose_keys():
    key = _verification_key()
    with pytest.raises(ValidationError, match="key_id tem de ser único"):
        _key_set(keys=(key, key))
    with pytest.raises(ValidationError, match="lista confiável"):
        _key_set(trusted_key_ids={"another-key"})
    with pytest.raises(ValidationError, match="autoridade configurada"):
        _key_set(keys=(key.model_copy(update={"issuer": "another-issuer"}),))
    with pytest.raises(ValidationError, match="chaves da autoridade terrestre"):
        _key_set(keys=(key.model_copy(update={"purpose": KeyPurpose.ONBOARD_TOKEN}),))


def test_rejects_revoked_or_out_of_window_key():
    now = _now()
    revoked = _verification_key(
        state=KeyState.REVOKED,
        revoked_at=now - timedelta(seconds=1),
    )
    token = _signed_delegation()
    with pytest.raises(DelegationVerificationError, match="chave de assinatura foi revogada"):
        _verify(token, key_set=_key_set(revoked), now=now)

    expired_for_verification = _verification_key(
        valid_from=now - timedelta(days=3),
        signing_not_after=now - timedelta(days=1),
        verify_not_after=now - timedelta(hours=1),
    )
    prior_delegation = _delegation(
        now,
        issued_at=now - timedelta(days=2),
        valid_from=now - timedelta(days=2),
        expires_at=now + timedelta(minutes=5),
    )
    with pytest.raises(DelegationVerificationError, match="validade de verificação"):
        _verify(
            _signed_delegation(prior_delegation),
            key_set=_key_set(expired_for_verification),
            now=now,
        )


def test_retired_key_can_verify_prior_delegations_during_overlap():
    now = _now()
    key = _verification_key(
        state=KeyState.RETIRED,
        signing_not_after=now - timedelta(seconds=1),
        verify_not_after=now + timedelta(days=1),
    )
    delegation = _delegation(
        now,
        issued_at=now - timedelta(minutes=2),
        valid_from=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
    )

    verified = _verify(
        _signed_delegation(delegation),
        key_set=_key_set(key),
        now=now,
    )

    assert verified == delegation


def test_rejects_naive_verification_time():
    with pytest.raises(DelegationVerificationError, match="fuso horário"):
        _verify(_signed_delegation(), now=datetime(2030, 1, 1))


def test_unknown_key_lookup_fails_explicitly():
    with pytest.raises(KeyConfigurationError, match="lista confiável"):
        _key_set().get_ground_key("unknown-key")
