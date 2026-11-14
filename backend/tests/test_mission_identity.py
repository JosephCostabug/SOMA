from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.mission_identity import (
    ActorType,
    DelegationState,
    GroundIdentityAuthority,
    IdentityState,
    Mission,
    MissionDelegation,
    MissionIdentity,
    MissionIdentityConfiguration,
    MissionState,
)


UTC = timezone.utc
MISSION_START = datetime(2030, 1, 1, tzinfo=UTC)
MISSION_END = datetime(2030, 7, 1, tzinfo=UTC)
DELEGATION_ID = UUID("c54d86ca-59f9-41b6-9dbb-f18b3976fc31")


def _mission(**overrides):
    values = {
        "mission_id": "mission-001",
        "state": MissionState.ACTIVE,
        "valid_from": MISSION_START,
        "expires_at": MISSION_END,
    }
    return Mission(**(values | overrides))


def _ground_authority(**overrides):
    values = {
        "issuer": "beyond-dynamics-ground",
        "trusted_key_ids": {"ground-root-01"},
    }
    return GroundIdentityAuthority(**(values | overrides))


def _service_identity(**overrides):
    values = {
        "identity_id": "onboard-service-001",
        "mission_id": "mission-001",
        "actor_type": ActorType.SERVICE,
        "state": IdentityState.ACTIVE,
        "permissions": {"readings:read", "sync:write"},
        "astronaut_ids": {"astronaut-01", "astronaut-02"},
        "valid_from": MISSION_START,
        "expires_at": MISSION_END,
        "key_id": "onboard-key-01",
        "public_key_thumbprint": "sha256:service-key-thumbprint",
    }
    return MissionIdentity(**(values | overrides))


def _delegation(**overrides):
    values = {
        "delegation_id": DELEGATION_ID,
        "mission_id": "mission-001",
        "ground_issuer": "beyond-dynamics-ground",
        "ground_key_id": "ground-root-01",
        "onboard_service_id": "onboard-service-001",
        "onboard_key_id": "onboard-key-01",
        "allowed_actor_types": {ActorType.USER, ActorType.DEVICE},
        "permissions": {"readings:read", "sync:write"},
        "astronaut_ids": {"astronaut-01"},
        "policy_id": "policy-v1",
        "state": DelegationState.ACTIVE,
        "issued_at": MISSION_START,
        "valid_from": MISSION_START + timedelta(days=1),
        "expires_at": MISSION_END - timedelta(days=1),
        "max_token_lifetime_seconds": 900,
    }
    return MissionDelegation(**(values | overrides))


def _configuration(*, mission=None, ground_authority=None, identities=None, delegations=None):
    return MissionIdentityConfiguration(
        mission=mission or _mission(),
        ground_authority=ground_authority or _ground_authority(),
        identities=tuple(identities or [_service_identity()]),
        delegations=tuple(delegations or [_delegation()]),
    )


def test_delegation_permits_token_within_all_granted_bounds():
    delegation = _delegation()
    token_iat = MISSION_START + timedelta(days=2)

    permitted = delegation.permits_token(
        mission_id="mission-001",
        actor_type=ActorType.DEVICE,
        permissions=frozenset({"sync:write"}),
        astronaut_ids=frozenset({"astronaut-01"}),
        issued_at=token_iat,
        expires_at=token_iat + timedelta(minutes=10),
    )

    assert permitted


@pytest.mark.parametrize(
    "overrides",
    [
        {"mission_id": "another-mission"},
        {"actor_type": ActorType.SERVICE},
        {"permissions": frozenset({"admin:all"})},
        {"astronaut_ids": frozenset({"astronaut-02"})},
        {
            "issued_at": MISSION_START + timedelta(hours=12),
            "expires_at": MISSION_START + timedelta(hours=12, minutes=10),
        },
        {
            "expires_at": MISSION_START
            + timedelta(days=1, seconds=900),
        },
    ],
)
def test_delegation_rejects_token_outside_granted_bounds(overrides):
    delegation = _delegation()
    token_iat = MISSION_START + timedelta(days=2)
    claims = {
        "mission_id": "mission-001",
        "actor_type": ActorType.DEVICE,
        "permissions": frozenset({"sync:write"}),
        "astronaut_ids": frozenset({"astronaut-01"}),
        "issued_at": token_iat,
        "expires_at": token_iat + timedelta(minutes=10),
    }
    claims.update(overrides)

    assert not delegation.permits_token(**claims)


def test_revoked_delegation_cannot_authorize_tokens():
    delegation = _delegation(
        state=DelegationState.REVOKED,
        revoked_at=MISSION_START + timedelta(days=5),
    )
    token_iat = MISSION_START + timedelta(days=2)

    assert not delegation.permits_token(
        mission_id="mission-001",
        actor_type=ActorType.DEVICE,
        permissions=frozenset({"sync:write"}),
        astronaut_ids=frozenset({"astronaut-01"}),
        issued_at=token_iat,
        expires_at=token_iat + timedelta(minutes=10),
    )


def test_configuration_links_ground_mission_and_onboard_service():
    configuration = _configuration()

    assert configuration.mission.mission_id == "mission-001"
    assert configuration.delegations[0].onboard_key_id == "onboard-key-01"


@pytest.mark.parametrize(
    ("delegation_overrides", "message"),
    [
        ({"ground_issuer": "untrusted-ground"}, "outra autoridade terrestre"),
        ({"ground_key_id": "unknown-root"}, "não é confiável"),
        ({"mission_id": "another-mission"}, "outra missão"),
        ({"onboard_key_id": "unknown-onboard-key"}, "serviço a bordo"),
        ({"permissions": {"admin:all"}}, "exceder as permissões"),
        ({"astronaut_ids": {"astronaut-99"}}, "exceder o escopo"),
    ],
)
def test_configuration_rejects_invalid_delegation_relationships(
    delegation_overrides, message
):
    with pytest.raises(ValidationError, match=message):
        _configuration(delegations=[_delegation(**delegation_overrides)])


def test_configuration_rejects_identity_from_another_mission():
    with pytest.raises(ValidationError, match="outra missão"):
        _configuration(
            identities=[_service_identity(mission_id="another-mission")]
        )


def test_configuration_rejects_delegation_outliving_onboard_identity():
    with pytest.raises(ValidationError, match="validade do serviço a bordo"):
        _configuration(
            identities=[
                _service_identity(expires_at=MISSION_END - timedelta(days=2))
            ]
        )


def test_active_delegation_requires_provisioned_onboard_identity():
    with pytest.raises(ValidationError, match="identidade do serviço provisionada"):
        _configuration(
            identities=[_service_identity(state=IdentityState.SUSPENDED)]
        )


def test_configuration_rejects_duplicate_identity_and_delegation_ids():
    with pytest.raises(ValidationError, match="identity_id tem de ser único"):
        _configuration(identities=[_service_identity(), _service_identity()])

    with pytest.raises(ValidationError, match="delegation_id tem de ser único"):
        _configuration(delegations=[_delegation(), _delegation()])


def test_device_identity_requires_a_provisioned_public_key_reference():
    with pytest.raises(ValidationError, match="key_id e public_key_thumbprint"):
        MissionIdentity(
            identity_id="device-001",
            mission_id="mission-001",
            actor_type=ActorType.DEVICE,
            state=IdentityState.PROVISIONED,
            permissions={"sync:write"},
            astronaut_ids={"astronaut-01"},
            valid_from=MISSION_START,
            expires_at=MISSION_END,
        )


def test_temporal_policy_values_are_required_and_validated():
    with pytest.raises(ValidationError):
        MissionDelegation(
            delegation_id=DELEGATION_ID,
            mission_id="mission-001",
            ground_issuer="beyond-dynamics-ground",
            ground_key_id="ground-root-01",
            onboard_service_id="onboard-service-001",
            onboard_key_id="onboard-key-01",
            allowed_actor_types={ActorType.DEVICE},
            permissions={"sync:write"},
            astronaut_ids={"astronaut-01"},
            policy_id="policy-v1",
            state=DelegationState.ACTIVE,
            issued_at=MISSION_START,
            valid_from=MISSION_START,
            expires_at=MISSION_END,
        )

    with pytest.raises(ValidationError, match="fuso horário"):
        _delegation(valid_from=datetime(2030, 1, 2))

    with pytest.raises(ValidationError, match="anterior a expires_at"):
        _delegation(valid_from=MISSION_END)
