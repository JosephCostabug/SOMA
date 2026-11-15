import hashlib
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
import sqlite3
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.database import connect_database, initialize_database
from app.main import app
from app.identity_bootstrap import (
    AuthenticationPublicKey,
    IdentityBootstrapError,
    MissionIdentityBootstrap,
    OnboardTokenVerifier,
    load_identity_bootstrap,
)
from app.key_management import (
    KeyPurpose,
    KeyState,
    VerificationKey,
    VerificationKeySet,
)
from app.nasa_osdr import (
    OSDRDatasetFile,
    OSDRDatasetSearchHit,
    OSDRMetadataError,
    OSDRPublicInspiration4Dataset,
    OSDRStudyMetadata,
)
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
from app.provisioning import load_provisioned_mission_configuration
from app.schemas import Metric, MonitoringAlertRule
from app.token_service import (
    CredentialIssueError,
    OnboardTokenService,
    RefreshTokenError,
    RefreshTokenReuseError,
)


_ISSUER = "onboard-service-001"
_AUDIENCE = "health-monitoring-api"
_MISSION_ID = "mission-test-001"
_GROUND_ISSUER = "ground-test-authority"
_GROUND_KEY_ID = "ground-test-key"
_ONBOARD_KEY_ID = "onboard-key-01"
_DEVICE_ID = "99d52a98-95e3-48ae-a0c2-24d888d1183f"
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()
_GROUND_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_GROUND_PUBLIC_KEY = _GROUND_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()
_ONBOARD_FINGERPRINT = hashlib.sha256(
    _PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
).hexdigest()
_AUTH_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_AUTH_PUBLIC_KEY = _AUTH_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()
_AUTH_FINGERPRINT = hashlib.sha256(
    _AUTH_PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
).hexdigest()


def _create_bootstrap_file(
    path,
    monitoring_alert_rules=(),
    enable_alert_configuration=False,
    enable_alert_approval=False,
    enable_alert_acknowledgement=False,
    enable_offline_authentication=False,
    enable_scientific_data=False,
):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    mission_start = now - timedelta(days=30)
    mission_end = now + timedelta(days=365)
    alert_permissions = {"alerts:configure"} if enable_alert_configuration else set()
    if enable_alert_approval:
        alert_permissions.add("alerts:approve")
    if enable_alert_acknowledgement:
        alert_permissions.add("alerts:acknowledge")
    scientific_data_permissions = (
        {
            "scientific-data:read",
            "scientific-data:sync",
            "scientific-data:import",
        }
        if enable_scientific_data
        else set()
    )
    user_authentication_key_id = (
        "user-01-auth-key" if enable_offline_authentication else None
    )
    identities = (
        MissionIdentity(
            identity_id=_ISSUER,
            mission_id=_MISSION_ID,
            actor_type=ActorType.SERVICE,
            state=IdentityState.ACTIVE,
            permissions=frozenset(
                {"readings:read", "readings:write", "sync:write"}
                | alert_permissions
                | scientific_data_permissions
            ),
            astronaut_ids=frozenset({"astronaut-01", "astronaut-02"}),
            valid_from=mission_start,
            expires_at=mission_end,
            key_id=_ONBOARD_KEY_ID,
            public_key_thumbprint=f"sha256:{_ONBOARD_FINGERPRINT}",
        ),
        MissionIdentity(
            identity_id="user-01",
            mission_id=_MISSION_ID,
            actor_type=ActorType.USER,
            state=IdentityState.ACTIVE,
            permissions=frozenset(
                {"readings:read", "readings:write"}
                | alert_permissions
                | scientific_data_permissions
            ),
            astronaut_ids=frozenset({"astronaut-01", "astronaut-02"}),
            valid_from=mission_start,
            expires_at=mission_end,
            key_id=user_authentication_key_id,
            public_key_thumbprint=(
                f"sha256:{_AUTH_FINGERPRINT}"
                if enable_offline_authentication
                else None
            ),
        ),
        *(
            MissionIdentity(
                identity_id=device_id,
                mission_id=_MISSION_ID,
                actor_type=ActorType.DEVICE,
                state=IdentityState.ACTIVE,
                permissions=frozenset({"sync:write"}),
                astronaut_ids=frozenset({"astronaut-01", "astronaut-02"}),
                valid_from=mission_start,
                expires_at=mission_end,
                key_id=f"{device_id}-key",
                public_key_thumbprint=f"sha256:{device_id}-thumbprint",
            )
            for device_id in (_DEVICE_ID, "another-device")
        ),
    )
    base_configuration = MissionIdentityConfiguration(
        mission=Mission(
            mission_id=_MISSION_ID,
            state=MissionState.ACTIVE,
            valid_from=mission_start,
            expires_at=mission_end,
        ),
        ground_authority=GroundIdentityAuthority(
            issuer=_GROUND_ISSUER,
            trusted_key_ids=frozenset({_GROUND_KEY_ID}),
        ),
        identities=identities,
        delegations=(),
    )
    ground_key = VerificationKey(
        key_id=_GROUND_KEY_ID,
        issuer=_GROUND_ISSUER,
        purpose=KeyPurpose.GROUND_DELEGATION,
        state=KeyState.ACTIVE,
        public_key_pem=_GROUND_PUBLIC_KEY,
        valid_from=mission_start,
        signing_not_after=mission_end,
        verify_not_after=mission_end,
    )
    key_set = VerificationKeySet(
        issuer=_GROUND_ISSUER,
        trusted_key_ids=frozenset({_GROUND_KEY_ID}),
        keys=(ground_key,),
    )
    delegation = MissionDelegation(
        delegation_id="c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        mission_id=_MISSION_ID,
        ground_issuer=_GROUND_ISSUER,
        ground_key_id=_GROUND_KEY_ID,
        onboard_service_id=_ISSUER,
        onboard_key_id=_ONBOARD_KEY_ID,
        allowed_actor_types=frozenset({ActorType.USER, ActorType.DEVICE}),
        permissions=frozenset(
            {"readings:read", "readings:write", "sync:write"}
            | alert_permissions
            | scientific_data_permissions
        ),
        astronaut_ids=frozenset({"astronaut-01", "astronaut-02"}),
        policy_id="test-policy",
        state=DelegationState.ACTIVE,
        issued_at=now - timedelta(minutes=1),
        valid_from=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=30),
        max_token_lifetime_seconds=3600,
    )
    delegation_token = jwt.encode(
        {
            "iss": _GROUND_ISSUER,
            "aud": _ISSUER,
            "iat": int(delegation.issued_at.timestamp()),
            "nbf": int(delegation.valid_from.timestamp()),
            "exp": int(delegation.expires_at.timestamp()),
            "jti": str(delegation.delegation_id),
            "delegation": delegation.model_dump(mode="json"),
        },
        _GROUND_PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": _GROUND_KEY_ID, "typ": "mission-delegation+jwt"},
    )
    bootstrap = MissionIdentityBootstrap(
        base_configuration=base_configuration,
        ground_keys=key_set,
        onboard_token_verifier=OnboardTokenVerifier(
            key_id=_ONBOARD_KEY_ID,
            public_key_pem=_PUBLIC_KEY,
            audience=_AUDIENCE,
        ),
        initial_signed_delegation_tokens=(delegation_token,),
        monitoring_alert_rules=monitoring_alert_rules,
        authentication_keys=(
            (
                AuthenticationPublicKey(
                    identity_id="user-01",
                    key_id="user-01-auth-key",
                    public_key_pem=_AUTH_PUBLIC_KEY,
                ),
            )
            if enable_offline_authentication
            else ()
        ),
    )
    path.write_text(
        json.dumps(bootstrap.model_dump(mode="json")),
        encoding="utf-8",
    )
    if path.stat().st_mode & 0o777 != 0o600 and hasattr(path, "chmod"):
        path.chmod(0o600)


@pytest.fixture(autouse=True)
def configure_authentication(monkeypatch, tmp_path):
    bootstrap_path = tmp_path / "mission-bootstrap.json"
    _create_bootstrap_file(bootstrap_path)
    signing_key_path = tmp_path / "onboard-signing-key.pem"
    signing_key_path.write_bytes(
        _PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    signing_key_path.chmod(0o600)
    monkeypatch.setenv("MISSION_BOOTSTRAP_PATH", str(bootstrap_path.resolve()))
    monkeypatch.setenv("ONBOARD_TOKEN_SIGNING_KEY_PATH", str(signing_key_path.resolve()))
    monkeypatch.setenv("AUTH_CHALLENGE_TTL_SECONDS", "300")
    monkeypatch.setenv("AUTH_CHALLENGE_RATE_LIMIT_MAX_REQUESTS", "100")
    monkeypatch.setenv("AUTH_CHALLENGE_RATE_LIMIT_WINDOW_SECONDS", "60")
    monkeypatch.setenv("HEALTH_DB_PATH", str((tmp_path / "health.sqlite3").resolve()))


def _authorization_headers(
    *,
    actor_type="user",
    subject="user-01",
    astronaut_ids=None,
    permissions=None,
    audience=_AUDIENCE,
    mission_id=_MISSION_ID,
    expires_in=timedelta(minutes=5),
):
    now = datetime.now(timezone.utc)
    token_id = str(uuid4())
    token = jwt.encode(
        {
            "sub": subject,
            "iss": _ISSUER,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + expires_in,
            "jti": token_id,
            "mission_id": mission_id,
            "actor_type": actor_type,
            "astronaut_ids": astronaut_ids or ["astronaut-01"],
            "permissions": permissions
            or (
                ["sync:write"]
                if actor_type == "device"
                else ["readings:read", "readings:write"]
            ),
        },
        _PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": _ONBOARD_KEY_ID, "typ": "JWT"},
    )
    initialize_database()
    connection = connect_database()
    try:
        connection.execute(
            """
            INSERT INTO onboard_access_tokens (jti, family_id, expires_at)
            VALUES (?, ?, ?)
            """,
            (token_id, token_id, (now + expires_in).isoformat()),
        )
        connection.commit()
    finally:
        connection.close()
    return {"Authorization": f"Bearer {token}"}


def _approve_and_activate_test_rule(client, rule_id, version):
    approval = client.post(
        f"/api/v1/alerts/rules/{rule_id}/approve",
        json={
            "protocol_reference": "TEST protocol placeholder.",
            "source_reference": "TEST source placeholder.",
            "approval_version": "test-version",
            "scope": ["operational"],
        },
        headers=_authorization_headers(
            astronaut_ids=["astronaut-01", "astronaut-02"],
            permissions=["alerts:approve"],
        ),
    )
    assert approval.status_code == 200
    activation = client.post(
        f"/api/v1/alerts/rules/{rule_id}/activate",
        headers=_authorization_headers(
            astronaut_ids=["astronaut-01", "astronaut-02"],
            permissions=["alerts:configure"],
        ),
    )
    assert activation.status_code == 200
    assert activation.json()["approval"]["approved_rule_version"] == version


def _authentication_proof(challenge, private_key=_AUTH_PRIVATE_KEY):
    claims = {
        "iss": challenge["subject"],
        "aud": challenge["issuer"],
        "iat": int(datetime.fromisoformat(challenge["issued_at"]).timestamp()),
        "exp": int(datetime.fromisoformat(challenge["expires_at"]).timestamp()),
        "jti": challenge["challenge_id"],
        "nonce": challenge["nonce"],
        "mission_id": challenge["mission_id"],
        "actor_type": challenge["actor_type"],
    }
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": challenge["key_id"], "typ": "onboard-auth+jwt"},
    )


def _onboard_token_service(bootstrap):
    private_key_pem = _PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return OnboardTokenService(
        private_key_pem=private_key_pem,
        key_id=_ONBOARD_KEY_ID,
        verifier=bootstrap.onboard_token_verifier,
    )


def test_onboard_credentials_rotate_and_reuse_revokes_family():
    with TestClient(app) as client:
        bootstrap = app.state.identity_bootstrap
        connection = connect_database()
        try:
            configuration = load_provisioned_mission_configuration(
                connection,
                base_configuration=bootstrap.base_configuration,
                key_set=bootstrap.ground_keys,
                expected_onboard_service_id=_ISSUER,
                now=datetime.now(timezone.utc),
            )
            service = _onboard_token_service(bootstrap)
            now = datetime.now(timezone.utc)
            issued = service.issue(
                connection,
                configuration=configuration,
                subject="user-01",
                actor_type=ActorType.USER,
                permissions=frozenset({"readings:read"}),
                astronaut_ids=frozenset({"astronaut-01"}),
                access_lifetime_seconds=300,
                now=now,
            )
            claims = jwt.decode(
                issued.access_token,
                _PUBLIC_KEY,
                algorithms=["RS256"],
                audience=_AUDIENCE,
                issuer=_ISSUER,
            )
            first_jti = claims["jti"]
            rotated = service.refresh(
                connection,
                configuration=configuration,
                refresh_token=issued.refresh_token,
                access_lifetime_seconds=300,
                now=now,
            )
            rotated_claims = jwt.decode(
                rotated.access_token,
                _PUBLIC_KEY,
                algorithms=["RS256"],
                audience=_AUDIENCE,
                issuer=_ISSUER,
            )
            with pytest.raises(RefreshTokenReuseError):
                service.refresh(
                    connection,
                    configuration=configuration,
                    refresh_token=issued.refresh_token,
                    access_lifetime_seconds=300,
                    now=now,
                )

            records = connection.execute(
                """
                SELECT jti, revoked_at
                FROM onboard_access_tokens
                WHERE family_id = (
                    SELECT family_id
                    FROM onboard_refresh_sessions
                    WHERE token_sha256 = ?
                )
                """,
                (hashlib.sha256(issued.refresh_token.encode("ascii")).hexdigest(),),
            ).fetchall()
            assert rotated_claims["jti"] != first_jti
            assert len(records) == 2
            assert all(record["revoked_at"] is not None for record in records)
            response = client.get(
                "/api/v1/readings",
                params={"astronaut_id": "astronaut-01"},
                headers={"Authorization": f"Bearer {rotated.access_token}"},
            )
            assert response.status_code == 401
        finally:
            connection.close()


def test_onboard_credentials_reject_lifetime_outside_delegation():
    with TestClient(app):
        bootstrap = app.state.identity_bootstrap
        connection = connect_database()
        try:
            configuration = load_provisioned_mission_configuration(
                connection,
                base_configuration=bootstrap.base_configuration,
                key_set=bootstrap.ground_keys,
                expected_onboard_service_id=_ISSUER,
                now=datetime.now(timezone.utc),
            )
            service = _onboard_token_service(bootstrap)
            with pytest.raises(CredentialIssueError):
                service.issue(
                    connection,
                    configuration=configuration,
                    subject="user-01",
                    actor_type=ActorType.USER,
                    permissions=frozenset({"readings:read"}),
                    astronaut_ids=frozenset({"astronaut-01"}),
                    access_lifetime_seconds=3601,
                    now=datetime.now(timezone.utc),
                )
            assert connection.execute(
                "SELECT COUNT(*) FROM onboard_access_tokens"
            ).fetchone()[0] == 0
        finally:
            connection.close()


def test_onboard_credential_issue_rolls_back_if_refresh_session_cannot_persist():
    with TestClient(app):
        bootstrap = app.state.identity_bootstrap
        connection = connect_database()
        try:
            configuration = load_provisioned_mission_configuration(
                connection,
                base_configuration=bootstrap.base_configuration,
                key_set=bootstrap.ground_keys,
                expected_onboard_service_id=_ISSUER,
                now=datetime.now(timezone.utc),
            )
            service = _onboard_token_service(bootstrap)
            connection.execute(
                """
                CREATE TRIGGER reject_refresh_session
                BEFORE INSERT ON onboard_refresh_sessions
                BEGIN
                    SELECT RAISE(ABORT, 'refresh persistence unavailable');
                END
                """
            )
            connection.commit()

            with pytest.raises(CredentialIssueError):
                service.issue(
                    connection,
                    configuration=configuration,
                    subject="user-01",
                    actor_type=ActorType.USER,
                    permissions=frozenset({"readings:read"}),
                    astronaut_ids=frozenset({"astronaut-01"}),
                    access_lifetime_seconds=300,
                    now=datetime.now(timezone.utc),
                )

            assert not connection.in_transaction
            assert connection.execute(
                "SELECT COUNT(*) FROM onboard_access_tokens"
            ).fetchone()[0] == 0
            assert connection.execute(
                "SELECT COUNT(*) FROM onboard_refresh_sessions"
            ).fetchone()[0] == 0
        finally:
            connection.close()


def test_onboard_revoke_family_invalidates_refresh_and_access_tokens():
    with TestClient(app) as client:
        bootstrap = app.state.identity_bootstrap
        connection = connect_database()
        try:
            now = datetime.now(timezone.utc)
            configuration = load_provisioned_mission_configuration(
                connection,
                base_configuration=bootstrap.base_configuration,
                key_set=bootstrap.ground_keys,
                expected_onboard_service_id=_ISSUER,
                now=now,
            )
            service = _onboard_token_service(bootstrap)
            issued = service.issue(
                connection,
                configuration=configuration,
                subject="user-01",
                actor_type=ActorType.USER,
                permissions=frozenset({"readings:read"}),
                astronaut_ids=frozenset({"astronaut-01"}),
                access_lifetime_seconds=300,
                now=now,
            )
            rotated = service.refresh(
                connection,
                configuration=configuration,
                refresh_token=issued.refresh_token,
                access_lifetime_seconds=300,
                now=now,
            )

            active_response = client.get(
                "/api/v1/readings",
                params={"astronaut_id": "astronaut-01"},
                headers={"Authorization": f"Bearer {rotated.access_token}"},
            )
            service.revoke_family(
                connection,
                refresh_token=rotated.refresh_token,
                now=now,
            )
            revoked_response = client.get(
                "/api/v1/readings",
                params={"astronaut_id": "astronaut-01"},
                headers={"Authorization": f"Bearer {rotated.access_token}"},
            )
            family_records = connection.execute(
                """
                SELECT revoked_at
                FROM onboard_refresh_sessions
                WHERE family_id = (
                    SELECT family_id FROM onboard_refresh_sessions
                    WHERE token_sha256 = ?
                )
                """,
                (hashlib.sha256(issued.refresh_token.encode("ascii")).hexdigest(),),
            ).fetchall()
            access_records = connection.execute(
                """
                SELECT revoked_at
                FROM onboard_access_tokens
                WHERE family_id = (
                    SELECT family_id FROM onboard_refresh_sessions
                    WHERE token_sha256 = ?
                )
                """,
                (hashlib.sha256(issued.refresh_token.encode("ascii")).hexdigest(),),
            ).fetchall()

            assert active_response.status_code == 200
            assert revoked_response.status_code == 401
            assert len(family_records) == 2
            assert all(row["revoked_at"] is not None for row in family_records)
            assert len(access_records) == 2
            assert all(row["revoked_at"] is not None for row in access_records)
            with pytest.raises(RefreshTokenError):
                service.refresh(
                    connection,
                    configuration=configuration,
                    refresh_token=rotated.refresh_token,
                    access_lifetime_seconds=300,
                    now=now,
                )
        finally:
            connection.close()


def test_onboard_expired_refresh_token_is_not_rotated():
    with TestClient(app):
        bootstrap = app.state.identity_bootstrap
        connection = connect_database()
        try:
            now = datetime.now(timezone.utc)
            configuration = load_provisioned_mission_configuration(
                connection,
                base_configuration=bootstrap.base_configuration,
                key_set=bootstrap.ground_keys,
                expected_onboard_service_id=_ISSUER,
                now=now,
            )
            service = _onboard_token_service(bootstrap)
            issued = service.issue(
                connection,
                configuration=configuration,
                subject="user-01",
                actor_type=ActorType.USER,
                permissions=frozenset({"readings:read"}),
                astronaut_ids=frozenset({"astronaut-01"}),
                access_lifetime_seconds=300,
                now=now,
            )

            with pytest.raises(RefreshTokenError, match="Refresh token expirado"):
                service.refresh(
                    connection,
                    configuration=configuration,
                    refresh_token=issued.refresh_token,
                    access_lifetime_seconds=300,
                    now=issued.refresh_expires_at + timedelta(seconds=1),
                )

            refresh_row = connection.execute(
                """
                SELECT used_at, revoked_at
                FROM onboard_refresh_sessions
                WHERE token_sha256 = ?
                """,
                (hashlib.sha256(issued.refresh_token.encode("ascii")).hexdigest(),),
            ).fetchone()
            assert refresh_row["used_at"] is None
            assert refresh_row["revoked_at"] is None
            assert connection.execute(
                "SELECT COUNT(*) FROM onboard_access_tokens"
            ).fetchone()[0] == 1
        finally:
            connection.close()


def test_offline_authentication_proves_key_possession_and_issues_scoped_tokens():
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_offline_authentication=True,
    )
    with TestClient(app) as client:
        missing_key = client.post(
            "/api/v1/auth/challenges",
            json={"subject": "user-02", "actor_type": "user"},
        )
        challenge_response = client.post(
            "/api/v1/auth/challenges",
            json={"subject": "user-01", "actor_type": "user"},
        )
        challenge = challenge_response.json()
        proof = _authentication_proof(challenge)
        invalid_proof = _authentication_proof(challenge, _PRIVATE_KEY)
        wrong_key = client.post(
            "/api/v1/auth/token",
            json={
                "challenge_id": challenge["challenge_id"],
                "proof": invalid_proof,
                "permissions": ["readings:read"],
                "astronaut_ids": ["astronaut-01"],
                "access_lifetime_seconds": 300,
            },
        )
        excessive_claims = client.post(
            "/api/v1/auth/token",
            json={
                "challenge_id": challenge["challenge_id"],
                "proof": proof,
                "permissions": ["admin:all"],
                "astronaut_ids": ["astronaut-01"],
                "access_lifetime_seconds": 300,
            },
        )
        issued = client.post(
            "/api/v1/auth/token",
            json={
                "challenge_id": challenge["challenge_id"],
                "proof": proof,
                "permissions": ["readings:read"],
                "astronaut_ids": ["astronaut-01"],
                "access_lifetime_seconds": 300,
            },
        )
        replay = client.post(
            "/api/v1/auth/token",
            json={
                "challenge_id": challenge["challenge_id"],
                "proof": proof,
                "permissions": ["readings:read"],
                "astronaut_ids": ["astronaut-01"],
                "access_lifetime_seconds": 300,
            },
        )
        access_response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers={"Authorization": f"Bearer {issued.json()['access_token']}"},
        )
        refreshed = client.post(
            "/api/v1/auth/refresh",
            json={
                "refresh_token": issued.json()["refresh_token"],
                "access_lifetime_seconds": 300,
            },
        )
        revoked = client.post(
            "/api/v1/auth/revoke",
            json={"refresh_token": refreshed.json()["refresh_token"]},
        )
        revoked_access = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers={"Authorization": f"Bearer {refreshed.json()['access_token']}"},
        )

    assert missing_key.status_code == 401
    assert challenge_response.status_code == 200
    assert wrong_key.status_code == 401
    assert excessive_claims.status_code == 403
    assert issued.status_code == 200
    assert replay.status_code == 401
    assert access_response.status_code == 200
    assert refreshed.status_code == 200
    assert revoked.status_code == 200
    assert revoked_access.status_code == 401


def test_authentication_challenges_are_rate_limited_per_identity(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_offline_authentication=True,
    )
    monkeypatch.setenv("AUTH_CHALLENGE_RATE_LIMIT_MAX_REQUESTS", "2")
    monkeypatch.setenv("AUTH_CHALLENGE_RATE_LIMIT_WINDOW_SECONDS", "60")

    with TestClient(app) as client:
        first = client.post(
            "/api/v1/auth/challenges",
            json={"subject": "user-01", "actor_type": "user"},
        )
        second = client.post(
            "/api/v1/auth/challenges",
            json={"subject": "user-01", "actor_type": "user"},
        )
        limited = client.post(
            "/api/v1/auth/challenges",
            json={"subject": "user-01", "actor_type": "user"},
        )

        connection = connect_database()
        try:
            connection.execute(
                """
                UPDATE authentication_challenge_attempts
                SET requested_at = ?
                WHERE mission_id = ? AND subject = ? AND actor_type = ?
                """,
                (
                    (datetime.now(timezone.utc) - timedelta(seconds=61)).isoformat(),
                    _MISSION_ID,
                    "user-01",
                    "user",
                ),
            )
            connection.commit()
        finally:
            connection.close()

        after_window = client.post(
            "/api/v1/auth/challenges",
            json={"subject": "user-01", "actor_type": "user"},
        )
        connection = connect_database()
        try:
            attempt_count = connection.execute(
                """
                SELECT COUNT(*) FROM authentication_challenge_attempts
                WHERE mission_id = ? AND subject = ? AND actor_type = ?
                """,
                (_MISSION_ID, "user-01", "user"),
            ).fetchone()[0]
        finally:
            connection.close()

    assert first.status_code == 200
    assert second.status_code == 200
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
    assert after_window.status_code == 200
    assert attempt_count == 1


def test_offline_authentication_startup_requires_rate_limit_configuration(
    monkeypatch,
):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_offline_authentication=True,
    )
    monkeypatch.delenv("AUTH_CHALLENGE_RATE_LIMIT_MAX_REQUESTS")

    with pytest.raises(RuntimeError, match="configuração de emissão.*rejeitada"):
        with TestClient(app):
            pass


def test_offline_authentication_rejects_replayed_and_expired_challenges():
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_offline_authentication=True,
    )
    with TestClient(app) as client:
        challenge_response = client.post(
            "/api/v1/auth/challenges",
            json={"subject": "user-01", "actor_type": "user"},
        )
        challenge = challenge_response.json()
        connection = connect_database()
        try:
            connection.execute(
                """
                UPDATE authentication_challenges
                SET expires_at = ?
                WHERE challenge_id = ?
                """,
                (
                    (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                    challenge["challenge_id"],
                ),
            )
            connection.commit()
        finally:
            connection.close()
        expired = client.post(
            "/api/v1/auth/token",
            json={
                "challenge_id": challenge["challenge_id"],
                "proof": _authentication_proof(challenge),
                "permissions": ["readings:read"],
                "astronaut_ids": ["astronaut-01"],
                "access_lifetime_seconds": 300,
            },
        )

    assert challenge_response.status_code == 200
    assert expired.status_code == 401


def test_offline_authentication_is_disabled_without_signing_key(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_offline_authentication=True,
    )
    monkeypatch.delenv("ONBOARD_TOKEN_SIGNING_KEY_PATH")
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/challenges",
            json={"subject": "user-01", "actor_type": "user"},
        )

    assert response.status_code == 503


def _device_headers(device_id=_DEVICE_ID, astronaut_ids=None):
    return _authorization_headers(
        actor_type="device",
        subject=device_id,
        astronaut_ids=astronaut_ids,
    )


def test_create_and_filter_readings(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00+01:00",
                "measurements": [
                    {"metric": "systolic_blood_pressure", "value": 120},
                    {"metric": "diastolic_blood_pressure", "value": 80},
                    {"metric": "blood_glucose", "value": 95.5},
                ],
                "glucose_context": "fasting",
            },
            headers=_authorization_headers(),
        )

        assert response.status_code == 201
        assert len(response.json()) == 3
        assert response.json()[0]["measured_at"] == "2026-11-14T15:00:00Z"

        history = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01", "metric": "blood_glucose"},
            headers=_authorization_headers(),
        )
        assert history.status_code == 200
        assert history.json()["total"] == 1
        assert history.json()["items"][0]["glucose_context"] == "fasting"


def test_reading_analysis_returns_descriptive_statistics_and_trend(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    headers = _authorization_headers()
    start = datetime(2026, 11, 12, tzinfo=timezone.utc)
    with TestClient(app) as client:
        for day, heart_rate in enumerate((72, 74, 76)):
            created = client.post(
                "/api/v1/readings",
                json={
                    "astronaut_id": "astronaut-01",
                    "measured_at": (start + timedelta(days=day)).isoformat(),
                    "measurements": [{"metric": "heart_rate", "value": heart_rate}],
                },
                headers=headers,
            )
            assert created.status_code == 201

        response = client.get(
            "/api/v1/readings/analysis",
            params={
                "astronaut_id": "astronaut-01",
                "metric": "heart_rate",
                "start": start.isoformat(),
                "end": (start + timedelta(days=2)).isoformat(),
            },
            headers=headers,
        )

    assert response.status_code == 200
    result = response.json()
    assert result["sample_count"] == 3
    assert result["minimum"] == 72
    assert result["maximum"] == 76
    assert result["mean"] == 74
    assert result["median"] == 74
    assert result["sample_standard_deviation"] == 2
    assert result["latest_value"] == 76
    assert result["trend_slope_per_day"] == pytest.approx(2)
    assert result["scope"] == "descriptive_only"


def test_glucose_analysis_requires_and_filters_context(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    headers = _authorization_headers()
    start = datetime(2026, 11, 14, tzinfo=timezone.utc)
    with TestClient(app) as client:
        for hour, value, context in (
            (8, 95.5, "fasting"),
            (12, 150.0, "after_meal"),
        ):
            created = client.post(
                "/api/v1/readings",
                json={
                    "astronaut_id": "astronaut-01",
                    "measured_at": (start + timedelta(hours=hour)).isoformat(),
                    "measurements": [{"metric": "blood_glucose", "value": value}],
                    "glucose_context": context,
                },
                headers=headers,
            )
            assert created.status_code == 201

        params = {
            "astronaut_id": "astronaut-01",
            "metric": "blood_glucose",
            "start": start.isoformat(),
            "end": (start + timedelta(days=1)).isoformat(),
        }
        missing_context = client.get(
            "/api/v1/readings/analysis",
            params=params,
            headers=headers,
        )
        fasting = client.get(
            "/api/v1/readings/analysis",
            params={**params, "glucose_context": "fasting"},
            headers=headers,
        )

    assert missing_context.status_code == 422
    assert fasting.status_code == 200
    assert fasting.json()["sample_count"] == 1
    assert fasting.json()["mean"] == 95.5
    assert fasting.json()["glucose_context"] == "fasting"


def test_indicator_contract_marks_clinical_thresholds_as_illustrative(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))

    with TestClient(app) as client:
        response = client.get("/api/v1/indicators")

    assert response.status_code == 200
    metrics = response.json()
    heart_rate = next(item for item in metrics if item["metric"] == "heart_rate")
    assert heart_rate["technical_validation_range"] == [20, 250]
    thresholds = heart_rate["clinical_thresholds"]
    assert thresholds["status"] == "illustrative"
    assert thresholds["source_reference"] == (
        "Sem fonte clínica validada neste deployment; os valores são ilustrativos "
        "e não constituem diagnóstico ou critério de aptidão."
    )
    assert thresholds["minimum_value"] is None
    assert thresholds["maximum_value"] is None


def test_reading_coverage_reports_observed_counts_without_claiming_missing_data(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    headers = _authorization_headers()
    start = datetime(2026, 11, 12, tzinfo=timezone.utc)
    with TestClient(app) as client:
        for day, heart_rate in enumerate((72, 74)):
            created = client.post(
                "/api/v1/readings",
                json={
                    "astronaut_id": "astronaut-01",
                    "measured_at": (start + timedelta(days=day)).isoformat(),
                    "measurements": [{"metric": "heart_rate", "value": heart_rate}],
                },
                headers=headers,
            )
            assert created.status_code == 201

        response = client.get(
            "/api/v1/readings/coverage",
            params={
                "astronaut_id": "astronaut-01",
                "start": start.isoformat(),
                "end": (start + timedelta(days=2)).isoformat(),
            },
            headers=headers,
        )

    assert response.status_code == 200
    result = response.json()
    assert result["scope"] == "observed_counts_only"
    assert len(result["indicators"]) == 8
    heart_rate = next(
        item for item in result["indicators"] if item["metric"] == "heart_rate"
    )
    mood = next(item for item in result["indicators"] if item["metric"] == "mood")
    assert heart_rate["sample_count"] == 2
    assert heart_rate["latest_measured_at"] == "2026-11-13T00:00:00Z"
    assert mood["sample_count"] == 0
    assert mood["latest_measured_at"] is None


def test_operations_summary_reports_origins_receipts_rejections_duplicates_and_conflicts(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    headers = _authorization_headers()
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    batch = {
        "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        "source_device_id": _DEVICE_ID,
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": start.isoformat(),
                "declared_origin": "simulated",
                "measurements": [
                    {
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "metric": "heart_rate",
                        "value": 72,
                        "sequence_number": 12,
                    }
                ],
            }
        ],
    }

    with TestClient(app) as client:
        manual = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": start.isoformat(),
                "measurements": [{"metric": "mood", "value": 4}],
            },
            headers=headers,
        )
        simulated = client.post(
            "/api/v1/sync/readings",
            json=batch,
            headers=_device_headers(),
        )
        duplicate = client.post(
            "/api/v1/sync/readings",
            json={
                **batch,
                "batch_id": "825ee45b-90cd-4bd0-9e45-e457445b5c78",
            },
            headers=_device_headers(),
        )
        rejected = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": start.isoformat(),
                "measurements": [{"metric": "heart_rate", "value": 10}],
            },
            headers=headers,
        )
        conflict = client.post(
            "/api/v1/sync/readings",
            json={
                **batch,
                "batch_id": "f3a5bdb4-19bc-4fa2-92e4-6f999f531c55",
                "readings": [
                    {
                        **batch["readings"][0],
                        "measurements": [
                            {
                                **batch["readings"][0]["measurements"][0],
                                "reading_id": "12a2452f-4de5-43eb-b42a-a88723b9df88",
                                "sequence_number": 12,
                            }
                        ],
                    }
                ],
            },
            headers=_device_headers(),
        )
        summary = client.get(
            "/api/v1/readings/operations-summary",
            params={
                "astronaut_id": "astronaut-01",
                "start": (start - timedelta(minutes=1)).isoformat(),
                "end": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            },
            headers=headers,
        )
        out_of_scope = client.get(
            "/api/v1/readings/operations-summary",
            params={
                "astronaut_id": "astronaut-01",
                "start": (start - timedelta(minutes=1)).isoformat(),
                "end": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            },
            headers=_authorization_headers(astronaut_ids=["astronaut-02"]),
        )

    assert manual.status_code == 201
    assert simulated.status_code == 200
    assert duplicate.status_code == 200
    assert duplicate.json()["items"][0]["status"] == "already_received"
    assert rejected.status_code == 422
    assert conflict.status_code == 409
    assert summary.status_code == 200
    assert out_of_scope.status_code == 403
    result = summary.json()
    assert result["valid_record_count"] == 2
    assert result["rejected_record_count"] == 1
    assert result["duplicate_record_count"] == 1
    assert result["conflict_record_count"] == 1
    assert result["last_received_at"] is not None
    assert result["records_without_receipt_time"] == 0
    assert {
        origin["declared_origin"]: origin["record_count"]
        for origin in result["origins"]
    } == {"manual": 1, "simulated": 1, "nasa": 0}
    heart_rate = next(
        item for item in result["indicators"] if item["metric"] == "heart_rate"
    )
    assert heart_rate["valid_record_count"] == 1
    assert heart_rate["latest_received_at"] is not None
    assert simulated.json()["items"][0]["status"] == "accepted"


def test_unauthenticated_invalid_ingestion_is_not_counted_as_rejected_data(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "health.sqlite3"
    monkeypatch.setenv("HEALTH_DB_PATH", str(database_path))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [{"metric": "heart_rate", "value": 10}],
            },
        )
        with sqlite3.connect(database_path) as connection:
            rejected_count = connection.execute(
                "SELECT COUNT(*) FROM ingestion_events WHERE outcome = 'rejected'"
            ).fetchone()[0]

    assert response.status_code in {401, 422}
    assert rejected_count == 0


def test_indicator_catalog_groups_metrics_by_body_system_and_trend_support():
    with TestClient(app) as client:
        response = client.get("/api/v1/indicators")

    assert response.status_code == 200
    heart_rate = next(
        indicator for indicator in response.json() if indicator["metric"] == "heart_rate"
    )
    mood = next(
        indicator for indicator in response.json() if indicator["metric"] == "mood"
    )
    assert heart_rate["body_system"] == "cardiovascular"
    assert heart_rate["trend_supported"] is True
    assert mood["body_system"] == "wellbeing"
    assert mood["trend_supported"] is True


def test_indicator_catalog_exposes_stable_ui_labels_and_sort_order():
    with TestClient(app) as client:
        response = client.get("/api/v1/indicators")

    assert response.status_code == 200
    heart_rate = next(
        indicator for indicator in response.json() if indicator["metric"] == "heart_rate"
    )
    oxygen = next(
        indicator
        for indicator in response.json()
        if indicator["metric"] == "blood_oxygen"
    )
    assert heart_rate["display_name"] == "Heart rate"
    assert heart_rate["sort_order"] == 3
    assert oxygen["display_name"] == "Blood oxygen"
    assert oxygen["sort_order"] == 8


def test_indicator_catalog_includes_blood_oxygen():
    with TestClient(app) as client:
        response = client.get("/api/v1/indicators")

    assert response.status_code == 200
    oxygen = next(
        indicator
        for indicator in response.json()
        if indicator["metric"] == "blood_oxygen"
    )
    assert oxygen["unit"] == "%"
    assert oxygen["technical_validation_range"] == [0, 100]


def test_indicator_catalog_includes_mission_context_and_ground_support():
    with TestClient(app) as client:
        response = client.get("/api/v1/indicators")

    assert response.status_code == 200
    heart_rate = next(
        indicator for indicator in response.json() if indicator["metric"] == "heart_rate"
    )
    assert "monitoring_focus" in heart_rate
    assert "ground_support_note" in heart_rate
    assert "esforço" in heart_rate["monitoring_focus"].lower()
    assert "solo" in heart_rate["ground_support_note"].lower()


def test_frontend_is_served_from_application_root():
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "SOMA" in response.text
    assert "NASA OSDR" not in response.text
    assert "Citação e crédito" not in response.text
    assert "/api/v1/scientific-data/public/osdr/inspiration4/cmp" not in response.text
    assert "Cadastrar astronauta" not in response.text
    assert "auth/challenges" not in response.text
    assert "soma-prototype-v1" not in response.text
    assert (
        '<button type="button" data-view="mission" aria-current="page">'
        "Monitorização</button>"
    ) in response.text
    assert 'id="body-model-3d"' in response.text
    assert 'id="mission-body-systems"' in response.text
    assert 'id="mission-dashboard-form"' in response.text
    assert 'type="password"' in response.text
    assert "/api/v1/readings/coverage" in response.text
    assert "/api/v1/readings/analysis" in response.text
    assert 'id="mission-trend-chart"' in response.text
    assert "/api/v1/alerts/" in response.text
    assert 'data-ack-alert=' in response.text
    assert 'id="offline-reading-form"' in response.text
    assert "indexedDB.open" in response.text
    assert 'navigator.serviceWorker.register("/service-worker.js")' in response.text
    assert "monitoring_support_not_diagnosis" in response.text
    assert "localStorage" not in response.text


def test_frontend_exposes_synthetic_demo_and_interactive_body_map_without_signup():
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert 'id="demo-start"' in response.text
    assert 'id="demo-dashboard"' in response.text
    assert 'id="body-model-3d"' in response.text
    assert 'data-body-hotspot=' in response.text
    assert 'id="body-system-detail"' in response.text
    assert "Demonstração com dados sintéticos" in response.text
    assert "Cadastrar astronauta" not in response.text
    assert 'id="mission-dashboard-form"' in response.text
    assert "authorization:" in response.text.lower()


def test_offline_service_worker_is_served_without_caching_api_responses():
    with TestClient(app) as client:
        response = client.get("/service-worker.js")

    assert response.status_code == 200
    assert "text/javascript" in response.headers["content-type"]
    assert "url.pathname.startsWith(\"/api/\")" in response.text
    assert "caches.match(\"/\")" in response.text


def test_public_osdr_inspiration4_summary_requires_no_mission_login(monkeypatch):
    dataset = OSDRPublicInspiration4Dataset(
        title="Inspiration4 serum study",
        study_url="https://osdr.nasa.gov/bio/repo/data/studies/OSD-575",
        source_api_url="https://visualization.osdr.nasa.gov/biodata/api/v2/dataset/OSD-575/",
        source_file_name="cmp.csv",
        source_file_url="https://osdr.nasa.gov/geode-py/ws/studies/OSD-575/download",
        source_file_updated_at=None,
        source_file_size_bytes=10,
        source_file_sha256="a" * 64,
        record_count=0,
        sample_count=0,
        retrieved_at=datetime.now(timezone.utc),
        citation="NASA OSDR, OSD-575.",
        metrics=(),
    )
    monkeypatch.setattr(
        "app.main.fetch_osdr_inspiration4_cmp_summary",
        lambda: dataset,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/scientific-data/public/osdr/inspiration4/cmp")

    assert response.status_code == 200
    assert response.json()["accession"] == "OSD-575"
    assert "s-maxage=3600" in response.headers["cache-control"]


def test_readiness_requires_operational_bootstrap_and_database():
    with TestClient(app) as client:
        ready = client.get("/ready")
        live = client.get("/health")
        bootstrap = app.state.identity_bootstrap
        app.state.identity_bootstrap = None
        missing_bootstrap = client.get("/ready")
        app.state.identity_bootstrap = bootstrap

    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}
    assert live.status_code == 200
    assert live.json() == {"status": "ok"}
    assert missing_bootstrap.status_code == 503


def test_readiness_reports_database_unavailable(monkeypatch):
    def fail_connect():
        raise sqlite3.OperationalError("database unavailable")

    with TestClient(app) as client:
        monkeypatch.setattr("app.main.connect_database", fail_connect)
        response = client.get("/ready")

    assert response.status_code == 503


def test_readiness_reports_missing_scientific_metadata_schema():
    with TestClient(app) as client:
        connection = connect_database()
        try:
            connection.execute("DROP TABLE nasa_osdr_study_metadata")
            connection.commit()
        finally:
            connection.close()
        response = client.get("/ready")

    assert response.status_code == 503


def test_configured_monitoring_alerts_are_atomic_idempotent_and_scoped():
    rules = (
        MonitoringAlertRule(
            rule_id="heart-rate-monitoring",
            version=1,
            metric=Metric.HEART_RATE,
            minimum_value=55,
            maximum_value=100,
            rationale="Limites de monitorização definidos para o ensaio.",
            source_reference="Protocolo de monitorização da missão, secção 4.",
        ),
    )
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        monitoring_alert_rules=rules,
        enable_alert_configuration=True,
        enable_alert_approval=True,
    )
    start = datetime.now(timezone.utc) - timedelta(minutes=1)

    with TestClient(app) as client:
        _approve_and_activate_test_rule(client, "heart-rate-monitoring", 1)
        for value in (54, 55, 100, 101):
            response = client.post(
                "/api/v1/readings",
                json={
                    "astronaut_id": "astronaut-01",
                    "measured_at": datetime.now(timezone.utc).isoformat(),
                    "measurements": [{"metric": "heart_rate", "value": value}],
                },
                headers=_authorization_headers(),
            )
            assert response.status_code == 201

        offline_reading_id = "f59b83f0-56a8-47f3-874d-ed940f65d346"
        batch = {
            "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
            "source_device_id": _DEVICE_ID,
            "readings": [
                {
                    "astronaut_id": "astronaut-01",
                    "measured_at": datetime.now(timezone.utc).isoformat(),
                    "measurements": [
                        {
                            "reading_id": offline_reading_id,
                            "sequence_number": 1,
                            "metric": "heart_rate",
                            "value": 40,
                        }
                    ],
                }
            ],
        }
        first_sync = client.post(
            "/api/v1/sync/readings",
            json=batch,
            headers=_device_headers(),
        )
        replay = client.post(
            "/api/v1/sync/readings",
            json={
                **batch,
                "batch_id": "825ee45b-90cd-4bd0-9e45-e457445b5c78",
            },
            headers=_device_headers(),
        )
        alerts = client.get(
            "/api/v1/alerts",
            params={
                "astronaut_id": "astronaut-01",
                "start": start.isoformat(),
                "end": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            },
            headers=_authorization_headers(),
        )
        out_of_scope = client.get(
            "/api/v1/alerts",
            params={
                "astronaut_id": "astronaut-01",
                "start": start.isoformat(),
                "end": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            },
            headers=_authorization_headers(astronaut_ids=["astronaut-02"]),
        )
        device_access = client.get(
            "/api/v1/alerts",
            params={
                "astronaut_id": "astronaut-01",
                "start": start.isoformat(),
                "end": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            },
            headers=_device_headers(),
        )

    assert first_sync.status_code == 200
    assert replay.status_code == 200
    assert replay.json()["items"][0]["status"] == "already_received"
    assert alerts.status_code == 200
    assert alerts.json()["total"] == 3
    assert len(alerts.json()["items"]) == 3
    assert out_of_scope.status_code == 403
    assert device_access.status_code == 403
    alert_directions = {
        (alert["direction"], alert["configured_limit"])
        for alert in alerts.json()["items"]
    }
    assert alert_directions == {("below_minimum", 55), ("above_maximum", 100)}
    assert all(
        alert["source_reference"] == "Protocolo de monitorização da missão, secção 4."
        and alert["interpretation"] == "monitoring_support_not_diagnosis"
        for alert in alerts.json()["items"]
    )


def test_monitoring_alerts_are_empty_without_rules():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/alerts",
            params={
                "astronaut_id": "astronaut-01",
                "start": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                "end": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            },
            headers=_authorization_headers(),
        )

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}


def test_monitoring_alert_persistence_failure_rolls_back_reading():
    rules = (
        MonitoringAlertRule(
            rule_id="heart-rate-minimum",
            version=1,
            metric=Metric.HEART_RATE,
            minimum_value=55,
            rationale="Limite de monitorização do teste.",
            source_reference="Protocolo de teste.",
        ),
    )
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        monitoring_alert_rules=rules,
        enable_alert_configuration=True,
        enable_alert_approval=True,
    )
    reading_id = "12a2452f-4de5-43eb-b42a-a88723b9df88"

    with TestClient(app) as client:
        _approve_and_activate_test_rule(client, "heart-rate-minimum", 1)
        connection = connect_database()
        try:
            connection.execute(
                """
                CREATE TRIGGER reject_monitoring_alert
                BEFORE INSERT ON monitoring_alerts
                BEGIN
                    SELECT RAISE(ABORT, 'alert persistence unavailable');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        response = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": datetime.now(timezone.utc).isoformat(),
                "measurements": [
                    {
                        "reading_id": reading_id,
                        "metric": "heart_rate",
                        "value": 40,
                    }
                ],
            },
            headers=_authorization_headers(),
        )
        connection = connect_database()
        try:
            stored_reading_count = connection.execute(
                "SELECT COUNT(*) FROM health_readings WHERE reading_id = ?",
                (reading_id,),
            ).fetchone()[0]
            stored_alert_count = connection.execute(
                "SELECT COUNT(*) FROM monitoring_alerts WHERE reading_id = ?",
                (reading_id,),
            ).fetchone()[0]
        finally:
            connection.close()

    assert response.status_code == 500
    assert stored_reading_count == 0
    assert stored_alert_count == 0


def test_alert_acknowledgement_is_permissioned_scoped_and_idempotent():
    rules = (
        MonitoringAlertRule(
            rule_id="heart-rate-minimum",
            version=1,
            metric=Metric.HEART_RATE,
            minimum_value=55,
            rationale="Limite de monitorização do teste.",
            source_reference="Protocolo de teste.",
        ),
    )
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        monitoring_alert_rules=rules,
        enable_alert_configuration=True,
        enable_alert_approval=True,
        enable_alert_acknowledgement=True,
    )
    ack_headers = _authorization_headers(
        permissions=["readings:read", "alerts:acknowledge"],
    )

    with TestClient(app) as client:
        _approve_and_activate_test_rule(client, "heart-rate-minimum", 1)
        reading = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": datetime.now(timezone.utc).isoformat(),
                "measurements": [{"metric": "heart_rate", "value": 40}],
            },
            headers=_authorization_headers(),
        )
        alert_query = {
            "astronaut_id": "astronaut-01",
            "start": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "end": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
        }
        alerts_before = client.get(
            "/api/v1/alerts",
            params=alert_query,
            headers=_authorization_headers(),
        )
        alert_id = alerts_before.json()["items"][0]["alert_id"]
        missing_permission = client.post(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            headers=_authorization_headers(),
        )
        out_of_scope = client.post(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            headers=_authorization_headers(
                astronaut_ids=["astronaut-02"],
                permissions=["readings:read", "alerts:acknowledge"],
            ),
        )
        acknowledged = client.post(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            headers=ack_headers,
        )
        repeated_acknowledgement = client.post(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            headers=ack_headers,
        )
        alerts_after = client.get(
            "/api/v1/alerts",
            params=alert_query,
            headers=ack_headers,
        )
        unknown_alert = client.post(
            "/api/v1/alerts/999/acknowledge",
            headers=ack_headers,
        )

    assert reading.status_code == 201
    assert alerts_before.status_code == 200
    assert alerts_before.json()["items"][0]["acknowledgement_count"] == 0
    assert alerts_before.json()["items"][0]["acknowledged_by_current_user"] is False
    assert missing_permission.status_code == 403
    assert out_of_scope.status_code == 403
    assert acknowledged.status_code == 200
    assert repeated_acknowledgement.status_code == 200
    assert acknowledged.json() == repeated_acknowledgement.json()
    assert acknowledged.json()["status"] == "acknowledged"
    assert alerts_after.json()["items"][0]["acknowledgement_count"] == 1
    assert alerts_after.json()["items"][0]["acknowledged_by_current_user"] is True
    assert unknown_alert.status_code == 404


def test_monitoring_rules_require_scoped_approval_before_activation():
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_alert_configuration=True,
        enable_alert_approval=True,
    )
    configuration_headers = _authorization_headers(
        astronaut_ids=["astronaut-01", "astronaut-02"],
        permissions=["readings:read", "alerts:configure"],
    )
    approval_headers = _authorization_headers(
        astronaut_ids=["astronaut-01", "astronaut-02"],
        permissions=["alerts:approve"],
    )
    rule_body = {
        "expected_version": 0,
        "metric": "heart_rate",
        "minimum_value": 55,
        "rationale": "Test-only rule; not a clinical recommendation.",
        "source_reference": "TEST source placeholder.",
    }

    with TestClient(app) as client:
        created = client.put(
            "/api/v1/alerts/rules/approval-gate-test",
            json=rule_body,
            headers=configuration_headers,
        )
        unapproved_activation = client.post(
            "/api/v1/alerts/rules/approval-gate-test/activate",
            headers=configuration_headers,
        )
        missing_permission = client.post(
            "/api/v1/alerts/rules/approval-gate-test/approve",
            json={
                "protocol_reference": "TEST protocol placeholder.",
                "source_reference": "TEST source placeholder.",
                "approval_version": "test-version",
                "scope": ["operational"],
            },
            headers=configuration_headers,
        )
        clinical_only_approval = client.post(
            "/api/v1/alerts/rules/approval-gate-test/approve",
            json={
                "protocol_reference": "TEST protocol placeholder.",
                "source_reference": "TEST source placeholder.",
                "approval_version": "test-version",
                "scope": ["clinical"],
            },
            headers=approval_headers,
        )
        clinical_only_activation = client.post(
            "/api/v1/alerts/rules/approval-gate-test/activate",
            headers=configuration_headers,
        )
        updated = client.put(
            "/api/v1/alerts/rules/approval-gate-test",
            json={**rule_body, "expected_version": 1, "minimum_value": 60},
            headers=configuration_headers,
        )
        operational_approval = client.post(
            "/api/v1/alerts/rules/approval-gate-test/approve",
            json={
                "protocol_reference": "TEST protocol version ref.",
                "source_reference": "TEST source version ref.",
                "approval_version": "test-version-2",
                "scope": ["operational"],
            },
            headers=approval_headers,
        )
        activation = client.post(
            "/api/v1/alerts/rules/approval-gate-test/activate",
            headers=configuration_headers,
        )

    assert created.status_code == 200
    assert created.json()["active"] is False
    assert created.json()["approval"]["status"] == "unapproved"
    assert unapproved_activation.status_code == 409
    assert missing_permission.status_code == 403
    assert clinical_only_approval.status_code == 200
    assert clinical_only_approval.json()["approval"]["approval_authority"] == "user-01"
    assert clinical_only_approval.json()["approval"]["scope"] == ["clinical"]
    assert clinical_only_approval.json()["approval"]["approval_date"] is not None
    assert clinical_only_activation.status_code == 409
    assert updated.status_code == 200
    assert updated.json()["active"] is False
    assert updated.json()["approval"]["status"] == "unapproved"
    assert operational_approval.status_code == 200
    assert operational_approval.json()["approval"]["approved_rule_version"] == 2
    assert operational_approval.json()["approval"]["approval_version"] == "test-version-2"
    assert operational_approval.json()["approval"]["protocol_reference"] == (
        "TEST protocol version ref."
    )
    assert activation.status_code == 200
    assert activation.json()["active"] is True
    assert activation.json()["approval"]["scope"] == ["operational"]


def test_alert_rule_management_is_delegated_versioned_audited_and_persistent():
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_alert_configuration=True,
        enable_alert_approval=True,
    )
    admin_headers = _authorization_headers(
        astronaut_ids=["astronaut-01", "astronaut-02"],
        permissions=["readings:read", "alerts:configure"],
    )
    approver_headers = _authorization_headers(
        astronaut_ids=["astronaut-01", "astronaut-02"],
        permissions=["alerts:approve"],
    )
    approval_payload = {
        "protocol_reference": "TEST protocol placeholder.",
        "source_reference": "TEST source placeholder.",
        "approval_version": "test-version",
        "scope": ["operational"],
    }
    rule_body = {
        "expected_version": 0,
        "metric": "heart_rate",
        "minimum_value": 55,
        "maximum_value": None,
        "rationale": "Test-only rule; not a clinical recommendation.",
        "source_reference": "TEST rule source placeholder.",
    }

    with TestClient(app) as client:
        no_permission = client.get(
            "/api/v1/alerts/rules",
            headers=_authorization_headers(
                astronaut_ids=["astronaut-01", "astronaut-02"],
            ),
        )
        partial_scope = client.get(
            "/api/v1/alerts/rules",
            headers=_authorization_headers(
                permissions=["readings:read", "alerts:configure"],
            ),
        )
        created = client.put(
            "/api/v1/alerts/rules/heart-rate-check",
            json=rule_body,
            headers=admin_headers,
        )
        unapproved_activation = client.post(
            "/api/v1/alerts/rules/heart-rate-check/activate",
            headers=admin_headers,
        )
        approved_v1 = client.post(
            "/api/v1/alerts/rules/heart-rate-check/approve",
            json=approval_payload,
            headers=approver_headers,
        )
        activated_v1 = client.post(
            "/api/v1/alerts/rules/heart-rate-check/activate",
            headers=admin_headers,
        )
        stale_update = client.put(
            "/api/v1/alerts/rules/heart-rate-check",
            json=rule_body,
            headers=admin_headers,
        )
        updated = client.put(
            "/api/v1/alerts/rules/heart-rate-check",
            json={
                **rule_body,
                "expected_version": 1,
                "minimum_value": 60,
            },
            headers=admin_headers,
        )
        unapproved_update_activation = client.post(
            "/api/v1/alerts/rules/heart-rate-check/activate",
            headers=admin_headers,
        )
        inactive_reading = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": datetime.now(timezone.utc).isoformat(),
                "measurements": [{"metric": "heart_rate", "value": 40}],
            },
            headers=_authorization_headers(),
        )
        approved_v2 = client.post(
            "/api/v1/alerts/rules/heart-rate-check/approve",
            json=approval_payload,
            headers=approver_headers,
        )
        activated_v2 = client.post(
            "/api/v1/alerts/rules/heart-rate-check/activate",
            headers=admin_headers,
        )
        active_reading = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": datetime.now(timezone.utc).isoformat(),
                "measurements": [{"metric": "heart_rate", "value": 40}],
            },
            headers=_authorization_headers(),
        )
        deactivated = client.post(
            "/api/v1/alerts/rules/heart-rate-check/deactivate",
            json={"expected_version": 2},
            headers=admin_headers,
        )
        deactivated_activation = client.post(
            "/api/v1/alerts/rules/heart-rate-check/activate",
            headers=admin_headers,
        )
        approved_v3 = client.post(
            "/api/v1/alerts/rules/heart-rate-check/approve",
            json=approval_payload,
            headers=approver_headers,
        )
        reactivated = client.post(
            "/api/v1/alerts/rules/heart-rate-check/activate",
            headers=admin_headers,
        )
        alerts = client.get(
            "/api/v1/alerts",
            params={
                "astronaut_id": "astronaut-01",
                "start": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                "end": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            },
            headers=_authorization_headers(),
        )
        audit = client.get(
            "/api/v1/alerts/rules/audit",
            headers=admin_headers,
        )

    assert no_permission.status_code == 403
    assert partial_scope.status_code == 403
    assert created.status_code == 200
    assert created.json()["rule"]["version"] == 1
    assert created.json()["active"] is False
    assert created.json()["approval"]["status"] == "unapproved"
    assert unapproved_activation.status_code == 409
    assert approved_v1.status_code == 200
    assert activated_v1.status_code == 200
    assert stale_update.status_code == 409
    assert updated.status_code == 200
    assert updated.json()["rule"]["version"] == 2
    assert updated.json()["active"] is False
    assert updated.json()["approval"]["status"] == "unapproved"
    assert unapproved_update_activation.status_code == 409
    assert inactive_reading.status_code == 201
    assert approved_v2.status_code == 200
    assert activated_v2.status_code == 200
    assert active_reading.status_code == 201
    assert deactivated.status_code == 200
    assert deactivated.json()["rule"]["version"] == 3
    assert deactivated.json()["active"] is False
    assert deactivated_activation.status_code == 409
    assert approved_v3.status_code == 200
    assert reactivated.status_code == 200
    assert reactivated.json()["active"] is True
    assert reactivated.json()["rule"]["version"] == 3
    assert alerts.status_code == 200
    assert alerts.json()["total"] == 1
    assert audit.status_code == 200
    assert [
        item["action"] for item in reversed(audit.json()["items"])
    ] == [
        "created", "approved", "activated", "updated", "approved", "activated",
        "deactivated", "approved", "activated",
    ]
    assert all(item["actor_id"] == "user-01" for item in audit.json()["items"])

    with TestClient(app) as restarted_client:
        persisted_rules = restarted_client.get(
            "/api/v1/alerts/rules",
            headers=admin_headers,
        )
        persisted_audit = restarted_client.get(
            "/api/v1/alerts/rules/audit",
            headers=admin_headers,
        )

    assert persisted_rules.status_code == 200
    assert persisted_rules.json()["items"][0]["rule"]["version"] == 3
    assert persisted_rules.json()["items"][0]["active"] is True
    assert persisted_rules.json()["items"][0]["approval"]["status"] == "approved"
    assert persisted_audit.json()["total"] == 9


def test_alert_rule_update_rolls_back_if_audit_record_cannot_be_written():
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_alert_configuration=True,
    )
    headers = _authorization_headers(
        astronaut_ids=["astronaut-01", "astronaut-02"],
        permissions=["readings:read", "alerts:configure"],
    )
    with TestClient(app) as client:
        connection = connect_database()
        try:
            connection.execute(
                """
                CREATE TRIGGER reject_alert_rule_audit
                BEFORE INSERT ON monitoring_alert_rule_changes
                BEGIN
                    SELECT RAISE(ABORT, 'rule audit unavailable');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        response = client.put(
            "/api/v1/alerts/rules/heart-rate-check",
            json={
                "expected_version": 0,
                "metric": "heart_rate",
                "minimum_value": 55,
                "rationale": "Limite do teste.",
                "source_reference": "Protocolo de teste.",
            },
            headers=headers,
        )
        connection = connect_database()
        try:
            rule_count = connection.execute(
                "SELECT COUNT(*) FROM monitoring_alert_rules"
            ).fetchone()[0]
            audit_count = connection.execute(
                "SELECT COUNT(*) FROM monitoring_alert_rule_changes"
            ).fetchone()[0]
        finally:
            connection.close()

    assert response.status_code == 500
    assert rule_count == 0
    assert audit_count == 0


def test_alert_rule_approval_rolls_back_if_audit_record_cannot_be_written():
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_alert_configuration=True,
        enable_alert_approval=True,
    )
    configuration_headers = _authorization_headers(
        astronaut_ids=["astronaut-01", "astronaut-02"],
        permissions=["alerts:configure"],
    )
    approval_headers = _authorization_headers(
        astronaut_ids=["astronaut-01", "astronaut-02"],
        permissions=["alerts:approve"],
    )

    with TestClient(app) as client:
        created = client.put(
            "/api/v1/alerts/rules/approval-rollback-test",
            json={
                "expected_version": 0,
                "metric": "heart_rate",
                "minimum_value": 55,
                "rationale": "Test-only illustrative threshold.",
                "source_reference": "TEST placeholder.",
            },
            headers=configuration_headers,
        )
        connection = connect_database()
        try:
            connection.execute(
                """
                CREATE TRIGGER reject_alert_rule_approval_audit
                BEFORE INSERT ON monitoring_alert_rule_changes
                WHEN NEW.action = 'approved'
                BEGIN
                    SELECT RAISE(ABORT, 'approval audit unavailable');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        response = client.post(
            "/api/v1/alerts/rules/approval-rollback-test/approve",
            json={
                "protocol_reference": "TEST protocol placeholder.",
                "source_reference": "TEST source placeholder.",
                "approval_version": "test-version",
                "scope": ["operational"],
            },
            headers=approval_headers,
        )
        connection = connect_database()
        try:
            approval_count = connection.execute(
                "SELECT COUNT(*) FROM monitoring_alert_rule_approvals"
            ).fetchone()[0]
            audit_count = connection.execute(
                """
                SELECT COUNT(*) FROM monitoring_alert_rule_changes
                WHERE action = 'approved'
                """
            ).fetchone()[0]
        finally:
            connection.close()

    assert created.status_code == 200
    assert response.status_code == 500
    assert approval_count == 0
    assert audit_count == 0


def test_monitoring_alert_rules_require_valid_configured_limits():
    with pytest.raises(ValueError):
        MonitoringAlertRule(
            rule_id="empty",
            version=1,
            metric=Metric.HEART_RATE,
            rationale="Teste",
            source_reference="Protocolo de teste.",
        )
    with pytest.raises(ValueError):
        MonitoringAlertRule(
            rule_id="invalid",
            version=1,
            metric=Metric.HEART_RATE,
            minimum_value=110,
            maximum_value=100,
            rationale="Teste",
            source_reference="Protocolo de teste.",
        )


def test_rejects_invalid_values_and_blood_pressure(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    with TestClient(app) as client:
        base_payload = {
            "astronaut_id": "astronaut-01",
            "measured_at": "2026-11-14T16:00:00Z",
        }
        invalid_value = client.post(
            "/api/v1/readings",
            json={
                **base_payload,
                "measurements": [{"metric": "heart_rate", "value": 19}],
            },
            headers=_authorization_headers(),
        )
        assert invalid_value.status_code == 422

        invalid_pressure = client.post(
            "/api/v1/readings",
            json={
                **base_payload,
                "measurements": [
                    {"metric": "systolic_blood_pressure", "value": 80},
                    {"metric": "diastolic_blood_pressure", "value": 80},
                ],
            },
            headers=_authorization_headers(),
        )
        assert invalid_pressure.status_code == 422


def test_glucose_requires_measurement_context(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [{"metric": "blood_glucose", "value": 95.5}],
            },
            headers=_authorization_headers(),
        )

    assert response.status_code == 422


def test_requires_timezone_and_integer_mood(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    with TestClient(app) as client:
        no_timezone = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00",
                "measurements": [{"metric": "mood", "value": 4}],
            },
            headers=_authorization_headers(),
        )
        decimal_mood = client.post(
            "/api/v1/readings",
            json={
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [{"metric": "mood", "value": 4.5}],
            },
            headers=_authorization_headers(),
        )
        assert no_timezone.status_code == 422
        assert decimal_mood.status_code == 422


def test_offline_sync_is_idempotent_and_acknowledges_after_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    batch = {
        "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        "source_device_id": "99d52a98-95e3-48ae-a0c2-24d888d1183f",
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [
                    {
                        "reading_id": "12a2452f-4de5-43eb-b42a-a88723b9df88",
                        "metric": "mood",
                        "value": 4,
                        "sequence_number": 13,
                    },
                    {
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "metric": "heart_rate",
                        "value": 72,
                        "sequence_number": 12,
                    },
                ],
            }
        ],
    }

    with TestClient(app) as client:
        first = client.post(
            "/api/v1/sync/readings", json=batch, headers=_device_headers()
        )
        retry = client.post(
            "/api/v1/sync/readings", json=batch, headers=_device_headers()
        )
        new_batch_id = {
            **batch,
            "batch_id": "825ee45b-90cd-4bd0-9e45-e457445b5c78",
        }
        duplicate_readings = client.post(
            "/api/v1/sync/readings",
            json=new_batch_id,
            headers=_device_headers(),
        )
        status_response = client.get(
            f"/api/v1/sync/batches/{batch['batch_id']}",
            headers=_device_headers(),
        )
        history = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )

    assert first.status_code == 200
    assert {item["status"] for item in first.json()["items"]} == {"accepted"}
    assert retry.status_code == 200
    assert retry.json() == first.json()
    assert [item["sequence_number"] for item in first.json()["items"]] == [12, 13]
    assert duplicate_readings.status_code == 200
    assert {item["status"] for item in duplicate_readings.json()["items"]} == {
        "already_received"
    }
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "persisted"
    assert status_response.json()["items"] == first.json()["items"]
    assert history.json()["total"] == 2
    assert {item["sequence_number"] for item in history.json()["items"]} == {12, 13}


def test_offline_sync_conflict_rolls_back_entire_batch(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    existing_batch = {
        "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        "source_device_id": "99d52a98-95e3-48ae-a0c2-24d888d1183f",
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [
                    {
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "metric": "heart_rate",
                        "value": 72,
                        "sequence_number": 1,
                    }
                ],
            }
        ],
    }
    conflicting_batch = {
        "batch_id": "825ee45b-90cd-4bd0-9e45-e457445b5c78",
        "source_device_id": existing_batch["source_device_id"],
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:01:00Z",
                "measurements": [
                    {
                        "reading_id": "f391fc1d-425f-4dfb-bd88-aa1f7bb583ec",
                        "metric": "mood",
                        "value": 4,
                        "sequence_number": 2,
                    },
                    {
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "metric": "heart_rate",
                        "value": 73,
                        "sequence_number": 3,
                    },
                ],
            }
        ],
    }

    with TestClient(app) as client:
        assert (
            client.post(
                "/api/v1/sync/readings",
                json=existing_batch,
                headers=_device_headers(),
            ).status_code
            == 200
        )
        conflict = client.post(
            "/api/v1/sync/readings",
            json=conflicting_batch,
            headers=_device_headers(),
        )
        failed_batch_status = client.get(
            f"/api/v1/sync/batches/{conflicting_batch['batch_id']}",
            headers=_device_headers(),
        )
        history = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )

    assert conflict.status_code == 409
    assert failed_batch_status.status_code == 404
    assert history.json()["total"] == 1


def test_database_initialization_migrates_existing_readings(tmp_path, monkeypatch):
    database = tmp_path / "existing.sqlite3"
    monkeypatch.setenv("HEALTH_DB_PATH", str(database))
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE health_readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                astronaut_id TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT NOT NULL,
                measured_at TEXT NOT NULL,
                glucose_context TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO health_readings
                (astronaut_id, metric, value, unit, measured_at)
            VALUES ('astronaut-01', 'heart_rate', 72, 'bpm', '2026-11-14T16:00:00+00:00')
            """
        )

    initialize_database()

    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(health_readings)")}
        row = connection.execute(
            "SELECT astronaut_id, metric, value, reading_id, source_device_id, sequence_number "
            ", earth_sync_eligible FROM health_readings"
        ).fetchone()
        batch_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(sync_batches)")
        }
        batch_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        outbox_count = connection.execute(
            "SELECT COUNT(*) FROM earth_outbound_batches"
        ).fetchone()[0]

    assert {"reading_id", "source_device_id", "sequence_number"} <= columns
    assert "earth_sync_eligible" in columns
    assert row == ("astronaut-01", "heart_rate", 72.0, None, None, None, 0)
    assert "protocol_version" in batch_columns
    assert {"sync_batches", "sync_batch_items"} <= batch_tables
    assert {"earth_outbound_batches", "earth_outbound_batch_items"} <= batch_tables
    assert outbox_count == 0


def test_database_initialization_deactivates_legacy_unapproved_alert_rules(
    tmp_path, monkeypatch
):
    database = tmp_path / "legacy-alert-rules.sqlite3"
    monkeypatch.setenv("HEALTH_DB_PATH", str(database))
    legacy_rule = MonitoringAlertRule(
        rule_id="legacy-heart-rate",
        version=1,
        metric=Metric.HEART_RATE,
        minimum_value=55,
        rationale="Test-only illustrative threshold.",
        source_reference="TEST placeholder.",
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE monitoring_alert_rules (
                mission_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                rule_json TEXT NOT NULL,
                active INTEGER NOT NULL,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (mission_id, rule_id)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO monitoring_alert_rules (
                mission_id, rule_id, version, rule_json, active, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, 1, 'legacy', '2026-01-01T00:00:00+00:00')
            """,
            (
                _MISSION_ID,
                legacy_rule.rule_id,
                legacy_rule.version,
                legacy_rule.model_dump_json(),
            ),
        )

    initialize_database()

    with sqlite3.connect(database) as connection:
        rule = connection.execute(
            """
            SELECT active, updated_by FROM monitoring_alert_rules
            WHERE mission_id = ? AND rule_id = ?
            """,
            (_MISSION_ID, legacy_rule.rule_id),
        ).fetchone()
        audit = connection.execute(
            """
            SELECT action, actor_id, previous_active, current_active
            FROM monitoring_alert_rule_changes
            WHERE mission_id = ? AND rule_id = ?
            """,
            (_MISSION_ID, legacy_rule.rule_id),
        ).fetchone()

    assert rule == (0, "system:approval-required")
    assert audit == ("deactivated", "system:approval-required", 1, 0)


def _earth_sync_batch(*, eligible=True):
    return {
        "batch_id": "c228f603-1b3f-4f34-a5f1-d8d9f531a101",
        "source_device_id": "99d52a98-95e3-48ae-a0c2-24d888d1183f",
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [
                    {
                        "reading_id": "54d64069-2f8d-4ed8-8540-634b07b0d020",
                        "metric": "heart_rate",
                        "value": 72,
                        "sequence_number": 31,
                        "earth_sync_eligible": eligible,
                    },
                    {
                        "reading_id": "0926eed4-7895-4c45-8b5a-84708f292011",
                        "metric": "mood",
                        "value": 4,
                        "sequence_number": 32,
                        "earth_sync_eligible": False,
                    },
                ],
            }
        ],
    }


def test_v2_sync_atomically_enqueues_only_explicitly_eligible_new_readings(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    monkeypatch.setenv("EARTH_SERVICE_ID", "ground-health-service-001")
    batch = _earth_sync_batch()

    with TestClient(app) as client:
        response = client.post(
            "/api/v2/sync/readings",
            json=batch,
            headers=_device_headers(),
        )
        replay = client.post(
            "/api/v2/sync/readings",
            json=batch,
            headers=_device_headers(),
        )

    assert response.status_code == 200
    assert response.json()["onboard_status"] == "persisted"
    assert response.json()["earth_delivery_status"] == "pending"
    assert response.json()["delivery_batch_id"]
    assert replay.status_code == 200
    assert replay.json() == response.json()

    connection = connect_database()
    try:
        readings = connection.execute(
            """
            SELECT reading_id, earth_sync_eligible
            FROM health_readings
            ORDER BY sequence_number
            """
        ).fetchall()
        outbound = connection.execute(
            "SELECT * FROM earth_outbound_batches"
        ).fetchone()
        outbound_items = connection.execute(
            "SELECT * FROM earth_outbound_batch_items"
        ).fetchall()
        inbound = connection.execute(
            "SELECT protocol_version FROM sync_batches WHERE batch_id = ?",
            (batch["batch_id"],),
        ).fetchone()
    finally:
        connection.close()

    assert [(row["reading_id"], row["earth_sync_eligible"]) for row in readings] == [
        ("54d64069-2f8d-4ed8-8540-634b07b0d020", 1),
        ("0926eed4-7895-4c45-8b5a-84708f292011", 0),
    ]
    assert inbound["protocol_version"] == 2
    assert outbound["status"] == "pending"
    assert outbound["source_service_id"] == _ISSUER
    assert outbound["destination_service_id"] == "ground-health-service-001"
    assert outbound["delivery_batch_id"] == response.json()["delivery_batch_id"]
    assert hashlib.sha256(outbound["payload_json"].encode()).hexdigest() == (
        outbound["payload_sha256"]
    )
    assert len(outbound_items) == 1
    assert outbound_items[0]["reading_id"] == "54d64069-2f8d-4ed8-8540-634b07b0d020"


def test_v2_sync_requires_explicit_eligibility_and_destination_configuration(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    monkeypatch.delenv("EARTH_SERVICE_ID", raising=False)
    batch = _earth_sync_batch()
    with TestClient(app) as client:
        missing_flag = json.loads(json.dumps(batch))
        del missing_flag["readings"][0]["measurements"][0]["earth_sync_eligible"]
        invalid = client.post(
            "/api/v2/sync/readings",
            json=missing_flag,
            headers=_device_headers(),
        )
        missing_destination = client.post(
            "/api/v2/sync/readings",
            json=batch,
            headers=_device_headers(),
        )

    assert invalid.status_code == 422
    assert missing_destination.status_code == 503
    connection = connect_database()
    try:
        assert connection.execute("SELECT COUNT(*) FROM health_readings").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM sync_batches").fetchone()[0] == 0
    finally:
        connection.close()


def test_v2_sync_without_eligible_items_stays_local_without_earth_configuration(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    monkeypatch.delenv("EARTH_SERVICE_ID", raising=False)
    batch = _earth_sync_batch(eligible=False)
    with TestClient(app) as client:
        response = client.post(
            "/api/v2/sync/readings",
            json=batch,
            headers=_device_headers(),
        )

    assert response.status_code == 200
    assert response.json()["onboard_status"] == "persisted"
    assert response.json()["earth_delivery_status"] == "not_requested"
    assert response.json()["delivery_batch_id"] is None
    connection = connect_database()
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM earth_outbound_batches"
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_v2_outbox_failure_rolls_back_readings_and_inbound_receipt(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    monkeypatch.setenv("EARTH_SERVICE_ID", "ground-health-service-001")
    initialize_database()
    connection = connect_database()
    try:
        connection.execute(
            """
            CREATE TRIGGER reject_outbox_item
            BEFORE INSERT ON earth_outbound_batch_items
            BEGIN
                SELECT RAISE(ABORT, 'simulated outbox storage failure');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with TestClient(app) as client:
        response = client.post(
            "/api/v2/sync/readings",
            json=_earth_sync_batch(),
            headers=_device_headers(),
        )

    assert response.status_code == 500
    connection = connect_database()
    try:
        assert connection.execute("SELECT COUNT(*) FROM health_readings").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM sync_batches").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM earth_outbound_batches"
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_offline_sync_requires_stable_ids_and_unique_sequences(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    payload = {
        "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        "source_device_id": "99d52a98-95e3-48ae-a0c2-24d888d1183f",
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [
                    {
                        "metric": "heart_rate",
                        "value": 72,
                        "sequence_number": 12,
                    }
                ],
            }
        ],
    }

    with TestClient(app) as client:
        missing_id = client.post(
            "/api/v1/sync/readings",
            json=payload,
            headers=_device_headers(),
        )

    assert missing_id.status_code == 422


def test_offline_sync_rejects_reused_sequence_number(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    payload = {
        "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        "source_device_id": "99d52a98-95e3-48ae-a0c2-24d888d1183f",
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [
                    {
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "metric": "heart_rate",
                        "value": 72,
                        "sequence_number": 12,
                    },
                    {
                        "reading_id": "12a2452f-4de5-43eb-b42a-a88723b9df88",
                        "metric": "mood",
                        "value": 4,
                        "sequence_number": 12,
                    },
                ],
            }
        ],
    }

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/sync/readings",
            json=payload,
            headers=_device_headers(),
        )

    assert response.status_code == 422


def test_offline_sync_rejects_sequence_already_stored_for_device(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    batch = {
        "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        "source_device_id": "99d52a98-95e3-48ae-a0c2-24d888d1183f",
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [
                    {
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "metric": "heart_rate",
                        "value": 72,
                        "sequence_number": 12,
                    }
                ],
            }
        ],
    }
    replay_with_different_id = {
        **batch,
        "batch_id": "825ee45b-90cd-4bd0-9e45-e457445b5c78",
        "readings": [
            {
                **batch["readings"][0],
                "measurements": [
                    {
                        **batch["readings"][0]["measurements"][0],
                        "reading_id": "12a2452f-4de5-43eb-b42a-a88723b9df88",
                    }
                ],
            }
        ],
    }

    with TestClient(app) as client:
        first = client.post(
            "/api/v1/sync/readings", json=batch, headers=_device_headers()
        )
        replay = client.post(
            "/api/v1/sync/readings",
            json=replay_with_different_id,
            headers=_device_headers(),
        )

    assert first.status_code == 200
    assert replay.status_code == 409


def test_reading_endpoints_reject_missing_bearer_token():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
        )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_reading_endpoints_reject_wrong_audience():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(audience="another-api"),
        )

    assert response.status_code == 401


def test_reading_endpoints_reject_expired_token():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(expires_in=timedelta(seconds=-1)),
        )

    assert response.status_code == 401


def test_reading_endpoints_reject_invalid_actor_claim():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(actor_type=["user"]),
        )

    assert response.status_code == 401


def test_reading_endpoints_reject_token_for_another_mission():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(mission_id="another-mission"),
        )

    assert response.status_code == 401


def test_reading_endpoints_reject_unprovisioned_identity():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(subject="unprovisioned-user"),
        )

    assert response.status_code == 401


def test_reading_endpoints_reject_token_lifetime_above_delegation():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(expires_in=timedelta(hours=2)),
        )

    assert response.status_code == 401


def test_authorization_revalidates_persisted_delegation_each_request():
    with TestClient(app) as client:
        authorized = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )
        with sqlite3.connect(os.environ["HEALTH_DB_PATH"]) as connection:
            connection.execute(
                """
                UPDATE provisioned_mission_delegations
                SET signed_tokens_json = ?
                WHERE mission_id = ?
                """,
                (json.dumps(["invalid-token"]), _MISSION_ID),
            )
        rejected = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )

    assert authorized.status_code == 200
    assert rejected.status_code == 503


def test_users_cannot_access_astronauts_outside_their_scope():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-02"},
            headers=_authorization_headers(),
        )

    assert response.status_code == 403


def test_reading_endpoints_require_operation_permission():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(permissions=["readings:write"]),
        )

    assert response.status_code == 403


def test_sync_requires_matching_authenticated_device(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    batch = {
        "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        "source_device_id": _DEVICE_ID,
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [
                    {
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "sequence_number": 12,
                        "metric": "heart_rate",
                        "value": 72,
                    }
                ],
            }
        ],
    }

    with TestClient(app) as client:
        user_attempt = client.post(
            "/api/v1/sync/readings",
            json=batch,
            headers=_authorization_headers(),
        )
        mismatched_device = client.post(
            "/api/v1/sync/readings",
            json=batch,
            headers=_device_headers(device_id="another-device"),
        )
        unauthorized_astronaut = client.post(
            "/api/v1/sync/readings",
            json=batch,
            headers=_device_headers(astronaut_ids=["astronaut-02"]),
        )
        accepted = client.post(
            "/api/v1/sync/readings",
            json=batch,
            headers=_device_headers(),
        )

    assert user_attempt.status_code == 403
    assert mismatched_device.status_code == 403
    assert unauthorized_astronaut.status_code == 403
    assert accepted.status_code == 200


def test_sync_batch_id_cannot_be_reused_with_different_content(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    batch = {
        "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        "source_device_id": _DEVICE_ID,
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [
                    {
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "sequence_number": 12,
                        "metric": "heart_rate",
                        "value": 72,
                    }
                ],
            }
        ],
    }
    changed_batch = {
        **batch,
        "readings": [
            {
                **batch["readings"][0],
                "measurements": [
                    {
                        **batch["readings"][0]["measurements"][0],
                        "value": 73,
                    }
                ],
            }
        ],
    }

    with TestClient(app) as client:
        first = client.post(
            "/api/v1/sync/readings",
            json=batch,
            headers=_device_headers(),
        )
        conflict = client.post(
            "/api/v1/sync/readings",
            json=changed_batch,
            headers=_device_headers(),
        )
        history = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )

    assert first.status_code == 200
    assert conflict.status_code == 409
    assert history.json()["total"] == 1


def test_device_cannot_query_another_devices_sync_batch(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "health.sqlite3"))
    batch = {
        "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
        "source_device_id": _DEVICE_ID,
        "readings": [
            {
                "astronaut_id": "astronaut-01",
                "measured_at": "2026-11-14T16:00:00Z",
                "measurements": [
                    {
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "sequence_number": 12,
                        "metric": "heart_rate",
                        "value": 72,
                    }
                ],
            }
        ],
    }

    with TestClient(app) as client:
        client.post(
            "/api/v1/sync/readings",
            json=batch,
            headers=_device_headers(),
        )
        response = client.get(
            f"/api/v1/sync/batches/{batch['batch_id']}",
            headers=_device_headers(device_id="another-device"),
        )

    assert response.status_code == 403


def test_authentication_fails_closed_when_mission_bootstrap_is_not_configured(
    monkeypatch,
):
    monkeypatch.delenv("MISSION_BOOTSTRAP_PATH")
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )

    assert response.status_code == 503


def test_application_fails_to_start_with_invalid_bootstrap(monkeypatch, tmp_path):
    invalid_bootstrap = tmp_path / "invalid-bootstrap.json"
    invalid_bootstrap.write_text("{", encoding="utf-8")
    invalid_bootstrap.chmod(0o600)
    monkeypatch.setenv("MISSION_BOOTSTRAP_PATH", str(invalid_bootstrap.resolve()))

    with pytest.raises(RuntimeError, match="bootstrap da identidade"):
        with TestClient(app):
            pass


def test_bootstrap_rejects_onboard_key_mismatch(monkeypatch, tmp_path):
    invalid_bootstrap = tmp_path / "mismatched-key-bootstrap.json"
    data = json.loads(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]).read_text(encoding="utf-8")
    )
    data["onboard_token_verifier"]["public_key_pem"] = "not-a-public-key"
    invalid_bootstrap.write_text(json.dumps(data), encoding="utf-8")
    invalid_bootstrap.chmod(0o600)
    monkeypatch.setenv("MISSION_BOOTSTRAP_PATH", str(invalid_bootstrap.resolve()))

    with pytest.raises(RuntimeError, match="bootstrap da identidade"):
        with TestClient(app):
            pass


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode validation")
def test_bootstrap_rejects_group_or_world_access():
    bootstrap_path = Path(os.environ["MISSION_BOOTSTRAP_PATH"])
    bootstrap_path.chmod(0o644)
    try:
        with pytest.raises(IdentityBootstrapError, match="chmod 600"):
            load_identity_bootstrap(bootstrap_path)
    finally:
        bootstrap_path.chmod(0o600)


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL validation")
def test_bootstrap_rejects_access_granted_to_builtin_users():
    bootstrap_path = os.environ["MISSION_BOOTSTRAP_PATH"]
    subprocess.run(
        ["icacls", bootstrap_path, "/grant", "*S-1-5-32-545:(R)"],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        with pytest.raises(IdentityBootstrapError, match="conta não confiável"):
            load_identity_bootstrap(bootstrap_path)
    finally:
        subprocess.run(
            ["icacls", bootstrap_path, "/remove:g", "*S-1-5-32-545"],
            check=True,
            capture_output=True,
            text=True,
        )


def test_authentication_rejects_token_permissions_above_identity():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(
                permissions=["readings:read", "admin:all"]
            ),
        )

    assert response.status_code == 401


def test_openapi_declares_bearer_authentication_for_protected_routes():
    schema = app.openapi()

    assert "HTTPBearer" in schema["components"]["securitySchemes"]
    assert schema["paths"]["/api/v1/readings"]["get"]["security"]
    assert schema["paths"]["/api/v1/sync/readings"]["post"]["security"]
    assert schema["paths"]["/api/v2/sync/readings"]["post"]["security"]
    assert schema["paths"]["/api/v1/sync/batches/{batch_id}"]["get"]["security"]
    assert "security" not in schema["paths"]["/api/v1/auth/challenges"]["post"]
    assert "security" not in schema["paths"]["/api/v1/auth/token"]["post"]
    assert "security" not in schema["paths"]["/api/v1/auth/refresh"]["post"]
    assert "security" not in schema["paths"]["/api/v1/auth/revoke"]["post"]
    assert schema["paths"]["/api/v1/alerts/{alert_id}/acknowledge"]["post"]["security"]
    assert schema["paths"]["/api/v1/alerts/rules"]["get"]["security"]
    assert schema["paths"]["/api/v1/alerts/rules/{rule_id}"]["put"]["security"]
    assert schema["paths"]["/api/v1/alerts/rules/{rule_id}/deactivate"]["post"]["security"]
    assert schema["paths"]["/api/v1/alerts/rules/audit"]["get"]["security"]
    assert schema["paths"][
        "/api/v1/scientific-data/osdr/studies/{accession}"
    ]["get"]["security"]
    assert schema["paths"][
        "/api/v1/scientific-data/osdr/studies/{accession}/refresh"
    ]["post"]["security"]
    assert schema["paths"]["/api/v1/scientific-data/osdr/search"]["get"]["security"]
    assert schema["paths"][
        "/api/v1/scientific-data/osdr/search/refresh"
    ]["post"]["security"]
    assert schema["paths"][
        "/api/v1/scientific-data/osdr/studies/{accession}/files"
    ]["get"]["security"]
    assert schema["paths"][
        "/api/v1/scientific-data/osdr/studies/{accession}/files/refresh"
    ]["post"]["security"]
    assert schema["paths"][
        "/api/v1/scientific-data/osdr/studies/{accession}/files/{file_name}/imports"
    ]["post"]["security"]
    assert schema["paths"][
        "/api/v1/scientific-data/osdr/imports"
    ]["get"]["security"]
    assert "security" not in schema["paths"]["/health"]["get"]


def _osdr_metadata() -> OSDRStudyMetadata:
    return OSDRStudyMetadata(
        accession="OSD-575",
        title="SpaceX Inspiration4 Blood Serum Metabolic Panel",
        project_identifier="Inspiration4 Crew",
        mission_name="SpaceX Inspiration4",
        mission_start_date=datetime(2021, 9, 16).date(),
        mission_end_date=datetime(2021, 9, 18).date(),
        material_type="Serum",
        identifiers=("LSDS-8", "GLDS-579"),
        assay_technology_types=("Multiplex", "Comprehensive Metabolic Panel"),
        assay_platforms=("Eve Technologies Panel HDCVD9", "Quest Diagnostics"),
        source_api_url=(
            "https://visualization.osdr.nasa.gov/biodata/api/v2/dataset/OSD-575/"
        ),
        study_url="https://osdr.nasa.gov/bio/repo/data/studies/OSD-575",
        citation="NASA OSDR, OSD-575: SpaceX Inspiration4 Blood Serum Metabolic Panel.",
        retrieved_at=datetime.now(timezone.utc),
    )


def test_scientific_metadata_requires_explicit_read_permission():
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/scientific-data/osdr/studies/OSD-575",
            headers=_authorization_headers(permissions=["readings:read"]),
        )

    assert response.status_code == 403


def test_osdr_metadata_refresh_is_cached_and_readable_offline(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )
    metadata = _osdr_metadata()
    monkeypatch.setattr(
        "app.main.fetch_osdr_study_metadata",
        lambda _accession: metadata,
    )
    with TestClient(app) as client:
        refreshed = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/refresh",
            headers=_authorization_headers(
                permissions=["scientific-data:sync"]
            ),
        )
        monkeypatch.setattr(
            "app.main.fetch_osdr_study_metadata",
            lambda _accession: (_ for _ in ()).throw(AssertionError("network call")),
        )
        cached = client.get(
            "/api/v1/scientific-data/osdr/studies/OSD-575",
            headers=_authorization_headers(
                permissions=["scientific-data:read"]
            ),
        )

    assert refreshed.status_code == 200
    assert cached.status_code == 200
    assert cached.json()["accession"] == "OSD-575"
    assert cached.json()["identifiers"] == ["LSDS-8", "GLDS-579"]
    assert cached.json()["license_status"] == "not_verified"
    assert cached.json()["files_downloaded"] is False


def test_osdr_refresh_failure_does_not_create_cache_entry(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )

    def fail_refresh(_accession):
        raise OSDRMetadataError("NASA OSDR unavailable")

    monkeypatch.setattr("app.main.fetch_osdr_study_metadata", fail_refresh)
    with TestClient(app) as client:
        refreshed = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/refresh",
            headers=_authorization_headers(
                permissions=["scientific-data:sync"]
            ),
        )
        cached = client.get(
            "/api/v1/scientific-data/osdr/studies/OSD-575",
            headers=_authorization_headers(
                permissions=["scientific-data:read"]
            ),
        )

    assert refreshed.status_code == 502
    assert cached.status_code == 404


def _osdr_dataset_file(*, restricted=None, file_size_bytes=56):
    return OSDRDatasetFile(
        accession="OSD-575",
        file_name="test-transformed.csv",
        file_format="csv",
        source_api_url=(
            "https://visualization.osdr.nasa.gov/biodata/api/v2/"
            "dataset/OSD-575/file/test-transformed.csv/"
        ),
        download_url=(
            "https://osdr.nasa.gov/geode-py/ws/studies/OSD-575/"
            "download?source=datamanager&file=test-transformed.csv"
        ),
        file_size_bytes=file_size_bytes,
        restricted=restricted,
        remote_updated_at=None,
        retrieved_at=datetime.now(timezone.utc),
    )


def test_osdr_search_is_cached_for_offline_discovery(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )
    hits = (
        OSDRDatasetSearchHit(
            accession="OSD-575",
            organism="Homo sapiens",
            spaceflight_phase="Space Flight",
        ),
    )
    monkeypatch.setattr("app.main.search_osdr_datasets", lambda **_filters: hits)

    with TestClient(app) as client:
        refreshed = client.post(
            "/api/v1/scientific-data/osdr/search/refresh",
            params={"organism": "Homo sapiens"},
            headers=_authorization_headers(
                permissions=["scientific-data:sync"]
            ),
        )
        monkeypatch.setattr(
            "app.main.search_osdr_datasets",
            lambda **_filters: (_ for _ in ()).throw(AssertionError("network call")),
        )
        cached = client.get(
            "/api/v1/scientific-data/osdr/search",
            params={"organism": "Homo sapiens"},
            headers=_authorization_headers(
                permissions=["scientific-data:read"]
            ),
        )

    assert refreshed.status_code == 200
    assert cached.status_code == 200
    assert cached.json()["items"][0]["accession"] == "OSD-575"
    assert cached.json()["filters"] == {"organism": "Homo sapiens"}
    assert cached.json()["retrieved_at"] == refreshed.json()["retrieved_at"]


def test_osdr_search_requires_filter_and_permissions():
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )
    with TestClient(app) as client:
        no_filter = client.post(
            "/api/v1/scientific-data/osdr/search/refresh",
            headers=_authorization_headers(
                permissions=["scientific-data:sync"]
            ),
        )
        no_permission = client.get(
            "/api/v1/scientific-data/osdr/search",
            params={"organism": "Homo sapiens"},
            headers=_authorization_headers(),
        )

    assert no_filter.status_code == 422
    assert no_permission.status_code == 403


def test_osdr_file_inventory_is_cached_for_offline_reads(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )
    dataset_file = _osdr_dataset_file()
    monkeypatch.setattr(
        "app.main.fetch_osdr_dataset_files",
        lambda _accession: (dataset_file,),
    )

    with TestClient(app) as client:
        refreshed = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/files/refresh",
            headers=_authorization_headers(
                permissions=["scientific-data:sync"]
            ),
        )
        monkeypatch.setattr(
            "app.main.fetch_osdr_dataset_files",
            lambda _accession: (_ for _ in ()).throw(AssertionError("network call")),
        )
        cached = client.get(
            "/api/v1/scientific-data/osdr/studies/OSD-575/files",
            headers=_authorization_headers(
                permissions=["scientific-data:read"]
            ),
        )

    assert refreshed.status_code == 200
    assert cached.status_code == 200
    assert cached.json()[0]["file_name"] == "test-transformed.csv"
    assert cached.json()[0]["restricted"] is None


def test_osdr_csv_import_preserves_source_and_is_idempotent(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )
    content = b"sample_code,albumin_value_gram_per_deciliter\nS1,4.2\nS2,4.1\n"
    dataset_file = _osdr_dataset_file(file_size_bytes=len(content), restricted=False)
    monkeypatch.setenv("NASA_OSDR_IMPORT_MAX_BYTES", str(len(content)))
    monkeypatch.setattr(
        "app.main.fetch_osdr_study_metadata",
        lambda _accession: _osdr_metadata(),
    )
    monkeypatch.setattr(
        "app.main.fetch_osdr_dataset_file_metadata",
        lambda _accession, _file_name: (
            dataset_file,
            {
                "file_name": dataset_file.file_name,
                "restricted": False,
                "file_size": len(content),
            },
        ),
    )
    monkeypatch.setattr(
        "app.main.download_osdr_csv",
        lambda _file, *, max_bytes: content,
    )
    import_headers = _authorization_headers(
        permissions=["scientific-data:import"]
    )

    with TestClient(app) as client:
        first = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/"
            "files/test-transformed.csv/imports",
            headers=import_headers,
        )
        replay = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/"
            "files/test-transformed.csv/imports",
            headers=import_headers,
        )
        assert first.status_code == 200
        imported_id = first.json()["import_id"]
        details = client.get(
            f"/api/v1/scientific-data/osdr/imports/{imported_id}",
            headers=_authorization_headers(
                permissions=["scientific-data:read"]
            ),
        )
        records = client.get(
            f"/api/v1/scientific-data/osdr/imports/{imported_id}/records",
            params={"limit": 1},
            headers=_authorization_headers(
                permissions=["scientific-data:read"]
            ),
        )
        listing = client.get(
            "/api/v1/scientific-data/osdr/imports",
            params={"accession": "OSD-575"},
            headers=_authorization_headers(
                permissions=["scientific-data:read"]
            ),
        )
        refreshed_metadata = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/refresh",
            headers=_authorization_headers(
                permissions=["scientific-data:sync"]
            ),
        )
        cached_metadata = client.get(
            "/api/v1/scientific-data/osdr/studies/OSD-575",
            headers=_authorization_headers(
                permissions=["scientific-data:read"]
            ),
        )

    assert first.status_code == 200
    assert replay.status_code == 200
    assert first.json()["import_id"] == replay.json()["import_id"]
    assert first.json()["provenance"] == "nasa_osdr"
    assert first.json()["license_status"] == "not_verified"
    assert first.json()["normalization_status"] == "not_performed"
    assert first.json()["file_sha256"] == hashlib.sha256(content).hexdigest()
    assert details.status_code == 200
    assert records.status_code == 200
    assert records.json()["items"][0]["origin"] == "nasa"
    assert records.json()["items"][0]["source_values"] == {
        "sample_code": "S1",
        "albumin_value_gram_per_deciliter": "4.2",
    }
    assert records.json()["total"] == 2
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert refreshed_metadata.status_code == 200
    assert refreshed_metadata.json()["files_downloaded"] is True
    assert cached_metadata.status_code == 200
    assert cached_metadata.json()["files_downloaded"] is True

    connection = connect_database()
    try:
        stored = connection.execute(
            """
            SELECT original_content, record_count
            FROM nasa_osdr_dataset_imports
            """
        ).fetchone()
        reading_count = connection.execute(
            "SELECT COUNT(*) FROM health_readings"
        ).fetchone()[0]
        row_count = connection.execute(
            "SELECT COUNT(*) FROM nasa_osdr_dataset_import_rows"
        ).fetchone()[0]
        transformation = connection.execute(
            """
            SELECT operation, details_json
            FROM nasa_osdr_import_transformations
            """
        ).fetchone()
    finally:
        connection.close()

    assert bytes(stored["original_content"]) == content
    assert stored["record_count"] == 2
    assert reading_count == 0
    assert row_count == 2
    assert transformation["operation"] == "csv_parse_preserving_source_values"
    assert "not_performed" in transformation["details_json"]


def test_osdr_import_requires_explicit_import_permission():
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/"
            "files/test-transformed.csv/imports",
            headers=_authorization_headers(
                permissions=["scientific-data:sync"]
            ),
        )

    assert response.status_code == 403


def test_osdr_import_rejects_restricted_file_without_persisting(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )
    content = b"sample,value\nS1,1\n"
    dataset_file = _osdr_dataset_file(file_size_bytes=len(content), restricted=True)
    monkeypatch.setenv("NASA_OSDR_IMPORT_MAX_BYTES", str(len(content)))
    monkeypatch.setattr(
        "app.main.fetch_osdr_study_metadata",
        lambda _accession: _osdr_metadata(),
    )
    monkeypatch.setattr(
        "app.main.fetch_osdr_dataset_file_metadata",
        lambda _accession, _file_name: (dataset_file, {"restricted": True}),
    )
    monkeypatch.setattr(
        "app.main.download_osdr_csv",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("restricted download attempted")
        ),
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/"
            "files/test-transformed.csv/imports",
            headers=_authorization_headers(
                permissions=["scientific-data:import"]
            ),
        )

    assert response.status_code == 403
    connection = connect_database()
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM nasa_osdr_dataset_imports"
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_osdr_import_rejects_xlsx_until_a_workbook_parser_exists(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )
    xlsx_file = _osdr_dataset_file(
        file_size_bytes=100,
        restricted=False,
    ).model_copy(
        update={
            "file_name": "panel.xlsx",
            "file_format": "xlsx",
        }
    )
    monkeypatch.setenv("NASA_OSDR_IMPORT_MAX_BYTES", "1000")
    monkeypatch.setattr(
        "app.main.fetch_osdr_study_metadata",
        lambda _accession: _osdr_metadata(),
    )
    monkeypatch.setattr(
        "app.main.fetch_osdr_dataset_file_metadata",
        lambda _accession, _file_name: (xlsx_file, {"restricted": False}),
    )
    monkeypatch.setattr(
        "app.main.download_osdr_csv",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("xlsx must not be sent to the CSV downloader")
        ),
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/"
            "files/panel.xlsx/imports",
            headers=_authorization_headers(
                permissions=["scientific-data:import"]
            ),
        )

    assert response.status_code == 415
    connection = connect_database()
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM nasa_osdr_dataset_imports"
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_osdr_import_rolls_back_partial_persistence(monkeypatch):
    _create_bootstrap_file(
        Path(os.environ["MISSION_BOOTSTRAP_PATH"]),
        enable_scientific_data=True,
    )
    content = b"sample,value\nS1,1\n"
    dataset_file = _osdr_dataset_file(file_size_bytes=len(content), restricted=False)
    monkeypatch.setenv("NASA_OSDR_IMPORT_MAX_BYTES", str(len(content)))
    monkeypatch.setattr(
        "app.main.fetch_osdr_study_metadata",
        lambda _accession: _osdr_metadata(),
    )
    monkeypatch.setattr(
        "app.main.fetch_osdr_dataset_file_metadata",
        lambda _accession, _file_name: (
            dataset_file,
            {"file_name": dataset_file.file_name, "restricted": False},
        ),
    )
    monkeypatch.setattr(
        "app.main.download_osdr_csv",
        lambda _file, *, max_bytes: content,
    )

    with TestClient(app) as client:
        connection = connect_database()
        try:
            connection.execute(
                """
                CREATE TRIGGER reject_nasa_import_row
                BEFORE INSERT ON nasa_osdr_dataset_import_rows
                BEGIN
                    SELECT RAISE(ABORT, 'simulated row storage failure');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()
        response = client.post(
            "/api/v1/scientific-data/osdr/studies/OSD-575/"
            "files/test-transformed.csv/imports",
            headers=_authorization_headers(
                permissions=["scientific-data:import"]
            ),
        )

    assert response.status_code == 500
    connection = connect_database()
    try:
        for table_name in (
            "nasa_osdr_study_metadata",
            "nasa_osdr_dataset_files",
            "nasa_osdr_dataset_imports",
            "nasa_osdr_dataset_import_rows",
            "nasa_osdr_import_transformations",
        ):
            assert connection.execute(
                f"SELECT COUNT(*) FROM {table_name}"
            ).fetchone()[0] == 0
    finally:
        connection.close()
