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


def _create_bootstrap_file(path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    mission_start = now - timedelta(days=30)
    mission_end = now + timedelta(days=365)
    identities = (
        MissionIdentity(
            identity_id=_ISSUER,
            mission_id=_MISSION_ID,
            actor_type=ActorType.SERVICE,
            state=IdentityState.ACTIVE,
            permissions=frozenset({"readings:read", "readings:write", "sync:write"}),
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
            permissions=frozenset({"readings:read", "readings:write"}),
            astronaut_ids=frozenset({"astronaut-01", "astronaut-02"}),
            valid_from=mission_start,
            expires_at=mission_end,
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
        permissions=frozenset({"readings:read", "readings:write", "sync:write"}),
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
    monkeypatch.setenv("MISSION_BOOTSTRAP_PATH", str(bootstrap_path.resolve()))
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
            "FROM health_readings"
        ).fetchone()
        batch_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert {"reading_id", "source_device_id", "sequence_number"} <= columns
    assert row == ("astronaut-01", "heart_rate", 72.0, None, None, None)
    assert {"sync_batches", "sync_batch_items"} <= batch_tables


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
    assert schema["paths"]["/api/v1/sync/batches/{batch_id}"]["get"]["security"]
    assert "security" not in schema["paths"]["/health"]["get"]
