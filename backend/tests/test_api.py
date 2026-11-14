from datetime import datetime, timedelta, timezone
import sqlite3

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.database import initialize_database
from app.main import app


_ISSUER = "mission-identity"
_AUDIENCE = "health-monitoring-api"
_DEVICE_ID = "99d52a98-95e3-48ae-a0c2-24d888d1183f"
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()


@pytest.fixture(autouse=True)
def configure_authentication(monkeypatch):
    monkeypatch.setenv("AUTH_PUBLIC_KEY", _PUBLIC_KEY)
    monkeypatch.setenv("AUTH_ISSUER", _ISSUER)
    monkeypatch.setenv("AUTH_AUDIENCE", _AUDIENCE)


def _authorization_headers(
    *,
    actor_type="user",
    subject="user-01",
    astronaut_ids=None,
    permissions=None,
    audience=_AUDIENCE,
    expires_in=timedelta(minutes=5),
):
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": subject,
            "iss": _ISSUER,
            "aud": audience,
            "iat": now,
            "exp": now + expires_in,
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
    )
    return {"Authorization": f"Bearer {token}"}


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
                        "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
                        "metric": "heart_rate",
                        "value": 72,
                        "sequence_number": 12,
                    },
                    {
                        "reading_id": "12a2452f-4de5-43eb-b42a-a88723b9df88",
                        "metric": "mood",
                        "value": 4,
                        "sequence_number": 13,
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
        history = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )

    assert first.status_code == 200
    assert {item["status"] for item in first.json()["items"]} == {"accepted"}
    assert retry.status_code == 200
    assert {item["status"] for item in retry.json()["items"]} == {"already_received"}
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
        history = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )

    assert conflict.status_code == 409
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

    assert {"reading_id", "source_device_id", "sequence_number"} <= columns
    assert row == ("astronaut-01", "heart_rate", 72.0, None, None, None)


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


def test_authentication_fails_closed_when_not_configured(monkeypatch):
    monkeypatch.delenv("AUTH_PUBLIC_KEY")
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )

    assert response.status_code == 503


def test_authentication_fails_closed_with_invalid_public_key(monkeypatch):
    monkeypatch.setenv("AUTH_PUBLIC_KEY", "not-a-public-key")
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/readings",
            params={"astronaut_id": "astronaut-01"},
            headers=_authorization_headers(),
        )

    assert response.status_code == 503


def test_openapi_declares_bearer_authentication_for_protected_routes():
    schema = app.openapi()

    assert "HTTPBearer" in schema["components"]["securitySchemes"]
    assert schema["paths"]["/api/v1/readings"]["get"]["security"]
    assert schema["paths"]["/api/v1/sync/readings"]["post"]["security"]
    assert "security" not in schema["paths"]["/health"]["get"]
