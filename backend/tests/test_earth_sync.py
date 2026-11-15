from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
import pytest

import app.earth_sync as earth_sync
from app.database import connect_database, initialize_database
from app.earth_sync import (
    EarthSyncProtocolError,
    EarthSyncSettings,
    canonical_json,
    create_request_token,
    process_due_outbox_batches,
    receive_earth_sync_payload,
    verify_receipt_token,
)


def _settings_pair():
    onboard_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    earth_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    onboard = EarthSyncSettings(
        role="onboard",
        local_service_id="onboard-service",
        peer_service_id="earth-service",
        signing_key=onboard_key,
        peer_public_key=earth_key.public_key(),
        request_timeout_seconds=10,
        retry_base_seconds=5,
        retry_max_seconds=20,
        lease_seconds=20,
    )
    earth = EarthSyncSettings(
        role="earth",
        local_service_id="earth-service",
        peer_service_id="onboard-service",
        signing_key=earth_key,
        peer_public_key=onboard_key.public_key(),
    )
    return onboard, earth


def _payload(*, delivery_batch_id=None, reading_id=None, value=72):
    origin_batch_id = str(uuid4())
    return {
        "protocol_version": 1,
        "delivery_batch_id": str(delivery_batch_id or uuid4()),
        "origin_batch_id": origin_batch_id,
        "source_service_id": "onboard-service",
        "destination_service_id": "earth-service",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "items": [
            {
                "reading_id": str(reading_id or uuid4()),
                "astronaut_id": "crew-01",
                "metric": "heart_rate",
                "value": value,
                "unit": "bpm",
                "measured_at": datetime.now(timezone.utc).isoformat(),
                "received_at": datetime.now(timezone.utc).isoformat(),
                "glucose_context": None,
                "declared_origin": "manual",
                "source_device_id": str(uuid4()),
                "sequence_number": 1,
                "origin_batch_id": origin_batch_id,
            }
        ],
    }


def _request_token(settings, payload):
    encoded_payload = canonical_json(payload)
    return create_request_token(
        settings,
        payload=payload,
        payload_sha256=hashlib.sha256(encoded_payload.encode("utf-8")).hexdigest(),
    )


def _init_database(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "mission.sqlite3"))
    initialize_database()
    return connect_database()


def test_receiver_persists_atomically_and_returns_stable_idempotent_receipt(
    tmp_path,
    monkeypatch,
):
    onboard, earth = _settings_pair()
    with closing(_init_database(tmp_path, monkeypatch)) as connection:
        payload = _payload()
        token = _request_token(onboard, payload)

        first = receive_earth_sync_payload(
            connection,
            earth,
            payload=payload,
            bearer_token=token,
        )
        replay = receive_earth_sync_payload(
            connection,
            earth,
            payload=payload,
            bearer_token=token,
        )
        payload_hash = hashlib.sha256(
            canonical_json(payload).encode("utf-8")
        ).hexdigest()
        receipt = verify_receipt_token(
            onboard,
            token=replay.token,
            delivery_batch_id=payload["delivery_batch_id"],
            payload_sha256=payload_hash,
            expected_reading_ids={payload["items"][0]["reading_id"]},
        )
        batch_count = connection.execute(
            "SELECT COUNT(*) FROM earth_received_batches"
        ).fetchone()[0]
        item_count = connection.execute(
            "SELECT COUNT(*) FROM earth_received_items"
        ).fetchone()[0]
        link_count = connection.execute(
            "SELECT COUNT(*) FROM earth_received_batch_items"
        ).fetchone()[0]

    assert first.http_status == replay.http_status == 200
    assert first.token == replay.token
    assert receipt["status"] == "persisted"
    assert batch_count == item_count == link_count == 1


def test_receiver_deduplicates_readings_and_isolates_content_or_sequence_conflicts(
    tmp_path,
    monkeypatch,
):
    onboard, earth = _settings_pair()
    with closing(_init_database(tmp_path, monkeypatch)) as connection:
        first_payload = _payload()
        first_receipt = receive_earth_sync_payload(
            connection,
            earth,
            payload=first_payload,
            bearer_token=_request_token(onboard, first_payload),
        )

        same_reading_payload = json.loads(canonical_json(first_payload))
        same_reading_payload["delivery_batch_id"] = str(uuid4())
        duplicate_receipt = receive_earth_sync_payload(
            connection,
            earth,
            payload=same_reading_payload,
            bearer_token=_request_token(onboard, same_reading_payload),
        )

        conflicting_payload = json.loads(canonical_json(first_payload))
        conflicting_payload["delivery_batch_id"] = str(uuid4())
        conflicting_payload["items"][0]["value"] = 140
        conflict_receipt = receive_earth_sync_payload(
            connection,
            earth,
            payload=conflicting_payload,
            bearer_token=_request_token(onboard, conflicting_payload),
        )
        sequence_conflict_payload = json.loads(canonical_json(first_payload))
        sequence_conflict_payload["delivery_batch_id"] = str(uuid4())
        sequence_conflict_payload["items"][0]["reading_id"] = str(uuid4())
        sequence_conflict_receipt = receive_earth_sync_payload(
            connection,
            earth,
            payload=sequence_conflict_payload,
            bearer_token=_request_token(onboard, sequence_conflict_payload),
        )
        stored_item_count = connection.execute(
            "SELECT COUNT(*) FROM earth_received_items"
        ).fetchone()[0]
        conflict_count = connection.execute(
            "SELECT COUNT(*) FROM earth_sync_conflicts"
        ).fetchone()[0]

    assert first_receipt.http_status == 200
    assert duplicate_receipt.http_status == 200
    assert conflict_receipt.http_status == 409
    assert sequence_conflict_receipt.http_status == 409
    assert stored_item_count == 1
    assert conflict_count == 2


def test_receiver_persists_permanent_rejection_and_replays_its_receipt(
    tmp_path,
    monkeypatch,
):
    onboard, earth = _settings_pair()
    payload = _payload()
    payload["protocol_version"] = 2
    token = _request_token(onboard, payload)

    with closing(_init_database(tmp_path, monkeypatch)) as connection:
        first = receive_earth_sync_payload(
            connection,
            earth,
            payload=payload,
            bearer_token=token,
        )
        replay = receive_earth_sync_payload(
            connection,
            earth,
            payload=payload,
            bearer_token=token,
        )
        item_count = connection.execute(
            "SELECT COUNT(*) FROM earth_received_items"
        ).fetchone()[0]
        batch = connection.execute(
            "SELECT status FROM earth_received_batches"
        ).fetchone()

    assert first.http_status == replay.http_status == 422
    assert first.token == replay.token
    assert batch["status"] == "rejected_permanent"
    assert item_count == 0


def test_receiver_validates_service_signature_and_does_not_ack_payload_tampering(
    tmp_path,
    monkeypatch,
):
    onboard, earth = _settings_pair()
    payload = _payload()
    token = _request_token(onboard, payload)
    payload["items"][0]["value"] = 200
    with closing(_init_database(tmp_path, monkeypatch)) as connection:
        try:
            receive_earth_sync_payload(
                connection,
                earth,
                payload=payload,
                bearer_token=token,
            )
        except EarthSyncProtocolError:
            pass
        else:
            raise AssertionError("Tampered payload was accepted.")
        stored_count = connection.execute(
            "SELECT COUNT(*) FROM earth_received_batches"
        ).fetchone()[0]

    assert stored_count == 0


def test_receiver_storage_failure_rolls_back_without_receipt(
    tmp_path,
    monkeypatch,
):
    onboard, earth = _settings_pair()
    with closing(_init_database(tmp_path, monkeypatch)) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_earth_item
            BEFORE INSERT ON earth_received_items
            BEGIN
                SELECT RAISE(ABORT, 'storage unavailable');
            END
            """
        )
        connection.commit()
        payload = _payload()
        try:
            receive_earth_sync_payload(
                connection,
                earth,
                payload=payload,
                bearer_token=_request_token(onboard, payload),
            )
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("Storage failure was not surfaced.")
        assert connection.execute(
            "SELECT COUNT(*) FROM earth_received_batches"
        ).fetchone()[0] == 0


def test_worker_recovers_lost_response_and_acknowledges_only_signed_receipt(
    tmp_path,
    monkeypatch,
):
    onboard, earth = _settings_pair()
    with closing(_init_database(tmp_path, monkeypatch)) as connection:
        payload = _payload()
        payload_json = canonical_json(payload)
        digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO earth_outbound_batches (
                delivery_batch_id, origin_batch_id, source_service_id,
                destination_service_id, protocol_version, payload_json,
                payload_sha256, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                payload["delivery_batch_id"],
                payload["origin_batch_id"],
                onboard.local_service_id,
                onboard.peer_service_id,
                1,
                payload_json,
                digest,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()
        clock = [datetime.now(timezone.utc)]
        calls = [0]

        def fake_send(settings, *, payload_json, payload_sha256):
            batch_payload = json.loads(payload_json)
            receipt = receive_earth_sync_payload(
                connection,
                earth,
                payload=batch_payload,
                bearer_token=create_request_token(
                    settings,
                    payload=batch_payload,
                    payload_sha256=payload_sha256,
                ),
            )
            calls[0] += 1
            if calls[0] == 1:
                raise EarthSyncProtocolError("Resposta perdida após persistência.")
            return receipt.http_status, receipt.token

        monkeypatch.setattr(earth_sync, "_send_batch", fake_send)
        first_run = process_due_outbox_batches(
            connection,
            onboard,
            now_provider=lambda: clock[0],
        )
        pending = connection.execute(
            """
            SELECT status, attempt_count, next_attempt_at
            FROM earth_outbound_batches WHERE delivery_batch_id = ?
            """,
            (payload["delivery_batch_id"],),
        ).fetchone()
        clock[0] = datetime.fromisoformat(pending["next_attempt_at"])
        second_run = process_due_outbox_batches(
            connection,
            onboard,
            now_provider=lambda: clock[0],
        )
        final = connection.execute(
            """
            SELECT status, attempt_count, receipt_json, acknowledged_at
            FROM earth_outbound_batches WHERE delivery_batch_id = ?
            """,
            (payload["delivery_batch_id"],),
        ).fetchone()

    assert first_run.retry_scheduled == 1
    assert pending["status"] == "retry_wait"
    assert second_run.acknowledged == 1
    assert final["status"] == "acknowledged_durable"
    assert final["attempt_count"] == 2
    assert final["receipt_json"]
    assert final["acknowledged_at"]


def test_worker_does_not_accept_unsigned_or_mismatched_receipt(
    tmp_path,
    monkeypatch,
):
    onboard, earth = _settings_pair()
    with closing(_init_database(tmp_path, monkeypatch)) as connection:
        payload = _payload()
        payload_json = canonical_json(payload)
        digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO earth_outbound_batches (
                delivery_batch_id, origin_batch_id, source_service_id,
                destination_service_id, protocol_version, payload_json,
                payload_sha256, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                payload["delivery_batch_id"],
                payload["origin_batch_id"],
                onboard.local_service_id,
                onboard.peer_service_id,
                1,
                payload_json,
                digest,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()
        monkeypatch.setattr(
            earth_sync,
            "_send_batch",
            lambda *_args, **_kwargs: (200, "not-a-signed-receipt"),
        )
        result = process_due_outbox_batches(connection, onboard)
        state = connection.execute(
            "SELECT status, acknowledged_at FROM earth_outbound_batches"
        ).fetchone()

    assert result.retry_scheduled == 1
    assert state["status"] == "retry_wait"
    assert state["acknowledged_at"] is None


def test_worker_recovers_an_expired_claimed_lease_after_restart(
    tmp_path,
    monkeypatch,
):
    onboard, earth = _settings_pair()
    with closing(_init_database(tmp_path, monkeypatch)) as connection:
        payload = _payload()
        payload_json = canonical_json(payload)
        digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc)
        connection.execute(
            """
            INSERT INTO earth_outbound_batches (
                delivery_batch_id, origin_batch_id, source_service_id,
                destination_service_id, protocol_version, payload_json,
                payload_sha256, status, created_at, attempt_count,
                last_attempt_at, lease_owner, lease_expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'in_flight', ?, 1, ?, 'old-worker', ?)
            """,
            (
                payload["delivery_batch_id"],
                payload["origin_batch_id"],
                onboard.local_service_id,
                onboard.peer_service_id,
                1,
                payload_json,
                digest,
                now.isoformat(),
                now.isoformat(),
                (now - timedelta(seconds=1)).isoformat(),
            ),
        )
        connection.commit()

        def fake_send(settings, *, payload_json, payload_sha256):
            batch_payload = json.loads(payload_json)
            receipt = receive_earth_sync_payload(
                connection,
                earth,
                payload=batch_payload,
                bearer_token=create_request_token(
                    settings,
                    payload=batch_payload,
                    payload_sha256=payload_sha256,
                ),
            )
            return receipt.http_status, receipt.token

        monkeypatch.setattr(earth_sync, "_send_batch", fake_send)
        result = process_due_outbox_batches(
            connection,
            onboard,
            now_provider=lambda: now,
        )
        state = connection.execute(
            """
            SELECT status, attempt_count, lease_owner, receipt_json
            FROM earth_outbound_batches WHERE delivery_batch_id = ?
            """,
            (payload["delivery_batch_id"],),
        ).fetchone()

    assert result.attempted == result.acknowledged == 1
    assert state["status"] == "acknowledged_durable"
    assert state["attempt_count"] == 2
    assert state["lease_owner"] is None
    assert state["receipt_json"]


def test_earth_role_cannot_start_without_the_mtls_receiver_runner(
    monkeypatch,
):
    _, earth = _settings_pair()
    monkeypatch.setenv("EARTH_SYNC_ROLE", "earth")
    monkeypatch.delenv("EARTH_SYNC_MTLS_ENFORCED", raising=False)
    import app.main as main

    monkeypatch.setattr(main, "load_earth_sync_settings", lambda: earth)
    with pytest.raises(RuntimeError, match="sincronização bordo-Terra"):
        with TestClient(main.app):
            pass


def test_receiver_http_endpoint_requires_service_token_and_persists_before_ack(
    tmp_path,
    monkeypatch,
):
    onboard, earth = _settings_pair()
    monkeypatch.setenv("HEALTH_DB_PATH", str(tmp_path / "endpoint.sqlite3"))
    monkeypatch.setenv("EARTH_SYNC_ROLE", "earth")
    monkeypatch.setenv("EARTH_SYNC_MTLS_ENFORCED", "1")
    from fastapi.testclient import TestClient

    import app.main as main

    monkeypatch.setattr(main, "load_earth_sync_settings", lambda: earth)

    with TestClient(main.app, base_url="https://testserver") as client:
        plaintext = client.post(
            "http://testserver/api/v1/sync/earth/batches",
            json=_payload(),
        )
        missing_auth = client.post(
            "/api/v1/sync/earth/batches",
            json=_payload(),
        )
        payload = _payload()
        response = client.post(
            "/api/v1/sync/earth/batches",
            json=payload,
            headers={"Authorization": f"Bearer {_request_token(onboard, payload)}"},
        )
        ready = client.get("/ready")

    assert plaintext.status_code == 426
    assert missing_auth.status_code == 401
    assert response.status_code == 200
    assert response.json()["receipt"]
    assert ready.status_code == 200
