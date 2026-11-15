import os
import sqlite3
from pathlib import Path
from typing import Iterator


def database_path() -> Path:
    return Path(os.environ.get("HEALTH_DB_PATH", "data/health_monitoring.sqlite3"))


def connect_database() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def get_connection() -> Iterator[sqlite3.Connection]:
    connection = connect_database()
    try:
        yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS health_readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                astronaut_id TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT NOT NULL,
                measured_at TEXT NOT NULL,
                glucose_context TEXT,
                received_at TEXT,
                declared_origin TEXT NOT NULL DEFAULT 'manual',
                earth_sync_eligible INTEGER NOT NULL DEFAULT 0
                    CHECK (earth_sync_eligible IN (0, 1))
            )
            """
        )
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(health_readings)")
        }
        if "reading_id" not in columns:
            connection.execute("ALTER TABLE health_readings ADD COLUMN reading_id TEXT")
        if "source_device_id" not in columns:
            connection.execute("ALTER TABLE health_readings ADD COLUMN source_device_id TEXT")
        if "sequence_number" not in columns:
            connection.execute("ALTER TABLE health_readings ADD COLUMN sequence_number INTEGER")
        if "received_at" not in columns:
            connection.execute("ALTER TABLE health_readings ADD COLUMN received_at TEXT")
        if "declared_origin" not in columns:
            connection.execute(
                """
                ALTER TABLE health_readings
                ADD COLUMN declared_origin TEXT NOT NULL DEFAULT 'manual'
                """
            )
        if "earth_sync_eligible" not in columns:
            connection.execute(
                """
                ALTER TABLE health_readings
                ADD COLUMN earth_sync_eligible INTEGER NOT NULL DEFAULT 0
                    CHECK (earth_sync_eligible IN (0, 1))
                """
            )
        reading_id_index = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'index' AND name = 'idx_health_readings_reading_id'
            """
        ).fetchone()
        if reading_id_index is not None and "WHERE" in reading_id_index[0].upper():
            connection.execute("DROP INDEX idx_health_readings_reading_id")
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_health_readings_reading_id
            ON health_readings (reading_id)
            """
        )
        connection.execute(
            """
            DROP INDEX IF EXISTS idx_health_readings_device_sequence_metric
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_health_readings_device_sequence
            ON health_readings (source_device_id, sequence_number)
            WHERE source_device_id IS NOT NULL AND sequence_number IS NOT NULL
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_health_readings_astronaut_metric_time
            ON health_readings (astronaut_id, metric, measured_at)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_batches (
                batch_id TEXT PRIMARY KEY,
                source_device_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                received_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status = 'persisted'),
                protocol_version INTEGER NOT NULL DEFAULT 1
                    CHECK (protocol_version >= 1)
            )
            """
        )
        sync_batch_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(sync_batches)")
        }
        if "protocol_version" not in sync_batch_columns:
            connection.execute(
                """
                ALTER TABLE sync_batches
                ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 1
                    CHECK (protocol_version >= 1)
                """
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ingestion_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                astronaut_id TEXT,
                declared_origin TEXT NOT NULL
                    CHECK (declared_origin IN ('nasa', 'simulated', 'manual', 'unknown')),
                outcome TEXT NOT NULL
                    CHECK (outcome IN ('duplicate', 'rejected', 'conflict')),
                record_count INTEGER NOT NULL DEFAULT 1 CHECK (record_count >= 1),
                occurred_at TEXT NOT NULL
            )
            """
        )
        event_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(ingestion_events)")
        }
        if "record_count" not in event_columns:
            connection.execute(
                """
                ALTER TABLE ingestion_events
                ADD COLUMN record_count INTEGER NOT NULL DEFAULT 1
                """
            )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ingestion_events_astronaut_time
            ON ingestion_events (astronaut_id, occurred_at, outcome)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_health_readings_astronaut_received
            ON health_readings (astronaut_id, received_at)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_batch_items (
                batch_id TEXT NOT NULL REFERENCES sync_batches(batch_id),
                reading_id TEXT NOT NULL REFERENCES health_readings(reading_id),
                sequence_number INTEGER NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('accepted', 'already_received')),
                PRIMARY KEY (batch_id, reading_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS earth_outbound_batches (
                delivery_batch_id TEXT PRIMARY KEY,
                origin_batch_id TEXT NOT NULL,
                source_service_id TEXT NOT NULL,
                destination_service_id TEXT NOT NULL,
                protocol_version INTEGER NOT NULL CHECK (protocol_version >= 1),
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN (
                        'pending', 'in_flight', 'retry_wait',
                        'acknowledged_durable', 'rejected_permanent',
                        'conflict_isolated'
                    )
                ),
                created_at TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                last_attempt_at TEXT,
                next_attempt_at TEXT,
                lease_owner TEXT,
                lease_expires_at TEXT,
                receipt_json TEXT,
                acknowledged_at TEXT,
                error_code TEXT,
                UNIQUE (origin_batch_id, destination_service_id),
                CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
                CHECK (
                    status != 'acknowledged_durable'
                    OR (receipt_json IS NOT NULL AND acknowledged_at IS NOT NULL)
                )
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_earth_outbound_batches_pending
            ON earth_outbound_batches (status, next_attempt_at, created_at)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS earth_outbound_batch_items (
                delivery_batch_id TEXT NOT NULL
                    REFERENCES earth_outbound_batches(delivery_batch_id),
                reading_id TEXT NOT NULL UNIQUE
                    REFERENCES health_readings(reading_id),
                origin_batch_id TEXT NOT NULL,
                source_device_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL CHECK (sequence_number >= 1),
                item_sha256 TEXT NOT NULL,
                PRIMARY KEY (delivery_batch_id, reading_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS earth_received_batches (
                delivery_batch_id TEXT PRIMARY KEY,
                origin_batch_id TEXT NOT NULL,
                source_service_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                receipt_jwt TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN (
                        'persisted', 'already_persisted', 'rejected_permanent'
                    )
                ),
                recorded_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_earth_received_batches_origin_time
            ON earth_received_batches (origin_batch_id, recorded_at)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS earth_received_items (
                reading_id TEXT PRIMARY KEY,
                source_device_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL CHECK (sequence_number >= 1),
                item_sha256 TEXT NOT NULL,
                item_json TEXT NOT NULL,
                first_delivery_batch_id TEXT NOT NULL
                    REFERENCES earth_received_batches(delivery_batch_id)
            )
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_earth_received_device_sequence
            ON earth_received_items (source_device_id, sequence_number)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS earth_received_batch_items (
                delivery_batch_id TEXT NOT NULL
                    REFERENCES earth_received_batches(delivery_batch_id),
                reading_id TEXT NOT NULL
                    REFERENCES earth_received_items(reading_id),
                item_sha256 TEXT NOT NULL,
                PRIMARY KEY (delivery_batch_id, reading_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS earth_sync_conflicts (
                conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_batch_id TEXT NOT NULL,
                origin_batch_id TEXT NOT NULL,
                source_service_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                conflict_code TEXT NOT NULL,
                receipt_jwt TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE (delivery_batch_id, payload_sha256)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_earth_sync_conflicts_recorded
            ON earth_sync_conflicts (recorded_at, conflict_id)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS monitoring_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                astronaut_id TEXT NOT NULL,
                reading_id TEXT NOT NULL REFERENCES health_readings(reading_id),
                rule_id TEXT NOT NULL,
                rule_version INTEGER NOT NULL CHECK (rule_version >= 1),
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT NOT NULL,
                direction TEXT NOT NULL
                    CHECK (direction IN ('below_minimum', 'above_maximum')),
                configured_limit REAL NOT NULL,
                rationale TEXT NOT NULL,
                source_reference TEXT NOT NULL,
                measured_at TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                UNIQUE (reading_id, rule_id, rule_version)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_monitoring_alerts_astronaut_time
            ON monitoring_alerts (astronaut_id, measured_at, id)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS monitoring_alert_acknowledgements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL REFERENCES monitoring_alerts(id),
                actor_id TEXT NOT NULL,
                acknowledged_at TEXT NOT NULL,
                UNIQUE (alert_id, actor_id)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_monitoring_alert_acknowledgements_alert
            ON monitoring_alert_acknowledgements (alert_id, acknowledged_at)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS monitoring_alert_rules (
                mission_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1),
                rule_json TEXT NOT NULL,
                active INTEGER NOT NULL CHECK (active IN (0, 1)),
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (mission_id, rule_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS monitoring_alert_rule_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1),
                action TEXT NOT NULL CHECK (
                    action IN (
                        'provisioned', 'created', 'updated',
                        'reactivated', 'deactivated'
                    )
                ),
                actor_id TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                previous_active INTEGER CHECK (previous_active IN (0, 1)),
                current_active INTEGER NOT NULL CHECK (current_active IN (0, 1)),
                previous_rule_json TEXT,
                current_rule_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_rule_changes_mission_time
            ON monitoring_alert_rule_changes (mission_id, changed_at, id)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS provisioned_mission_delegations (
                mission_id TEXT PRIMARY KEY,
                signed_tokens_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS onboard_refresh_sessions (
                token_sha256 TEXT PRIMARY KEY,
                family_id TEXT NOT NULL,
                mission_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'device')),
                permissions_json TEXT NOT NULL,
                astronaut_ids_json TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                revoked_at TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_onboard_refresh_family
            ON onboard_refresh_sessions (family_id)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS onboard_access_tokens (
                jti TEXT PRIMARY KEY,
                family_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_onboard_access_family
            ON onboard_access_tokens (family_id)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS authentication_challenges (
                challenge_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'device')),
                key_id TEXT NOT NULL,
                nonce_sha256 TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_authentication_challenges_subject
            ON authentication_challenges (mission_id, subject, actor_type, expires_at)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS authentication_challenge_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'device')),
                requested_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_challenge_attempts_identity_time
            ON authentication_challenge_attempts (
                mission_id, subject, actor_type, requested_at
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS nasa_osdr_study_metadata (
                accession TEXT PRIMARY KEY,
                metadata_json TEXT NOT NULL,
                retrieved_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS nasa_osdr_search_cache (
                filter_sha256 TEXT PRIMARY KEY,
                filters_json TEXT NOT NULL,
                results_json TEXT NOT NULL,
                retrieved_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS nasa_osdr_dataset_files (
                accession TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_metadata_json TEXT NOT NULL,
                retrieved_at TEXT NOT NULL,
                PRIMARY KEY (accession, file_name)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS nasa_osdr_dataset_imports (
                import_id TEXT PRIMARY KEY,
                accession TEXT NOT NULL,
                file_name TEXT NOT NULL,
                source_api_url TEXT NOT NULL,
                source_download_url TEXT NOT NULL,
                source_metadata_json TEXT NOT NULL,
                file_sha256 TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL CHECK (file_size_bytes >= 0),
                original_content BLOB NOT NULL,
                record_count INTEGER NOT NULL CHECK (record_count >= 0),
                imported_at TEXT NOT NULL,
                source_file_updated_at TEXT,
                citation TEXT NOT NULL,
                citation_status TEXT NOT NULL CHECK (citation_status = 'not_verified'),
                provenance TEXT NOT NULL CHECK (provenance = 'nasa_osdr'),
                license_status TEXT NOT NULL CHECK (license_status = 'not_verified'),
                parser_version TEXT NOT NULL,
                normalization_status TEXT NOT NULL
                    CHECK (normalization_status = 'not_performed'),
                UNIQUE (accession, file_name, file_sha256)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_nasa_osdr_imports_accession_file
            ON nasa_osdr_dataset_imports (accession, file_name, imported_at)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS nasa_osdr_dataset_import_rows (
                import_id TEXT NOT NULL
                    REFERENCES nasa_osdr_dataset_imports(import_id),
                source_row_number INTEGER NOT NULL CHECK (source_row_number >= 1),
                source_values_json TEXT NOT NULL,
                PRIMARY KEY (import_id, source_row_number)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS nasa_osdr_import_transformations (
                import_id TEXT NOT NULL
                    REFERENCES nasa_osdr_dataset_imports(import_id),
                step_number INTEGER NOT NULL CHECK (step_number >= 1),
                operation TEXT NOT NULL,
                version TEXT NOT NULL,
                details_json TEXT NOT NULL,
                PRIMARY KEY (import_id, step_number)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_sync_batches_device_received
            ON sync_batches (source_device_id, received_at)
            """
        )
