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
                glucose_context TEXT
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
                status TEXT NOT NULL CHECK (status = 'persisted')
            )
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
            CREATE INDEX IF NOT EXISTS idx_sync_batches_device_received
            ON sync_batches (source_device_id, received_at)
            """
        )
