import os
import sqlite3
from pathlib import Path
from typing import Iterator


def database_path() -> Path:
    return Path(os.environ.get("HEALTH_DB_PATH", "data/health_monitoring.sqlite3"))


def get_connection() -> Iterator[sqlite3.Connection]:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
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
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_health_readings_reading_id
            ON health_readings (reading_id)
            WHERE reading_id IS NOT NULL
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
