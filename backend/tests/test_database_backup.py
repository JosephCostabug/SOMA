import hashlib
import sqlite3

import pytest

from app.backup import DatabaseBackupError, backup_database, restore_database
from app.database import initialize_database


def test_backup_creates_verified_snapshot_without_changing_source(tmp_path):
    source = tmp_path / "source.sqlite3"
    destination = tmp_path / "backup.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute(
            """
            CREATE TABLE child (
                id INTEGER PRIMARY KEY,
                parent_id INTEGER NOT NULL REFERENCES parent(id)
            )
            """
        )
        connection.execute("INSERT INTO parent VALUES (1, 'sample')")
        connection.execute("INSERT INTO child VALUES (1, 1)")

    result = backup_database(source, destination)

    assert result.destination == destination
    assert result.size_bytes > 0
    assert result.integrity_check == "ok"
    with sqlite3.connect(destination) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert backup.execute("PRAGMA foreign_key_check").fetchall() == []
        assert backup.execute("SELECT value FROM parent").fetchone() == ("sample",)
        assert backup.execute("SELECT parent_id FROM child").fetchone() == (1,)
    with sqlite3.connect(source) as original:
        assert original.execute("SELECT COUNT(*) FROM child").fetchone() == (1,)


def test_backup_refuses_to_overwrite_an_existing_destination(tmp_path):
    source = tmp_path / "source.sqlite3"
    destination = tmp_path / "backup.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE readings (value INTEGER)")
    destination.write_bytes(b"existing backup")

    with pytest.raises(DatabaseBackupError, match="já existe"):
        backup_database(source, destination)

    assert destination.read_bytes() == b"existing backup"


def test_backup_refuses_source_as_destination(tmp_path):
    source = tmp_path / "source.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE readings (value INTEGER)")

    with pytest.raises(DatabaseBackupError, match="mesmo ficheiro"):
        backup_database(source, source)


def test_backup_rejects_non_database_file_and_leaves_no_partial_file(tmp_path):
    source = tmp_path / "not-a-database.sqlite3"
    destination = tmp_path / "backup.sqlite3"
    source.write_text("not SQLite", encoding="utf-8")

    with pytest.raises(DatabaseBackupError, match="integridade"):
        backup_database(source, destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".health-backup-*.sqlite3"))


def test_restore_copies_and_verifies_backup_without_overwriting(tmp_path):
    source = tmp_path / "source.sqlite3"
    backup = tmp_path / "backup.sqlite3"
    restored = tmp_path / "restored.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE readings (value INTEGER NOT NULL)")
        connection.execute("INSERT INTO readings VALUES (72)")

    backup_database(source, backup)
    result = restore_database(backup, restored)

    assert result.destination == restored
    assert result.integrity_check == "ok"
    with sqlite3.connect(restored) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM readings").fetchone() == (72,)
    with pytest.raises(DatabaseBackupError, match="já existe"):
        restore_database(backup, restored)


def test_backup_and_restore_preserve_nasa_import_bytes_and_provenance(
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "source.sqlite3"
    backup = tmp_path / "backup.sqlite3"
    restored = tmp_path / "restored.sqlite3"
    original_content = b"sample_code,value\r\nS1,4.2\r\n"
    monkeypatch.setenv("HEALTH_DB_PATH", str(source))
    initialize_database()

    with sqlite3.connect(source) as connection:
        connection.execute(
            """
            INSERT INTO nasa_osdr_dataset_imports (
                import_id, accession, file_name, source_api_url,
                source_download_url, source_metadata_json, file_sha256,
                file_size_bytes, original_content, record_count, imported_at,
                citation, citation_status, provenance, license_status,
                parser_version, normalization_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "import-1",
                "OSD-575",
                "panel.csv",
                "https://visualization.osdr.nasa.gov/api/file/",
                "https://osdr.nasa.gov/file",
                '{"restricted": false}',
                hashlib.sha256(original_content).hexdigest(),
                len(original_content),
                original_content,
                1,
                "2026-01-01T00:00:00+00:00",
                "",
                "not_verified",
                "nasa_osdr",
                "not_verified",
                "csv-raw-v1",
                "not_performed",
            ),
        )
        connection.execute(
            """
            INSERT INTO nasa_osdr_dataset_import_rows (
                import_id, source_row_number, source_values_json
            ) VALUES (?, ?, ?)
            """,
            ("import-1", 1, '{"sample_code":"S1","value":"4.2"}'),
        )
        connection.execute(
            """
            INSERT INTO nasa_osdr_import_transformations (
                import_id, step_number, operation, version, details_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "import-1",
                1,
                "csv_parse_preserving_source_values",
                "csv-raw-v1",
                '{"normalization_status":"not_performed"}',
            ),
        )

    backup_database(source, backup)
    restore_database(backup, restored)

    with sqlite3.connect(restored) as connection:
        imported = connection.execute(
            """
            SELECT original_content, file_sha256, provenance, accession,
                   file_name, normalization_status
            FROM nasa_osdr_dataset_imports
            WHERE import_id = ?
            """,
            ("import-1",),
        ).fetchone()
        source_row = connection.execute(
            """
            SELECT source_row_number, source_values_json
            FROM nasa_osdr_dataset_import_rows
            WHERE import_id = ?
            """,
            ("import-1",),
        ).fetchone()
        transformation = connection.execute(
            """
            SELECT operation, version, details_json
            FROM nasa_osdr_import_transformations
            WHERE import_id = ?
            """,
            ("import-1",),
        ).fetchone()

    assert imported == (
        original_content,
        hashlib.sha256(original_content).hexdigest(),
        "nasa_osdr",
        "OSD-575",
        "panel.csv",
        "not_performed",
    )
    assert source_row == (1, '{"sample_code":"S1","value":"4.2"}')
    assert transformation == (
        "csv_parse_preserving_source_values",
        "csv-raw-v1",
        '{"normalization_status":"not_performed"}',
    )
