import argparse
from contextlib import closing
import json
import os
import sqlite3
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.database import database_path


class DatabaseBackupError(RuntimeError):
    pass


@dataclass(frozen=True)
class DatabaseBackupResult:
    destination: Path
    size_bytes: int
    integrity_check: str


def _verify_database(connection: sqlite3.Connection) -> None:
    try:
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
    except sqlite3.DatabaseError as error:
        raise DatabaseBackupError(
            "A base de dados falhou a verificação de integridade."
        ) from error
    if integrity_rows != [("ok",)]:
        raise DatabaseBackupError("A base de dados falhou a verificação de integridade.")
    try:
        foreign_key_violation = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchone()
    except sqlite3.DatabaseError as error:
        raise DatabaseBackupError(
            "A base de dados falhou a verificação de chaves estrangeiras."
        ) from error
    if foreign_key_violation is not None:
        raise DatabaseBackupError("A base de dados contém violações de chaves estrangeiras.")


def _copy_database(source: Path, destination: Path) -> DatabaseBackupResult:
    try:
        source_path = source.resolve(strict=True)
        if not stat.S_ISREG(source_path.stat().st_mode):
            raise DatabaseBackupError("A origem tem de ser um ficheiro SQLite regular.")

        destination_parent = destination.parent.resolve(strict=True)
        if not destination_parent.is_dir():
            raise DatabaseBackupError("A pasta de destino não existe ou não é uma pasta.")
        destination_path = destination_parent / destination.name
        if source_path == destination_path:
            raise DatabaseBackupError("A origem e o destino não podem ser o mesmo ficheiro.")
        if destination.exists():
            raise DatabaseBackupError("O destino já existe; o backup não foi sobrescrito.")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".health-backup-",
            suffix=".sqlite3",
            dir=destination_parent,
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        try:
            if os.name == "posix":
                os.chmod(temporary_path, 0o600)
            with closing(sqlite3.connect(source_path)) as source_connection:
                _verify_database(source_connection)
                with closing(sqlite3.connect(temporary_path)) as backup_connection:
                    source_connection.backup(backup_connection)
                    _verify_database(backup_connection)

            with temporary_path.open("rb+") as backup_file:
                os.fsync(backup_file.fileno())
            try:
                os.link(temporary_path, destination_path)
            except FileExistsError as error:
                raise DatabaseBackupError(
                    "O destino já existe; o backup não foi sobrescrito."
                ) from error
            size_bytes = destination_path.stat().st_size
        finally:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass

        return DatabaseBackupResult(
            destination=destination_path,
            size_bytes=size_bytes,
            integrity_check="ok",
        )
    except DatabaseBackupError:
        raise
    except (OSError, sqlite3.Error) as error:
        raise DatabaseBackupError("Não foi possível copiar e verificar a base SQLite.") from error


def backup_database(source: Path, destination: Path) -> DatabaseBackupResult:
    return _copy_database(source, destination)


def restore_database(source: Path, destination: Path) -> DatabaseBackupResult:
    return _copy_database(source, destination)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cria um backup consistente e verificado da base SQLite."
    )
    parser.add_argument(
        "--source",
        type=Path,
        help="Ficheiro SQLite de origem (predefinição: HEALTH_DB_PATH, só para backup).",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        required=True,
        help="Novo caminho de destino; ficheiros existentes nunca são substituídos.",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Restaura a cópia indicada por --source para um novo ficheiro de destino.",
    )
    arguments = parser.parse_args()
    if arguments.restore and arguments.source is None:
        parser.error("--source é obrigatório para restaurar.")
    try:
        source = arguments.source or database_path()
        operation = restore_database if arguments.restore else backup_database
        result = operation(source, arguments.destination)
    except DatabaseBackupError as error:
        print(str(error), file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "destination": str(result.destination),
                "size_bytes": result.size_bytes,
                "integrity_check": result.integrity_check,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
