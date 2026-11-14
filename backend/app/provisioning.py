import json
import sqlite3
from datetime import datetime, timezone

from app.key_management import (
    MissionIdentityConfigurationError,
    VerificationKeySet,
    load_signed_mission_identity_configuration,
)
from app.mission_identity import MissionIdentityConfiguration


class MissionProvisioningError(RuntimeError):
    pass


def install_mission_delegations(
    connection: sqlite3.Connection,
    *,
    base_configuration: MissionIdentityConfiguration,
    signed_delegation_tokens: tuple[str, ...],
    key_set: VerificationKeySet,
    expected_onboard_service_id: str,
    now: datetime,
) -> MissionIdentityConfiguration:
    """Validate a provisioned bundle before atomically storing its signed tokens."""
    try:
        verified_configuration = load_signed_mission_identity_configuration(
            base_configuration,
            signed_delegation_tokens=signed_delegation_tokens,
            key_set=key_set,
            expected_onboard_service_id=expected_onboard_service_id,
            now=now,
        )
    except MissionIdentityConfigurationError as error:
        raise MissionProvisioningError(
            "A configuração de missão provisionada foi rejeitada."
        ) from error

    tokens_json = json.dumps(
        list(signed_delegation_tokens),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    try:
        with connection:
            connection.execute(
                """
                INSERT INTO provisioned_mission_delegations (
                    mission_id, signed_tokens_json, updated_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(mission_id) DO UPDATE SET
                    signed_tokens_json = excluded.signed_tokens_json,
                    updated_at = excluded.updated_at
                """,
                (
                    base_configuration.mission.mission_id,
                    tokens_json,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    except sqlite3.Error as error:
        raise MissionProvisioningError(
            "Não foi possível persistir a delegação provisionada."
        ) from error

    return verified_configuration


def load_provisioned_mission_configuration(
    connection: sqlite3.Connection,
    *,
    base_configuration: MissionIdentityConfiguration,
    key_set: VerificationKeySet,
    expected_onboard_service_id: str,
    now: datetime,
) -> MissionIdentityConfiguration:
    """Reload and re-verify persisted signed tokens against local trust material."""
    try:
        row = connection.execute(
            """
            SELECT signed_tokens_json
            FROM provisioned_mission_delegations
            WHERE mission_id = ?
            """,
            (base_configuration.mission.mission_id,),
        ).fetchone()
    except sqlite3.Error as error:
        raise MissionProvisioningError(
            "Não foi possível ler a configuração de missão provisionada."
        ) from error

    if row is None:
        raise MissionProvisioningError(
            "Não existe configuração provisionada para esta missão."
        )

    try:
        tokens = json.loads(row[0])
    except (json.JSONDecodeError, TypeError, IndexError, KeyError) as error:
        raise MissionProvisioningError(
            "O armazenamento da configuração provisionada está corrompido."
        ) from error
    if (
        not isinstance(tokens, list)
        or not tokens
        or any(not isinstance(token, str) or not token for token in tokens)
    ):
        raise MissionProvisioningError(
            "O armazenamento da configuração provisionada está corrompido."
        )

    try:
        return load_signed_mission_identity_configuration(
            base_configuration,
            signed_delegation_tokens=tuple(tokens),
            key_set=key_set,
            expected_onboard_service_id=expected_onboard_service_id,
            now=now,
        )
    except MissionIdentityConfigurationError as error:
        raise MissionProvisioningError(
            "A configuração persistida já não é válida para a missão."
        ) from error
