from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
from pathlib import Path as FilePath
from typing import Annotated, Any
from uuid import UUID, uuid4

import jwt
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, Response, status
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from jwt.exceptions import InvalidKeyError, InvalidTokenError

from app.analysis import summarize_readings
from app.auth import (
    CurrentPrincipal,
    require_astronaut_scope,
    require_permission,
)
from app.database import connect_database, get_connection, initialize_database
from app.earth_sync import (
    EarthSyncConfigurationError,
    EarthSyncProtocolError,
    EarthSyncSettings,
    load_earth_sync_settings,
    receive_earth_sync_payload,
)
from app.identity_bootstrap import (
    AuthenticationPublicKey,
    IdentityBootstrapError,
    MissionIdentityBootstrap,
    load_identity_bootstrap,
    read_protected_file,
)
from app.provisioning import (
    MissionProvisioningError,
    install_mission_delegations,
    load_provisioned_mission_configuration,
)
from app.mission_identity import (
    ActorType,
    IdentityState,
    MissionIdentityConfiguration,
    MissionState,
)
from app.nasa_osdr import (
    OSDRDatasetFile,
    OSDRMetadataError,
    OSDRDatasetSearchHit,
    OSDRDatasetSearchResults,
    OSDRStudyMetadata,
    download_osdr_csv,
    fetch_osdr_dataset_file_metadata,
    fetch_osdr_dataset_files,
    fetch_osdr_study_metadata,
    parse_osdr_csv,
    search_osdr_datasets,
)
from app.schemas import (
    METRIC_UNITS,
    TECHNICAL_LIMITS,
    DataOrigin,
    AuthenticationChallenge,
    AuthenticationChallengeRequest,
    AuthenticationRevokeRequest,
    AuthenticationRefreshRequest,
    AuthenticationTokenRequest,
    AuthenticationTokenResponse,
    GlucoseContext,
    HealthReading,
    IndicatorCoverage,
    Metric,
    MonitoringAlert,
    MonitoringAlertAcknowledgement,
    MonitoringAlertHistory,
    MonitoringAlertRule,
    MonitoringAlertRuleAudit,
    MonitoringAlertRuleChange,
    MonitoringAlertRuleHistory,
    MonitoringAlertRuleRecord,
    MonitoringAlertRuleUpdate,
    MonitoringAlertRuleVersion,
    EarthSyncAdmissionAcknowledgement,
    EarthSyncBatchInput,
    EarthSyncDeliveryStatus,
    EarthSyncReceiptResponse,
    OfflineSyncBatchInput,
    OperationsIndicatorCount,
    ReadingBatchInput,
    ReadingAnalysis,
    ReadingCoverage,
    ReadingHistory,
    ReadingOperationsSummary,
    OriginCount,
    OSDRDatasetImport,
    OSDRDatasetImportList,
    OSDRDatasetImportRecord,
    OSDRDatasetImportRecords,
    SyncAcknowledgement,
    SyncAcknowledgementItem,
    SyncBatchStatus,
)
from app.token_service import (
    CredentialIssueError,
    IssuedCredentials,
    OnboardTokenService,
    RefreshTokenError,
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    initialize_database()
    application.state.identity_bootstrap = None
    application.state.onboard_token_service = None
    application.state.auth_challenge_ttl_seconds = None
    application.state.auth_challenge_rate_limit_max_requests = None
    application.state.auth_challenge_rate_limit_window_seconds = None
    application.state.earth_sync_settings = None
    bootstrap_path = os.environ.get("MISSION_BOOTSTRAP_PATH")
    if bootstrap_path:
        try:
            bootstrap = load_identity_bootstrap(bootstrap_path)
        except IdentityBootstrapError as error:
            raise RuntimeError("O bootstrap da identidade da missão foi rejeitado.") from error

        connection = connect_database()
        try:
            existing = connection.execute(
                """
                SELECT 1 FROM provisioned_mission_delegations
                WHERE mission_id = ?
                """,
                (bootstrap.base_configuration.mission.mission_id,),
            ).fetchone()
            if existing is None:
                install_mission_delegations(
                    connection,
                    base_configuration=bootstrap.base_configuration,
                    signed_delegation_tokens=bootstrap.initial_signed_delegation_tokens,
                    key_set=bootstrap.ground_keys,
                    expected_onboard_service_id=bootstrap.onboard_token_verifier.onboard_service_id(
                        bootstrap.base_configuration
                    ),
                    now=datetime.now(timezone.utc),
                )
            load_provisioned_mission_configuration(
                connection,
                base_configuration=bootstrap.base_configuration,
                key_set=bootstrap.ground_keys,
                expected_onboard_service_id=bootstrap.onboard_token_verifier.onboard_service_id(
                    bootstrap.base_configuration
                ),
                now=datetime.now(timezone.utc),
            )
            seed_monitoring_alert_rules(
                connection,
                mission_id=bootstrap.base_configuration.mission.mission_id,
                rules=bootstrap.monitoring_alert_rules,
                now=datetime.now(timezone.utc),
            )
        except MissionProvisioningError as error:
            raise RuntimeError(
                "A delegação provisionada da missão não pôde ser validada."
            ) from error
        finally:
            connection.close()
        application.state.identity_bootstrap = bootstrap
        signing_key_path = os.environ.get("ONBOARD_TOKEN_SIGNING_KEY_PATH")
        if signing_key_path:
            challenge_ttl = os.environ.get("AUTH_CHALLENGE_TTL_SECONDS")
            challenge_rate_limit_max_requests = os.environ.get(
                "AUTH_CHALLENGE_RATE_LIMIT_MAX_REQUESTS"
            )
            challenge_rate_limit_window_seconds = os.environ.get(
                "AUTH_CHALLENGE_RATE_LIMIT_WINDOW_SECONDS"
            )
            try:
                if challenge_ttl is None:
                    raise ValueError("AUTH_CHALLENGE_TTL_SECONDS não foi configurado.")
                if challenge_rate_limit_max_requests is None:
                    raise ValueError(
                        "AUTH_CHALLENGE_RATE_LIMIT_MAX_REQUESTS não foi configurado."
                    )
                if challenge_rate_limit_window_seconds is None:
                    raise ValueError(
                        "AUTH_CHALLENGE_RATE_LIMIT_WINDOW_SECONDS não foi configurado."
                    )
                challenge_ttl_seconds = int(challenge_ttl)
                if not 1 <= challenge_ttl_seconds <= 3600:
                    raise ValueError(
                        "AUTH_CHALLENGE_TTL_SECONDS tem de estar entre 1 e 3600."
                    )
                challenge_rate_limit_max_requests_value = int(
                    challenge_rate_limit_max_requests
                )
                challenge_rate_limit_window_seconds_value = int(
                    challenge_rate_limit_window_seconds
                )
                if (
                    challenge_rate_limit_max_requests_value < 1
                    or challenge_rate_limit_window_seconds_value < 1
                ):
                    raise ValueError(
                        "Os parâmetros de rate limiting têm de ser inteiros positivos."
                    )
                timedelta(seconds=challenge_rate_limit_window_seconds_value)
                private_key_pem = read_protected_file(
                    signing_key_path,
                    max_bytes=16_384,
                    label="chave privada onboard",
                ).decode("ascii")
                application.state.onboard_token_service = OnboardTokenService(
                    private_key_pem=private_key_pem,
                    key_id=bootstrap.onboard_token_verifier.key_id,
                    verifier=bootstrap.onboard_token_verifier,
                )
                application.state.auth_challenge_ttl_seconds = challenge_ttl_seconds
                application.state.auth_challenge_rate_limit_max_requests = (
                    challenge_rate_limit_max_requests_value
                )
                application.state.auth_challenge_rate_limit_window_seconds = (
                    challenge_rate_limit_window_seconds_value
                )
            except (
                IdentityBootstrapError,
                CredentialIssueError,
                UnicodeDecodeError,
                OverflowError,
                ValueError,
            ) as error:
                raise RuntimeError(
                    "A configuração de emissão de credenciais onboard foi rejeitada."
                ) from error
    if os.environ.get("EARTH_SYNC_ROLE"):
        try:
            application.state.earth_sync_settings = load_earth_sync_settings()
            if (
                application.state.earth_sync_settings.role == "earth"
                and os.environ.get("EARTH_SYNC_MTLS_ENFORCED") != "1"
            ):
                raise EarthSyncConfigurationError(
                    "O receptor terrestre tem de ser iniciado pelo runner mTLS."
                )
        except EarthSyncConfigurationError as error:
            raise RuntimeError(
                "A configuração de sincronização bordo-Terra foi rejeitada."
            ) from error
    yield


app = FastAPI(
    title="Monitorização de Saúde Espacial",
    description=(
        "API de registo e consulta de indicadores de saúde. "
        "Os limites são validações técnicas, não critérios clínicos."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

MAX_ACTIVE_MONITORING_ALERT_RULES = 100


def _require_scientific_data_access(
    principal: CurrentPrincipal,
    permission: str,
) -> None:
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="O catálogo científico requer uma identidade de utilizador.",
        )
    require_permission(principal, permission)


def _osdr_search_filter_key(
    organism: str | None,
    spaceflight_phase: str | None,
) -> tuple[dict[str, str], str]:
    filters = {
        key: value.strip()
        for key, value in {
            "organism": organism,
            "spaceflight_phase": spaceflight_phase,
        }.items()
        if value is not None and value.strip()
    }
    if not filters:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Indique organism ou spaceflight_phase para pesquisar o OSDR.",
        )
    serialized = json.dumps(filters, sort_keys=True, separators=(",", ":"))
    return filters, hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _serialize_osdr_import(row: sqlite3.Row) -> OSDRDatasetImport:
    return OSDRDatasetImport(
        import_id=UUID(row["import_id"]),
        accession=row["accession"],
        file_name=row["file_name"],
        file_sha256=row["file_sha256"],
        file_size_bytes=row["file_size_bytes"],
        record_count=row["record_count"],
        imported_at=datetime.fromisoformat(row["imported_at"]),
        source_file_updated_at=(
            datetime.fromisoformat(row["source_file_updated_at"])
            if row["source_file_updated_at"] is not None
            else None
        ),
        source_api_url=row["source_api_url"],
        source_download_url=row["source_download_url"],
        citation=row["citation"],
        citation_status=row["citation_status"],
        provenance=row["provenance"],
        license_status=row["license_status"],
        parser_version=row["parser_version"],
        normalization_status=row["normalization_status"],
    )


def _nasa_import_max_bytes() -> int:
    configured_limit = os.environ.get("NASA_OSDR_IMPORT_MAX_BYTES")
    if configured_limit is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NASA_OSDR_IMPORT_MAX_BYTES tem de ser configurado para importar ficheiros.",
        )
    try:
        limit = int(configured_limit)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NASA_OSDR_IMPORT_MAX_BYTES tem de ser um inteiro positivo.",
        ) from error
    if limit <= 0:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NASA_OSDR_IMPORT_MAX_BYTES tem de ser um inteiro positivo.",
        )
    return limit


@app.exception_handler(RequestValidationError)
async def record_invalid_ingestion(
    request: Request,
    error: RequestValidationError,
):
    if request.url.path in {"/api/v1/readings", "/api/v1/sync/readings"}:
        astronaut_id, declared_origin, record_count = _validation_event_context(
            error.body
        )
        principal = getattr(request.state, "authenticated_principal", None)
        if principal is not None and principal.actor_type in {"user", "device"}:
            if astronaut_id not in principal.astronaut_ids:
                astronaut_id = None
            _record_ingestion_event(
                astronaut_id=astronaut_id,
                declared_origin=declared_origin,
                outcome="rejected",
                record_count=record_count,
            )
    return await request_validation_exception_handler(request, error)


@app.exception_handler(HTTPException)
async def record_ingestion_conflicts(request: Request, error: HTTPException):
    if (
        error.status_code == status.HTTP_409_CONFLICT
        and request.url.path in {"/api/v1/readings", "/api/v1/sync/readings"}
    ):
        _record_ingestion_event(
            astronaut_id=getattr(request.state, "ingestion_astronaut_id", None),
            declared_origin=getattr(request.state, "ingestion_origin", "unknown"),
            outcome="conflict",
            record_count=getattr(request.state, "ingestion_record_count", 1),
        )
    return await http_exception_handler(request, error)


Connection = Annotated[sqlite3.Connection, Depends(get_connection)]


def _require_onboard_token_service(request: Request) -> OnboardTokenService:
    service: OnboardTokenService | None = getattr(
        request.app.state,
        "onboard_token_service",
        None,
    )
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A emissão de credenciais onboard não está configurada.",
        )
    return service


def _load_current_mission_configuration(
    connection: sqlite3.Connection,
    bootstrap: MissionIdentityBootstrap,
    now: datetime,
) -> MissionIdentityConfiguration:
    try:
        return load_provisioned_mission_configuration(
            connection,
            base_configuration=bootstrap.base_configuration,
            key_set=bootstrap.ground_keys,
            expected_onboard_service_id=bootstrap.onboard_token_verifier.onboard_service_id(
                bootstrap.base_configuration
            ),
            now=now,
        )
    except MissionProvisioningError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A configuração de identidade da missão não está válida.",
        ) from error


def _credentials_response(
    credentials: IssuedCredentials,
) -> AuthenticationTokenResponse:
    return AuthenticationTokenResponse(
        access_token=credentials.access_token,
        refresh_token=credentials.refresh_token,
        access_expires_at=credentials.access_expires_at,
        refresh_expires_at=credentials.refresh_expires_at,
    )


def seed_monitoring_alert_rules(
    connection: sqlite3.Connection,
    *,
    mission_id: str,
    rules: tuple[MonitoringAlertRule, ...],
    now: datetime,
) -> None:
    changed_at = now.astimezone(timezone.utc).isoformat()
    with connection:
        for rule in rules:
            serialized_rule = rule.model_dump_json()
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO monitoring_alert_rules (
                    mission_id, rule_id, version, rule_json, active, updated_by,
                    updated_at
                ) VALUES (?, ?, ?, ?, 1, 'mission-bootstrap', ?)
                """,
                (mission_id, rule.rule_id, rule.version, serialized_rule, changed_at),
            )
            if cursor.rowcount == 1:
                connection.execute(
                    """
                    INSERT INTO monitoring_alert_rule_changes (
                        mission_id, rule_id, version, action, actor_id, changed_at,
                        previous_active, current_active, previous_rule_json,
                        current_rule_json
                    ) VALUES (?, ?, ?, 'provisioned', 'mission-bootstrap', ?, NULL, 1,
                              NULL, ?)
                    """,
                    (mission_id, rule.rule_id, rule.version, changed_at, serialized_rule),
                )


def _load_active_monitoring_alert_rules(
    connection: sqlite3.Connection,
    mission_id: str,
) -> tuple[MonitoringAlertRule, ...]:
    try:
        rows = connection.execute(
            """
            SELECT rule_json FROM monitoring_alert_rules
            WHERE mission_id = ? AND active = 1
            ORDER BY rule_id
            """,
            (mission_id,),
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Não foi possível carregar as regras ativas de monitorização.",
        ) from error
    try:
        return tuple(
            MonitoringAlertRule.model_validate_json(row["rule_json"])
            for row in rows
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A configuração persistida de regras de monitorização é inválida.",
        ) from error


def _require_alert_configuration_access(
    principal: CurrentPrincipal,
    request: Request,
) -> str:
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A gestão de regras requer uma identidade de utilizador.",
        )
    require_permission(principal, "alerts:configure")
    bootstrap: MissionIdentityBootstrap | None = getattr(
        request.app.state,
        "identity_bootstrap",
        None,
    )
    if bootstrap is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="O bootstrap da missão não está disponível.",
        )
    mission_astronaut_ids = frozenset().union(
        *(
            identity.astronaut_ids
            for identity in bootstrap.base_configuration.identities
            if identity.actor_type.value in {"user", "device"}
        )
    )
    if not mission_astronaut_ids:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A missão não tem astronautas provisionados para delimitar a configuração.",
        )
    if not mission_astronaut_ids <= principal.astronaut_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A gestão de regras requer escopo sobre todos os astronautas da missão.",
        )
    return bootstrap.base_configuration.mission.mission_id


def _serialize_reading(row: sqlite3.Row) -> HealthReading:
    return HealthReading(
        id=row["id"],
        reading_id=row["reading_id"],
        astronaut_id=row["astronaut_id"],
        metric=row["metric"],
        value=row["value"],
        unit=row["unit"],
        measured_at=datetime.fromisoformat(row["measured_at"]),
        received_at=(
            datetime.fromisoformat(row["received_at"])
            if row["received_at"] is not None
            else None
        ),
        glucose_context=row["glucose_context"],
        declared_origin=row["declared_origin"],
        origin_verification="unverified_declaration",
        source_device_id=row["source_device_id"],
        sequence_number=row["sequence_number"],
    )


def _record_ingestion_event(
    *,
    astronaut_id: str | None,
    declared_origin: str,
    outcome: str,
    record_count: int = 1,
) -> None:
    if declared_origin not in {origin.value for origin in DataOrigin}:
        declared_origin = "unknown"
    connection = connect_database()
    try:
        connection.execute(
            """
            INSERT INTO ingestion_events (
                astronaut_id, declared_origin, outcome, record_count, occurred_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                astronaut_id,
                declared_origin,
                outcome,
                max(record_count, 1),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _validation_event_context(body: Any) -> tuple[str | None, str, int]:
    if not isinstance(body, dict):
        return None, "unknown", 1
    astronaut_id = body.get("astronaut_id")
    origin = body.get("declared_origin", DataOrigin.MANUAL.value)
    record_count = len(body.get("measurements", [])) if isinstance(
        body.get("measurements"), list
    ) else 1
    if astronaut_id is None and isinstance(body.get("readings"), list):
        readings = body["readings"]
        record_count = sum(
            len(reading.get("measurements", []))
            for reading in readings
            if isinstance(reading, dict)
            and isinstance(reading.get("measurements"), list)
        )
        if readings and isinstance(readings[0], dict):
            astronaut_id = readings[0].get("astronaut_id")
            origin = readings[0].get("declared_origin", DataOrigin.MANUAL.value)
    if not isinstance(astronaut_id, str) or not astronaut_id or len(astronaut_id) > 100:
        astronaut_id = None
    if not isinstance(origin, str) or origin not in {item.value for item in DataOrigin}:
        origin = "unknown"
    return astronaut_id, origin, max(record_count, 1)


def _persist_readings(
    connection: sqlite3.Connection,
    reading_batches: list[
        tuple[
            ReadingBatchInput,
            UUID | None,
            dict[UUID, int] | None,
            dict[UUID, bool] | None,
        ]
    ],
    sync_batch: tuple[UUID, UUID, str, int, str | None, str | None] | None = None,
    alert_rules: tuple[MonitoringAlertRule, ...] = (),
) -> tuple[list[HealthReading], list[SyncAcknowledgementItem], UUID | None, str]:
    records: list[HealthReading] = []
    acknowledgements: list[SyncAcknowledgementItem] = []
    outbound_items: list[dict[str, object]] = []
    delivery_batch_id: UUID | None = None
    requested_earth_sync = any(
        eligible
        for _, _, _, eligibility in reading_batches
        for eligible in (eligibility or {}).values()
    )
    earth_delivery_status = (
        "no_new_eligible_items" if requested_earth_sync else "not_requested"
    )
    try:
        with connection:
            if sync_batch is not None:
                (
                    batch_id,
                    source_device_id,
                    payload_sha256,
                    protocol_version,
                    source_service_id,
                    destination_service_id,
                ) = sync_batch
                existing_batch = connection.execute(
                    "SELECT * FROM sync_batches WHERE batch_id = ?",
                    (str(batch_id),),
                ).fetchone()
                if existing_batch is not None:
                    if (
                        existing_batch["source_device_id"] != str(source_device_id)
                        or existing_batch["payload_sha256"] != payload_sha256
                        or existing_batch["protocol_version"] != protocol_version
                    ):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="batch_id já existe com conteúdo diferente.",
                        )
                    rows = connection.execute(
                        """
                        SELECT reading_id, sequence_number, status
                        FROM sync_batch_items
                        WHERE batch_id = ?
                        ORDER BY sequence_number
                        """,
                        (str(batch_id),),
                    ).fetchall()
                    acknowledgements.extend(
                        SyncAcknowledgementItem(
                            reading_id=row["reading_id"],
                            sequence_number=row["sequence_number"],
                            status=row["status"],
                        )
                        for row in rows
                    )
                    received_at = datetime.now(timezone.utc).isoformat()
                    connection.executemany(
                        """
                        INSERT INTO ingestion_events (
                            astronaut_id, declared_origin, outcome, occurred_at
                        ) VALUES (?, ?, 'duplicate', ?)
                        """,
                        [
                            (
                                payload.astronaut_id,
                                payload.declared_origin.value,
                                received_at,
                            )
                            for payload, _, _, _ in reading_batches
                            for _ in payload.measurements
                        ],
                    )
                    if sync_batch is not None:
                        acknowledgements.sort(key=lambda item: item.sequence_number)
                    existing_outbound = connection.execute(
                        """
                        SELECT delivery_batch_id, status
                        FROM earth_outbound_batches
                        WHERE origin_batch_id = ?
                        """,
                        (str(batch_id),),
                    ).fetchone()
                    if existing_outbound is not None:
                        delivery_batch_id = UUID(
                            existing_outbound["delivery_batch_id"]
                        )
                        earth_delivery_status = existing_outbound["status"]
                    return (
                        records,
                        acknowledgements,
                        delivery_batch_id,
                        earth_delivery_status,
                    )

                connection.execute(
                    """
                    INSERT INTO sync_batches (
                        batch_id, source_device_id, payload_sha256, received_at,
                        status, protocol_version
                    ) VALUES (?, ?, ?, ?, 'persisted', ?)
                    """,
                    (
                        str(batch_id),
                        str(source_device_id),
                        payload_sha256,
                        datetime.now(timezone.utc).isoformat(),
                        protocol_version,
                    ),
                )

            for (
                payload,
                source_device_id,
                sequences_by_id,
                eligibility_by_id,
            ) in reading_batches:
                measured_at = payload.measured_at.astimezone(timezone.utc).isoformat()
                received_at = datetime.now(timezone.utc).isoformat()
                for measurement in payload.measurements:
                    reading_id = measurement.reading_id or uuid4()
                    sequence_number = (
                        sequences_by_id.get(reading_id)
                        if sequences_by_id is not None
                        else None
                    )
                    glucose_context = (
                        payload.glucose_context.value
                        if measurement.metric == Metric.BLOOD_GLUCOSE
                        and payload.glucose_context is not None
                        else None
                    )
                    existing = connection.execute(
                        "SELECT * FROM health_readings WHERE reading_id = ?",
                        (str(reading_id),),
                    ).fetchone()
                    if existing is not None:
                        is_same_reading = (
                            existing["astronaut_id"] == payload.astronaut_id
                            and existing["metric"] == measurement.metric.value
                            and existing["value"] == measurement.value
                            and existing["unit"] == METRIC_UNITS[measurement.metric]
                            and existing["measured_at"] == measured_at
                            and existing["glucose_context"] == glucose_context
                            and existing["source_device_id"]
                            == (str(source_device_id) if source_device_id else None)
                            and existing["sequence_number"] == sequence_number
                            and existing["declared_origin"]
                            == payload.declared_origin.value
                        )
                        if not is_same_reading:
                            raise HTTPException(
                                status_code=status.HTTP_409_CONFLICT,
                                detail="reading_id já existe com conteúdo diferente.",
                            )
                        row = existing
                        acknowledgement_status = "already_received"
                        is_new_reading = False
                        connection.execute(
                            """
                            INSERT INTO ingestion_events (
                                astronaut_id, declared_origin, outcome, occurred_at
                            ) VALUES (?, ?, 'duplicate', ?)
                            """,
                            (
                                payload.astronaut_id,
                                payload.declared_origin.value,
                                received_at,
                            ),
                        )
                    else:
                        cursor = connection.execute(
                            """
                            INSERT INTO health_readings (
                                astronaut_id, metric, value, unit, measured_at,
                                glucose_context, reading_id, source_device_id,
                                sequence_number, received_at, declared_origin,
                                earth_sync_eligible
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                payload.astronaut_id,
                                measurement.metric.value,
                                measurement.value,
                                METRIC_UNITS[measurement.metric],
                                measured_at,
                                glucose_context,
                                str(reading_id),
                                str(source_device_id) if source_device_id else None,
                                sequence_number,
                                received_at,
                                payload.declared_origin.value,
                                int(
                                    (eligibility_by_id or {}).get(reading_id, False)
                                ),
                            ),
                        )
                        row = connection.execute(
                            "SELECT * FROM health_readings WHERE id = ?",
                            (cursor.lastrowid,),
                        ).fetchone()
                        acknowledgement_status = "accepted"
                        is_new_reading = True
                    if is_new_reading:
                        if (
                            sync_batch is not None
                            and (eligibility_by_id or {}).get(reading_id, False)
                        ):
                            outbound_items.append(
                                {
                                    "reading_id": str(reading_id),
                                    "astronaut_id": payload.astronaut_id,
                                    "metric": measurement.metric.value,
                                    "value": measurement.value,
                                    "unit": METRIC_UNITS[measurement.metric],
                                    "measured_at": measured_at,
                                    "received_at": received_at,
                                    "glucose_context": glucose_context,
                                    "declared_origin": payload.declared_origin.value,
                                    "source_device_id": str(source_device_id),
                                    "sequence_number": sequence_number,
                                    "origin_batch_id": str(sync_batch[0]),
                                }
                            )
                        for rule in alert_rules:
                            if rule.metric != measurement.metric:
                                continue
                            direction = None
                            configured_limit = None
                            if (
                                rule.minimum_value is not None
                                and measurement.value < rule.minimum_value
                            ):
                                direction = "below_minimum"
                                configured_limit = rule.minimum_value
                            elif (
                                rule.maximum_value is not None
                                and measurement.value > rule.maximum_value
                            ):
                                direction = "above_maximum"
                                configured_limit = rule.maximum_value
                            if direction is not None:
                                try:
                                    connection.execute(
                                        """
                                        INSERT INTO monitoring_alerts (
                                            astronaut_id, reading_id, rule_id, rule_version,
                                            metric, value, unit, direction, configured_limit,
                                            rationale, source_reference, measured_at,
                                            generated_at
                                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                        """,
                                        (
                                            payload.astronaut_id,
                                            str(reading_id),
                                            rule.rule_id,
                                            rule.version,
                                            measurement.metric.value,
                                            measurement.value,
                                            METRIC_UNITS[measurement.metric],
                                            direction,
                                            configured_limit,
                                            rule.rationale,
                                            rule.source_reference,
                                            measured_at,
                                            received_at,
                                        ),
                                    )
                                except sqlite3.IntegrityError as error:
                                    raise sqlite3.OperationalError(
                                        "Não foi possível persistir o alerta de monitorização."
                                    ) from error
                    records.append(_serialize_reading(row))
                    if sequence_number is not None:
                        acknowledgement = SyncAcknowledgementItem(
                            reading_id=reading_id,
                            sequence_number=sequence_number,
                            status=acknowledgement_status,
                        )
                        acknowledgements.append(acknowledgement)
                        if sync_batch is not None:
                            connection.execute(
                                """
                                INSERT INTO sync_batch_items (
                                    batch_id, reading_id, sequence_number, status
                                ) VALUES (?, ?, ?, ?)
                                """,
                                (
                                    str(sync_batch[0]),
                                    str(reading_id),
                                    sequence_number,
                                    acknowledgement_status,
                                ),
                            )
            if outbound_items:
                if (
                    sync_batch is None
                    or source_service_id is None
                    or destination_service_id is None
                ):
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="A identidade e o destino terrestre não estão configurados.",
                    )
                delivery_batch_id = uuid4()
                created_at = datetime.now(timezone.utc).isoformat()
                envelope = {
                    "protocol_version": protocol_version,
                    "delivery_batch_id": str(delivery_batch_id),
                    "origin_batch_id": str(batch_id),
                    "source_service_id": source_service_id,
                    "destination_service_id": destination_service_id,
                    "created_at": created_at,
                    "items": sorted(
                        outbound_items,
                        key=lambda item: (
                            item["source_device_id"],
                            item["sequence_number"],
                            item["reading_id"],
                        ),
                    ),
                }
                payload_json = json.dumps(
                    envelope,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                payload_sha256 = hashlib.sha256(
                    payload_json.encode("utf-8")
                ).hexdigest()
                try:
                    connection.execute(
                        """
                        INSERT INTO earth_outbound_batches (
                            delivery_batch_id, origin_batch_id, source_service_id,
                            destination_service_id, protocol_version, payload_json,
                            payload_sha256, status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                        """,
                        (
                            str(delivery_batch_id),
                            str(batch_id),
                            source_service_id,
                            destination_service_id,
                            protocol_version,
                            payload_json,
                            payload_sha256,
                            created_at,
                        ),
                    )
                    connection.executemany(
                        """
                        INSERT INTO earth_outbound_batch_items (
                            delivery_batch_id, reading_id, origin_batch_id,
                            source_device_id, sequence_number, item_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                str(delivery_batch_id),
                                item["reading_id"],
                                str(batch_id),
                                item["source_device_id"],
                                item["sequence_number"],
                                hashlib.sha256(
                                    json.dumps(
                                        item,
                                        sort_keys=True,
                                        separators=(",", ":"),
                                        ensure_ascii=True,
                                    ).encode("utf-8")
                                ).hexdigest(),
                            )
                            for item in envelope["items"]
                        ],
                    )
                except sqlite3.IntegrityError as error:
                    raise sqlite3.OperationalError(
                        "Não foi possível persistir a outbox terrestre."
                    ) from error
                earth_delivery_status = "pending"
    except sqlite3.IntegrityError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="reading_id ou sequência do dispositivo já foi usado.",
        ) from error
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível guardar os registos de saúde.",
        ) from error
    if sync_batch is not None:
        acknowledgements.sort(key=lambda item: item.sequence_number)
    return records, acknowledgements, delivery_batch_id, earth_delivery_status


@app.get("/", include_in_schema=False)
def frontend() -> FileResponse:
    return FileResponse(FilePath(__file__).parent / "static" / "index.html")


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready", tags=["health"])
def readiness_check(request: Request) -> dict[str, str]:
    earth_sync_settings: EarthSyncSettings | None = getattr(
        request.app.state,
        "earth_sync_settings",
        None,
    )
    if (
        getattr(request.app.state, "identity_bootstrap", None) is None
        and (earth_sync_settings is None or earth_sync_settings.role != "earth")
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="O serviço de identidade da missão não está configurado.",
        )
    connection: sqlite3.Connection | None = None
    try:
        connection = connect_database()
        connection.execute("SELECT 1").fetchone()
        required_tables = {
            "health_readings",
            "provisioned_mission_delegations",
            "onboard_access_tokens",
            "authentication_challenge_attempts",
            "nasa_osdr_study_metadata",
            "nasa_osdr_search_cache",
            "nasa_osdr_dataset_files",
            "nasa_osdr_dataset_imports",
            "nasa_osdr_dataset_import_rows",
            "nasa_osdr_import_transformations",
            "earth_outbound_batches",
            "earth_outbound_batch_items",
            "earth_received_batches",
            "earth_received_items",
            "earth_received_batch_items",
            "earth_sync_conflicts",
        }
        existing_tables = {
            row["name"]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()
        }
        if not required_tables <= existing_tables:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="O esquema operacional da base de dados não está pronto.",
            )
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A base de dados não está disponível.",
        ) from error
    finally:
        if connection is not None:
            connection.close()
    return {"status": "ready"}


@app.get(
    "/api/v1/scientific-data/osdr/studies/{accession}",
    response_model=OSDRStudyMetadata,
    tags=["scientific-data"],
)
def get_osdr_study_metadata(
    accession: Annotated[str, Path(pattern=r"^OSD-[0-9]+$")],
    connection: Connection,
    principal: CurrentPrincipal,
) -> OSDRStudyMetadata:
    _require_scientific_data_access(principal, "scientific-data:read")
    try:
        row = connection.execute(
            """
            SELECT
                metadata.metadata_json,
                EXISTS (
                    SELECT 1
                    FROM nasa_osdr_dataset_imports AS imports
                    WHERE imports.accession = metadata.accession
                ) AS files_downloaded
            FROM nasa_osdr_study_metadata AS metadata
            WHERE metadata.accession = ?
            """,
            (accession,),
        ).fetchone()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar os metadados científicos em cache.",
        ) from error
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Estudo NASA OSDR não encontrado no catálogo local.",
        )
    try:
        metadata = OSDRStudyMetadata.model_validate_json(row["metadata_json"])
        return metadata.model_copy(update={"files_downloaded": bool(row["files_downloaded"])})
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Os metadados científicos em cache são inválidos.",
        ) from error


@app.post(
    "/api/v1/scientific-data/osdr/studies/{accession}/refresh",
    response_model=OSDRStudyMetadata,
    tags=["scientific-data"],
)
def refresh_osdr_study_metadata(
    accession: Annotated[str, Path(pattern=r"^OSD-[0-9]+$")],
    connection: Connection,
    principal: CurrentPrincipal,
) -> OSDRStudyMetadata:
    _require_scientific_data_access(principal, "scientific-data:sync")
    try:
        metadata = fetch_osdr_study_metadata(accession)
    except OSDRMetadataError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Não foi possível atualizar os metadados do NASA OSDR.",
        ) from error

    try:
        with connection:
            has_downloaded_files = connection.execute(
                """
                SELECT EXISTS (
                    SELECT 1 FROM nasa_osdr_dataset_imports
                    WHERE accession = ?
                )
                """,
                (accession,),
            ).fetchone()[0]
            metadata = metadata.model_copy(
                update={"files_downloaded": bool(has_downloaded_files)}
            )
            connection.execute(
                """
                INSERT INTO nasa_osdr_study_metadata (
                    accession, metadata_json, retrieved_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(accession) DO UPDATE SET
                    metadata_json = excluded.metadata_json,
                    retrieved_at = excluded.retrieved_at
                """,
                (
                    metadata.accession,
                    metadata.model_dump_json(),
                    metadata.retrieved_at.isoformat(),
                ),
            )
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível guardar os metadados científicos.",
        ) from error
    return metadata


@app.get(
    "/api/v1/scientific-data/osdr/search",
    response_model=OSDRDatasetSearchResults,
    tags=["scientific-data"],
)
def get_osdr_search_results(
    connection: Connection,
    principal: CurrentPrincipal,
    organism: Annotated[str | None, Query(max_length=200)] = None,
    spaceflight_phase: Annotated[str | None, Query(max_length=200)] = None,
) -> OSDRDatasetSearchResults:
    _require_scientific_data_access(principal, "scientific-data:read")
    filters, filter_sha256 = _osdr_search_filter_key(organism, spaceflight_phase)
    try:
        row = connection.execute(
            """
            SELECT filters_json, results_json, retrieved_at
            FROM nasa_osdr_search_cache
            WHERE filter_sha256 = ?
            """,
            (filter_sha256,),
        ).fetchone()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar a descoberta OSDR em cache.",
        ) from error
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Não há resultados OSDR em cache para estes filtros.",
        )
    try:
        cached_filters = json.loads(row["filters_json"])
        results = json.loads(row["results_json"])
        if cached_filters != filters or not isinstance(results, list):
            raise ValueError("Cache inválida.")
        return OSDRDatasetSearchResults(
            items=tuple(OSDRDatasetSearchHit.model_validate(item) for item in results),
            filters=cached_filters,
            retrieved_at=datetime.fromisoformat(row["retrieved_at"]),
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A descoberta OSDR em cache é inválida.",
        ) from error


@app.post(
    "/api/v1/scientific-data/osdr/search/refresh",
    response_model=OSDRDatasetSearchResults,
    tags=["scientific-data"],
)
def refresh_osdr_search_results(
    connection: Connection,
    principal: CurrentPrincipal,
    organism: Annotated[str | None, Query(max_length=200)] = None,
    spaceflight_phase: Annotated[str | None, Query(max_length=200)] = None,
) -> OSDRDatasetSearchResults:
    _require_scientific_data_access(principal, "scientific-data:sync")
    filters, filter_sha256 = _osdr_search_filter_key(organism, spaceflight_phase)
    try:
        hits = search_osdr_datasets(
            organism=filters.get("organism"),
            spaceflight_phase=filters.get("spaceflight_phase"),
        )
    except OSDRMetadataError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Não foi possível pesquisar o catálogo NASA OSDR.",
        ) from error

    retrieved_at = datetime.now(timezone.utc)
    response = OSDRDatasetSearchResults(
        items=hits,
        filters=filters,
        retrieved_at=retrieved_at,
    )
    try:
        with connection:
            connection.execute(
                """
                INSERT INTO nasa_osdr_search_cache (
                    filter_sha256, filters_json, results_json, retrieved_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(filter_sha256) DO UPDATE SET
                    filters_json = excluded.filters_json,
                    results_json = excluded.results_json,
                    retrieved_at = excluded.retrieved_at
                """,
                (
                    filter_sha256,
                    json.dumps(filters, sort_keys=True, separators=(",", ":")),
                    json.dumps(
                        [item.model_dump(mode="json") for item in hits],
                        separators=(",", ":"),
                    ),
                    retrieved_at.isoformat(),
                ),
            )
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível guardar a descoberta NASA OSDR.",
        ) from error
    return response


@app.get(
    "/api/v1/scientific-data/osdr/studies/{accession}/files",
    response_model=list[OSDRDatasetFile],
    tags=["scientific-data"],
)
def get_osdr_dataset_files(
    accession: Annotated[str, Path(pattern=r"^OSD-[0-9]+$")],
    connection: Connection,
    principal: CurrentPrincipal,
) -> list[OSDRDatasetFile]:
    _require_scientific_data_access(principal, "scientific-data:read")
    try:
        rows = connection.execute(
            """
            SELECT file_metadata_json
            FROM nasa_osdr_dataset_files
            WHERE accession = ?
            ORDER BY file_name
            """,
            (accession,),
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar o inventário OSDR em cache.",
        ) from error
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="O inventário OSDR não foi consultado para este estudo.",
        )
    try:
        return [
            OSDRDatasetFile.model_validate_json(row["file_metadata_json"])
            for row in rows
        ]
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="O inventário OSDR em cache é inválido.",
        ) from error


@app.post(
    "/api/v1/scientific-data/osdr/studies/{accession}/files/refresh",
    response_model=list[OSDRDatasetFile],
    tags=["scientific-data"],
)
def refresh_osdr_dataset_files(
    accession: Annotated[str, Path(pattern=r"^OSD-[0-9]+$")],
    connection: Connection,
    principal: CurrentPrincipal,
) -> list[OSDRDatasetFile]:
    _require_scientific_data_access(principal, "scientific-data:sync")
    try:
        dataset_files = fetch_osdr_dataset_files(accession)
    except OSDRMetadataError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Não foi possível consultar o inventário de ficheiros NASA OSDR.",
        ) from error
    retrieved_at = datetime.now(timezone.utc)
    try:
        with connection:
            connection.execute(
                "DELETE FROM nasa_osdr_dataset_files WHERE accession = ?",
                (accession,),
            )
            connection.executemany(
                """
                INSERT INTO nasa_osdr_dataset_files (
                    accession, file_name, file_metadata_json, retrieved_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(accession, file_name) DO UPDATE SET
                    file_metadata_json = excluded.file_metadata_json,
                    retrieved_at = excluded.retrieved_at
                """,
                [
                    (
                        dataset_file.accession,
                        dataset_file.file_name,
                        dataset_file.model_dump_json(),
                        retrieved_at.isoformat(),
                    )
                    for dataset_file in dataset_files
                ],
            )
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível guardar o inventário de ficheiros NASA OSDR.",
        ) from error
    return list(dataset_files)


@app.post(
    "/api/v1/scientific-data/osdr/studies/{accession}/files/{file_name}/imports",
    response_model=OSDRDatasetImport,
    tags=["scientific-data"],
)
def import_osdr_dataset_file(
    accession: Annotated[str, Path(pattern=r"^OSD-[0-9]+$")],
    file_name: Annotated[str, Path(min_length=1, max_length=255)],
    connection: Connection,
    principal: CurrentPrincipal,
) -> OSDRDatasetImport:
    _require_scientific_data_access(principal, "scientific-data:import")
    max_bytes = _nasa_import_max_bytes()
    try:
        study_metadata = fetch_osdr_study_metadata(accession)
        dataset_file, source_metadata = fetch_osdr_dataset_file_metadata(
            accession,
            file_name,
        )
    except OSDRMetadataError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Não foi possível validar os metadados do ficheiro NASA OSDR.",
        ) from error

    if dataset_file.restricted is not False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A NASA não identificou este ficheiro como publicamente acessível.",
        )
    if dataset_file.file_format != "csv":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Esta etapa só importa ficheiros CSV.",
        )
    if dataset_file.file_size_bytes is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="A NASA não informou o tamanho do ficheiro.",
        )
    if dataset_file.file_size_bytes > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="O ficheiro excede NASA_OSDR_IMPORT_MAX_BYTES.",
        )
    try:
        content = download_osdr_csv(dataset_file, max_bytes=max_bytes)
    except OSDRMetadataError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Não foi possível descarregar o ficheiro NASA OSDR.",
        ) from error
    try:
        source_rows = parse_osdr_csv(content)
    except OSDRMetadataError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="O ficheiro disponibilizado pela NASA não passou a validação CSV.",
        ) from error

    study_metadata = study_metadata.model_copy(update={"files_downloaded": True})
    file_sha256 = hashlib.sha256(content).hexdigest()
    imported_at = datetime.now(timezone.utc)
    try:
        with connection:
            connection.execute(
                """
                INSERT INTO nasa_osdr_study_metadata (
                    accession, metadata_json, retrieved_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(accession) DO UPDATE SET
                    metadata_json = excluded.metadata_json,
                    retrieved_at = excluded.retrieved_at
                """,
                (
                    study_metadata.accession,
                    study_metadata.model_dump_json(),
                    study_metadata.retrieved_at.isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT INTO nasa_osdr_dataset_files (
                    accession, file_name, file_metadata_json, retrieved_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(accession, file_name) DO UPDATE SET
                    file_metadata_json = excluded.file_metadata_json,
                    retrieved_at = excluded.retrieved_at
                """,
                (
                    accession,
                    file_name,
                    dataset_file.model_dump_json(),
                    dataset_file.retrieved_at.isoformat(),
                ),
            )
            existing = connection.execute(
                """
                SELECT * FROM nasa_osdr_dataset_imports
                WHERE accession = ? AND file_name = ? AND file_sha256 = ?
                """,
                (accession, file_name, file_sha256),
            ).fetchone()
            if existing is not None:
                return _serialize_osdr_import(existing)

            import_id = str(uuid4())
            source_metadata_json = json.dumps(
                source_metadata,
                sort_keys=True,
                separators=(",", ":"),
            )
            connection.execute(
                """
                INSERT INTO nasa_osdr_dataset_imports (
                    import_id, accession, file_name, source_api_url,
                    source_download_url, source_metadata_json, file_sha256,
                    file_size_bytes, original_content, record_count, imported_at,
                    source_file_updated_at, citation, citation_status, provenance,
                    license_status, parser_version, normalization_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'not_verified',
                    'nasa_osdr', 'not_verified', 'csv-raw-v1', 'not_performed')
                """,
                (
                    import_id,
                    accession,
                    file_name,
                    dataset_file.source_api_url,
                    dataset_file.download_url,
                    source_metadata_json,
                    file_sha256,
                    len(content),
                    content,
                    len(source_rows),
                    imported_at.isoformat(),
                    (
                        dataset_file.remote_updated_at.isoformat()
                        if dataset_file.remote_updated_at is not None
                        else None
                    ),
                    study_metadata.citation,
                ),
            )
            connection.executemany(
                """
                INSERT INTO nasa_osdr_dataset_import_rows (
                    import_id, source_row_number, source_values_json
                ) VALUES (?, ?, ?)
                """,
                [
                    (
                        import_id,
                        source_row_number,
                        json.dumps(
                            source_values,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                    )
                    for source_row_number, source_values in enumerate(source_rows, 1)
                ],
            )
            connection.execute(
                """
                INSERT INTO nasa_osdr_import_transformations (
                    import_id, step_number, operation, version, details_json
                ) VALUES (?, 1, 'csv_parse_preserving_source_values', '1', ?)
                """,
                (
                    import_id,
                    json.dumps(
                        {
                            "effect": (
                                "Parsed CSV headers and cell text without changing "
                                "values, units, sample identifiers, or study meaning."
                            ),
                            "normalization": "not_performed",
                            "clinical_mapping": "not_performed",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            row = connection.execute(
                "SELECT * FROM nasa_osdr_dataset_imports WHERE import_id = ?",
                (import_id,),
            ).fetchone()
            if row is None:
                raise sqlite3.IntegrityError("O registo de importação não foi persistido.")
            return _serialize_osdr_import(row)
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A importação NASA OSDR não pôde ser persistida atomicamente.",
        ) from error


@app.get(
    "/api/v1/scientific-data/osdr/imports",
    response_model=OSDRDatasetImportList,
    tags=["scientific-data"],
)
def list_osdr_dataset_imports(
    connection: Connection,
    principal: CurrentPrincipal,
    accession: Annotated[str | None, Query(pattern=r"^OSD-[0-9]+$")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> OSDRDatasetImportList:
    _require_scientific_data_access(principal, "scientific-data:read")
    try:
        total = connection.execute(
            """
            SELECT COUNT(*) FROM nasa_osdr_dataset_imports
            WHERE (? IS NULL OR accession = ?)
            """,
            (accession, accession),
        ).fetchone()[0]
        rows = connection.execute(
            """
            SELECT * FROM nasa_osdr_dataset_imports
            WHERE (? IS NULL OR accession = ?)
            ORDER BY imported_at DESC, import_id
            LIMIT ? OFFSET ?
            """,
            (accession, accession, limit, offset),
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar as importações NASA OSDR.",
        ) from error
    return OSDRDatasetImportList(
        items=[_serialize_osdr_import(row) for row in rows],
        total=total,
    )


@app.get(
    "/api/v1/scientific-data/osdr/imports/{import_id}",
    response_model=OSDRDatasetImport,
    tags=["scientific-data"],
)
def get_osdr_dataset_import(
    import_id: UUID,
    connection: Connection,
    principal: CurrentPrincipal,
) -> OSDRDatasetImport:
    _require_scientific_data_access(principal, "scientific-data:read")
    try:
        row = connection.execute(
            "SELECT * FROM nasa_osdr_dataset_imports WHERE import_id = ?",
            (str(import_id),),
        ).fetchone()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar a importação NASA OSDR.",
        ) from error
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="A importação NASA OSDR não foi encontrada.",
        )
    return _serialize_osdr_import(row)


@app.get(
    "/api/v1/scientific-data/osdr/imports/{import_id}/records",
    response_model=OSDRDatasetImportRecords,
    tags=["scientific-data"],
)
def get_osdr_dataset_import_records(
    import_id: UUID,
    connection: Connection,
    principal: CurrentPrincipal,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> OSDRDatasetImportRecords:
    _require_scientific_data_access(principal, "scientific-data:read")
    try:
        dataset_import = connection.execute(
            """
            SELECT accession, file_name, record_count
            FROM nasa_osdr_dataset_imports
            WHERE import_id = ?
            """,
            (str(import_id),),
        ).fetchone()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar os registos da importação NASA OSDR.",
        ) from error
    if dataset_import is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="A importação NASA OSDR não foi encontrada.",
        )
    try:
        rows = connection.execute(
            """
            SELECT source_row_number, source_values_json
            FROM nasa_osdr_dataset_import_rows
            WHERE import_id = ?
            ORDER BY source_row_number
            LIMIT ? OFFSET ?
            """,
            (str(import_id), limit, offset),
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar os registos da importação NASA OSDR.",
        ) from error
    try:
        items = [
            OSDRDatasetImportRecord(
                source_row_number=row["source_row_number"],
                origin="nasa",
                source_values=json.loads(row["source_values_json"]),
            )
            for row in rows
        ]
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Os registos da importação NASA OSDR estão corrompidos.",
        ) from error
    return OSDRDatasetImportRecords(
        import_id=import_id,
        accession=dataset_import["accession"],
        file_name=dataset_import["file_name"],
        offset=offset,
        limit=limit,
        total=dataset_import["record_count"],
        items=items,
    )


@app.post(
    "/api/v1/auth/challenges",
    response_model=AuthenticationChallenge,
    tags=["authentication"],
)
def create_authentication_challenge(
    payload: AuthenticationChallengeRequest,
    connection: Connection,
    request: Request,
) -> AuthenticationChallenge:
    _require_onboard_token_service(request)
    bootstrap: MissionIdentityBootstrap | None = getattr(
        request.app.state,
        "identity_bootstrap",
        None,
    )
    challenge_ttl_seconds: int | None = getattr(
        request.app.state,
        "auth_challenge_ttl_seconds",
        None,
    )
    rate_limit_max_requests: int | None = getattr(
        request.app.state,
        "auth_challenge_rate_limit_max_requests",
        None,
    )
    rate_limit_window_seconds: int | None = getattr(
        request.app.state,
        "auth_challenge_rate_limit_window_seconds",
        None,
    )
    if (
        bootstrap is None
        or challenge_ttl_seconds is None
        or rate_limit_max_requests is None
        or rate_limit_window_seconds is None
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A autenticação offline não está configurada.",
        )

    now = datetime.now(timezone.utc).replace(microsecond=0)
    configuration = _load_current_mission_configuration(connection, bootstrap, now)
    actor_type = ActorType(payload.actor_type)
    identity = next(
        (
            item
            for item in configuration.identities
            if item.identity_id == payload.subject
            and item.actor_type == actor_type
        ),
        None,
    )
    authentication_key: AuthenticationPublicKey | None = next(
        (
            item
            for item in bootstrap.authentication_keys
            if item.identity_id == payload.subject
        ),
        None,
    )
    if (
        identity is None
        or identity.state != IdentityState.ACTIVE
        or not identity.valid_from <= now < identity.expires_at
        or configuration.mission.state != MissionState.ACTIVE
        or not configuration.mission.valid_from <= now < configuration.mission.expires_at
        or authentication_key is None
        or identity.key_id != authentication_key.key_id
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A identidade não pode autenticar neste serviço.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    challenge_id = uuid4()
    nonce = secrets.token_urlsafe(32)
    expires_at = now + timedelta(seconds=challenge_ttl_seconds)
    window_start = now - timedelta(seconds=rate_limit_window_seconds)
    service_id = bootstrap.onboard_token_verifier.onboard_service_id(configuration)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            DELETE FROM authentication_challenge_attempts
            WHERE requested_at <= ?
            """,
            (window_start.isoformat(),),
        )
        attempt_state = connection.execute(
            """
            SELECT COUNT(*) AS attempt_count, MIN(requested_at) AS oldest_attempt
            FROM authentication_challenge_attempts
            WHERE mission_id = ? AND subject = ? AND actor_type = ?
              AND requested_at > ?
            """,
            (
                configuration.mission.mission_id,
                payload.subject,
                payload.actor_type,
                window_start.isoformat(),
            ),
        ).fetchone()
        if attempt_state["attempt_count"] >= rate_limit_max_requests:
            oldest_attempt = datetime.fromisoformat(attempt_state["oldest_attempt"])
            retry_after = max(
                1,
                math.ceil(
                    (
                        oldest_attempt
                        + timedelta(seconds=rate_limit_window_seconds)
                        - now
                    ).total_seconds()
                ),
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Limite de pedidos de desafio excedido para esta identidade.",
                headers={"Retry-After": str(retry_after)},
            )
        connection.execute(
            "DELETE FROM authentication_challenges WHERE expires_at <= ?",
            (now.isoformat(),),
        )
        connection.execute(
            """
            DELETE FROM authentication_challenges
            WHERE mission_id = ? AND subject = ? AND actor_type = ?
            """,
            (configuration.mission.mission_id, payload.subject, payload.actor_type),
        )
        connection.execute(
            """
            INSERT INTO authentication_challenges (
                challenge_id, mission_id, subject, actor_type, key_id,
                nonce_sha256, issued_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(challenge_id),
                configuration.mission.mission_id,
                payload.subject,
                payload.actor_type,
                authentication_key.key_id,
                hashlib.sha256(nonce.encode("ascii")).hexdigest(),
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO authentication_challenge_attempts (
                mission_id, subject, actor_type, requested_at
            ) VALUES (?, ?, ?, ?)
            """,
            (
                configuration.mission.mission_id,
                payload.subject,
                payload.actor_type,
                now.isoformat(),
            ),
        )
        connection.commit()
    except HTTPException:
        connection.rollback()
        raise
    except sqlite3.Error as error:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível criar o desafio de autenticação.",
        ) from error

    return AuthenticationChallenge(
        challenge_id=challenge_id,
        nonce=nonce,
        subject=payload.subject,
        actor_type=payload.actor_type,
        mission_id=configuration.mission.mission_id,
        issuer=service_id,
        key_id=authentication_key.key_id,
        issued_at=now,
        expires_at=expires_at,
    )


@app.post(
    "/api/v1/auth/token",
    response_model=AuthenticationTokenResponse,
    tags=["authentication"],
)
def exchange_authentication_challenge(
    payload: AuthenticationTokenRequest,
    connection: Connection,
    request: Request,
) -> AuthenticationTokenResponse:
    service = _require_onboard_token_service(request)
    bootstrap: MissionIdentityBootstrap | None = getattr(
        request.app.state,
        "identity_bootstrap",
        None,
    )
    if bootstrap is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A autenticação offline não está configurada.",
        )
    now = datetime.now(timezone.utc)
    configuration = _load_current_mission_configuration(connection, bootstrap, now)

    try:
        challenge = connection.execute(
            "SELECT * FROM authentication_challenges WHERE challenge_id = ?",
            (str(payload.challenge_id),),
        ).fetchone()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Não foi possível consultar o desafio de autenticação.",
        ) from error
    if (
        challenge is None
        or challenge["mission_id"] != configuration.mission.mission_id
        or challenge["consumed_at"] is not None
        or datetime.fromisoformat(challenge["expires_at"]) <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="O desafio de autenticação é inválido, expirado ou já foi usado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    identity = next(
        (
            item
            for item in configuration.identities
            if item.identity_id == challenge["subject"]
            and item.actor_type.value == challenge["actor_type"]
        ),
        None,
    )
    authentication_key: AuthenticationPublicKey | None = next(
        (
            item
            for item in bootstrap.authentication_keys
            if item.identity_id == challenge["subject"]
            and item.key_id == challenge["key_id"]
        ),
        None,
    )
    if (
        identity is None
        or identity.state != IdentityState.ACTIVE
        or not identity.valid_from <= now < identity.expires_at
        or authentication_key is None
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A identidade já não pode autenticar neste serviço.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    service_id = bootstrap.onboard_token_verifier.onboard_service_id(configuration)
    try:
        header = jwt.get_unverified_header(payload.proof)
    except (InvalidTokenError, TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A prova de posse da chave é inválida.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    if (
        set(header) != {"alg", "kid", "typ"}
        or header.get("alg") != "RS256"
        or header.get("kid") != challenge["key_id"]
        or header.get("typ") != "onboard-auth+jwt"
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="O cabeçalho da prova de autenticação não é permitido.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = jwt.decode(
            payload.proof,
            authentication_key.public_key_pem,
            algorithms=["RS256"],
            issuer=challenge["subject"],
            audience=service_id,
            options={
                "require": [
                    "iss",
                    "aud",
                    "iat",
                    "exp",
                    "jti",
                    "nonce",
                    "mission_id",
                    "actor_type",
                ]
            },
        )
    except InvalidKeyError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A chave pública de autenticação não está válida.",
        ) from error
    except InvalidTokenError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A prova de posse da chave é inválida ou expirou.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error

    issued_at = datetime.fromisoformat(challenge["issued_at"])
    expires_at = datetime.fromisoformat(challenge["expires_at"])
    nonce = claims.get("nonce")
    if (
        set(claims)
        != {
            "iss",
            "aud",
            "iat",
            "exp",
            "jti",
            "nonce",
            "mission_id",
            "actor_type",
        }
        or claims.get("jti") != str(payload.challenge_id)
        or claims.get("mission_id") != challenge["mission_id"]
        or claims.get("actor_type") != challenge["actor_type"]
        or claims.get("iat") != int(issued_at.timestamp())
        or claims.get("exp") != int(expires_at.timestamp())
        or not isinstance(nonce, str)
        or not hmac.compare_digest(
            hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
            challenge["nonce_sha256"],
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A prova não corresponde ao desafio emitido.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        connection.execute("BEGIN IMMEDIATE")
        consumed = connection.execute(
            """
            UPDATE authentication_challenges
            SET consumed_at = ?
            WHERE challenge_id = ? AND consumed_at IS NULL AND expires_at > ?
            """,
            (now.isoformat(), str(payload.challenge_id), now.isoformat()),
        )
        if consumed.rowcount != 1:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="O desafio de autenticação já foi consumido.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        credentials = service.issue_in_transaction(
            connection,
            configuration=configuration,
            subject=challenge["subject"],
            actor_type=ActorType(challenge["actor_type"]),
            permissions=frozenset(payload.permissions),
            astronaut_ids=frozenset(payload.astronaut_ids),
            access_lifetime_seconds=payload.access_lifetime_seconds,
            now=now,
        )
        connection.commit()
    except HTTPException:
        connection.rollback()
        raise
    except CredentialIssueError as error:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A identidade, as permissões ou os escopos não podem receber estes tokens.",
        ) from error
    except sqlite3.Error as error:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Não foi possível emitir e persistir as credenciais.",
        ) from error
    return _credentials_response(credentials)


@app.post(
    "/api/v1/auth/refresh",
    response_model=AuthenticationTokenResponse,
    tags=["authentication"],
)
def refresh_authentication_tokens(
    payload: AuthenticationRefreshRequest,
    connection: Connection,
    request: Request,
) -> AuthenticationTokenResponse:
    service = _require_onboard_token_service(request)
    bootstrap: MissionIdentityBootstrap | None = getattr(
        request.app.state,
        "identity_bootstrap",
        None,
    )
    if bootstrap is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A autenticação offline não está configurada.",
        )
    now = datetime.now(timezone.utc)
    configuration = _load_current_mission_configuration(connection, bootstrap, now)
    try:
        credentials = service.refresh(
            connection,
            configuration=configuration,
            refresh_token=payload.refresh_token,
            access_lifetime_seconds=payload.access_lifetime_seconds,
            now=now,
        )
    except RefreshTokenError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="O refresh token é inválido, expirado, revogado ou já foi utilizado.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    return _credentials_response(credentials)


@app.post("/api/v1/auth/revoke", tags=["authentication"])
def revoke_authentication_tokens(
    payload: AuthenticationRevokeRequest,
    connection: Connection,
    request: Request,
) -> dict[str, str]:
    service = _require_onboard_token_service(request)
    try:
        service.revoke_family(
            connection,
            refresh_token=payload.refresh_token,
            now=datetime.now(timezone.utc),
        )
    except RefreshTokenError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="O refresh token é inválido ou desconhecido.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    return {"status": "revoked"}


@app.get("/api/v1/indicators", tags=["readings"])
def list_indicators() -> list[dict[str, object]]:
    return [
        {
            "metric": metric.value,
            "unit": METRIC_UNITS[metric],
            "technical_validation_range": TECHNICAL_LIMITS[metric],
        }
        for metric in Metric
    ]


@app.post(
    "/api/v1/readings",
    response_model=list[HealthReading],
    status_code=status.HTTP_201_CREATED,
    tags=["readings"],
)
def create_readings(
    payload: ReadingBatchInput,
    connection: Connection,
    principal: CurrentPrincipal,
    request: Request,
) -> list[HealthReading]:
    request.state.ingestion_astronaut_id = payload.astronaut_id
    request.state.ingestion_origin = payload.declared_origin.value
    request.state.ingestion_record_count = len(payload.measurements)
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint requer uma identidade de utilizador.",
        )
    require_permission(principal, "readings:write")
    require_astronaut_scope(principal, payload.astronaut_id)
    records, _, _, _ = _persist_readings(
        connection,
        [(payload, None, None, None)],
        alert_rules=_load_active_monitoring_alert_rules(
            connection,
            request.app.state.identity_bootstrap.base_configuration.mission.mission_id,
        ),
    )
    return records


@app.post(
    "/api/v1/sync/readings",
    response_model=SyncAcknowledgement,
    tags=["sync"],
)
def sync_readings(
    payload: OfflineSyncBatchInput,
    connection: Connection,
    principal: CurrentPrincipal,
    request: Request,
) -> SyncAcknowledgement:
    acknowledgement, _, _ = _accept_sync_batch(
        payload,
        connection,
        principal,
        request,
        protocol_version=1,
    )
    return acknowledgement


@app.post(
    "/api/v2/sync/readings",
    response_model=EarthSyncAdmissionAcknowledgement,
    tags=["sync"],
)
def sync_readings_v2(
    payload: EarthSyncBatchInput,
    connection: Connection,
    principal: CurrentPrincipal,
    request: Request,
) -> EarthSyncAdmissionAcknowledgement:
    acknowledgement, delivery_batch_id, earth_delivery_status = _accept_sync_batch(
        payload,
        connection,
        principal,
        request,
        protocol_version=2,
    )
    return EarthSyncAdmissionAcknowledgement(
        batch_id=acknowledgement.batch_id,
        items=acknowledgement.items,
        earth_delivery_status=earth_delivery_status,
        delivery_batch_id=delivery_batch_id,
    )


@app.post(
    "/api/v1/sync/earth/batches",
    response_model=EarthSyncReceiptResponse,
    tags=["sync"],
)
def receive_earth_sync_batch(
    payload: dict[str, object],
    connection: Connection,
    request: Request,
    response: Response,
) -> EarthSyncReceiptResponse:
    settings: EarthSyncSettings | None = getattr(
        request.app.state,
        "earth_sync_settings",
        None,
    )
    if settings is None or settings.role != "earth":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="O serviço não está configurado como receptor terrestre.",
        )
    if request.url.scheme != "https":
        raise HTTPException(
            status_code=status.HTTP_426_UPGRADE_REQUIRED,
            detail="O receptor terrestre só aceita transporte HTTPS/mTLS.",
        )
    authorization = request.headers.get("authorization", "")
    scheme, separator, bearer_token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not bearer_token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="É necessário um token de serviço válido.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        receipt = receive_earth_sync_payload(
            connection,
            settings,
            payload=payload,
            bearer_token=bearer_token.strip(),
        )
    except EarthSyncProtocolError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A autenticação ou o contrato do lote bordo-Terra é inválido.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível persistir o lote no sistema terrestre.",
        ) from error
    response.status_code = receipt.http_status
    return EarthSyncReceiptResponse(receipt=receipt.token)


def _accept_sync_batch(
    payload: OfflineSyncBatchInput,
    connection: sqlite3.Connection,
    principal: CurrentPrincipal,
    request: Request,
    *,
    protocol_version: int,
) -> tuple[SyncAcknowledgement, UUID | None, str]:
    request.state.ingestion_astronaut_id = (
        payload.readings[0].astronaut_id if payload.readings else None
    )
    request.state.ingestion_origin = (
        payload.readings[0].declared_origin.value
        if payload.readings
        else "unknown"
    )
    request.state.ingestion_record_count = sum(
        len(reading.measurements) for reading in payload.readings
    )
    if principal.actor_type != "device":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint requer uma identidade de dispositivo.",
        )
    if principal.subject != str(payload.source_device_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="O dispositivo autenticado não corresponde ao lote.",
        )
    require_permission(principal, "sync:write")
    for reading in payload.readings:
        require_astronaut_scope(principal, reading.astronaut_id)

    eligibility_by_reading: list[dict[UUID, bool]] = [
        {
            measurement.reading_id: getattr(
                measurement,
                "earth_sync_eligible",
                False,
            )
            for measurement in reading.measurements
        }
        for reading in payload.readings
    ]
    canonical_payload = json.dumps(
        payload.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    payload_sha256 = hashlib.sha256(canonical_payload).hexdigest()
    earth_sync_requested = any(
        value
        for eligibility in eligibility_by_reading
        for value in eligibility.values()
    )
    source_service_id: str | None = None
    destination_service_id: str | None = None
    if protocol_version >= 2 and earth_sync_requested:
        bootstrap: MissionIdentityBootstrap | None = getattr(
            request.app.state,
            "identity_bootstrap",
            None,
        )
        destination_service_id = os.environ.get("EARTH_SERVICE_ID")
        if (
            bootstrap is None
            or destination_service_id is None
            or not destination_service_id.strip()
            or len(destination_service_id) > 200
        ):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "A identidade do serviço terrestre tem de ser configurada "
                    "antes de aceitar medições elegíveis para envio."
                ),
            )
        source_service_id = (
            bootstrap.onboard_token_verifier.onboard_service_id(
                bootstrap.base_configuration
            )
        )

    _, acknowledgements, delivery_batch_id, earth_delivery_status = _persist_readings(
        connection,
        [
            (
                reading,
                payload.source_device_id,
                {
                    measurement.reading_id: measurement.sequence_number
                    for measurement in reading.measurements
                },
                eligibility,
            )
            for reading, eligibility in zip(
                payload.readings,
                eligibility_by_reading,
                strict=True,
            )
        ],
        (
            payload.batch_id,
            payload.source_device_id,
            payload_sha256,
            protocol_version,
            source_service_id,
            destination_service_id,
        ),
        _load_active_monitoring_alert_rules(
            connection,
            request.app.state.identity_bootstrap.base_configuration.mission.mission_id,
        ),
    )
    return (
        SyncAcknowledgement(batch_id=payload.batch_id, items=acknowledgements),
        delivery_batch_id,
        earth_delivery_status,
    )


def _require_earth_sync_status_access(
    principal: CurrentPrincipal,
    request: Request,
) -> None:
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A consulta da outbox requer uma identidade de utilizador.",
        )
    require_permission(principal, "sync:earth:read")
    bootstrap: MissionIdentityBootstrap | None = getattr(
        request.app.state,
        "identity_bootstrap",
        None,
    )
    if bootstrap is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="O bootstrap da missão não está disponível.",
        )
    mission_astronaut_ids = frozenset().union(
        *(
            identity.astronaut_ids
            for identity in bootstrap.base_configuration.identities
            if identity.actor_type.value in {"user", "device"}
        )
    )
    if not mission_astronaut_ids or not mission_astronaut_ids <= principal.astronaut_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A consulta da outbox requer escopo sobre toda a missão.",
        )


@app.get(
    "/api/v1/sync/earth/outbox/{delivery_batch_id}",
    response_model=EarthSyncDeliveryStatus,
    tags=["sync"],
)
def get_earth_sync_delivery_status(
    delivery_batch_id: UUID,
    connection: Connection,
    principal: CurrentPrincipal,
    request: Request,
) -> EarthSyncDeliveryStatus:
    _require_earth_sync_status_access(principal, request)
    try:
        row = connection.execute(
            """
            SELECT delivery_batch_id, origin_batch_id, source_service_id,
                   destination_service_id, payload_sha256, status, created_at,
                   attempt_count, last_attempt_at, next_attempt_at,
                   acknowledged_at, error_code
            FROM earth_outbound_batches
            WHERE delivery_batch_id = ?
            """,
            (str(delivery_batch_id),),
        ).fetchone()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar o estado da entrega terrestre.",
        ) from error
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lote de saída terrestre não encontrado.",
        )
    return EarthSyncDeliveryStatus(
        delivery_batch_id=row["delivery_batch_id"],
        origin_batch_id=row["origin_batch_id"],
        source_service_id=row["source_service_id"],
        destination_service_id=row["destination_service_id"],
        payload_sha256=row["payload_sha256"],
        status=row["status"],
        created_at=datetime.fromisoformat(row["created_at"]),
        attempt_count=row["attempt_count"],
        last_attempt_at=(
            datetime.fromisoformat(row["last_attempt_at"])
            if row["last_attempt_at"]
            else None
        ),
        next_attempt_at=(
            datetime.fromisoformat(row["next_attempt_at"])
            if row["next_attempt_at"]
            else None
        ),
        acknowledged_at=(
            datetime.fromisoformat(row["acknowledged_at"])
            if row["acknowledged_at"]
            else None
        ),
        error_code=row["error_code"],
    )


@app.get(
    "/api/v1/alerts",
    response_model=MonitoringAlertHistory,
    tags=["alerts"],
)
def get_monitoring_alerts(
    connection: Connection,
    principal: CurrentPrincipal,
    astronaut_id: Annotated[str, Query(min_length=1, max_length=100)],
    start: datetime,
    end: datetime,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> MonitoringAlertHistory:
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint requer uma identidade de utilizador.",
        )
    require_permission(principal, "readings:read")
    require_astronaut_scope(principal, astronaut_id)

    if start.tzinfo is None or start.utcoffset() is None:
        raise HTTPException(status_code=422, detail="start tem de incluir fuso horário.")
    if end.tzinfo is None or end.utcoffset() is None:
        raise HTTPException(status_code=422, detail="end tem de incluir fuso horário.")
    if start > end:
        raise HTTPException(status_code=422, detail="start não pode ser posterior a end.")

    parameters = (
        astronaut_id,
        start.astimezone(timezone.utc).isoformat(),
        end.astimezone(timezone.utc).isoformat(),
    )
    try:
        total = connection.execute(
            """
            SELECT COUNT(*) FROM monitoring_alerts
            WHERE astronaut_id = ? AND measured_at >= ? AND measured_at <= ?
            """,
            parameters,
        ).fetchone()[0]
        rows = connection.execute(
            """
            SELECT alerts.*,
                   COUNT(acknowledgements.id) AS acknowledgement_count,
                   MAX(
                       CASE WHEN acknowledgements.actor_id = ? THEN 1 ELSE 0 END
                   ) AS acknowledged_by_current_user
            FROM monitoring_alerts AS alerts
            LEFT JOIN monitoring_alert_acknowledgements AS acknowledgements
                ON acknowledgements.alert_id = alerts.id
            WHERE alerts.astronaut_id = ?
              AND alerts.measured_at >= ?
              AND alerts.measured_at <= ?
            GROUP BY alerts.id
            ORDER BY alerts.measured_at DESC, alerts.id DESC
            LIMIT ? OFFSET ?
            """,
            (principal.subject, *parameters, limit, offset),
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar os alertas de monitorização.",
        ) from error

    return MonitoringAlertHistory(
        items=[
            MonitoringAlert(
                alert_id=row["id"],
                astronaut_id=row["astronaut_id"],
                reading_id=row["reading_id"],
                rule_id=row["rule_id"],
                rule_version=row["rule_version"],
                metric=row["metric"],
                value=row["value"],
                unit=row["unit"],
                direction=row["direction"],
                configured_limit=row["configured_limit"],
                rationale=row["rationale"],
                source_reference=row["source_reference"],
                measured_at=datetime.fromisoformat(row["measured_at"]),
                generated_at=datetime.fromisoformat(row["generated_at"]),
                acknowledgement_count=row["acknowledgement_count"],
                acknowledged_by_current_user=bool(
                    row["acknowledged_by_current_user"]
                ),
                interpretation="monitoring_support_not_diagnosis",
            )
            for row in rows
        ],
        total=total,
    )


@app.post(
    "/api/v1/alerts/{alert_id}/acknowledge",
    response_model=MonitoringAlertAcknowledgement,
    tags=["alerts"],
)
def acknowledge_monitoring_alert(
    alert_id: Annotated[int, Path(ge=1)],
    connection: Connection,
    principal: CurrentPrincipal,
) -> MonitoringAlertAcknowledgement:
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A confirmação de receção requer uma identidade de utilizador.",
        )
    require_permission(principal, "alerts:acknowledge")
    try:
        connection.execute("BEGIN IMMEDIATE")
        alert = connection.execute(
            "SELECT astronaut_id FROM monitoring_alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if alert is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alerta não encontrado.",
            )
        require_astronaut_scope(principal, alert["astronaut_id"])
        connection.execute(
            """
            INSERT OR IGNORE INTO monitoring_alert_acknowledgements (
                alert_id, actor_id, acknowledged_at
            ) VALUES (?, ?, ?)
            """,
            (
                alert_id,
                principal.subject,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        acknowledgement = connection.execute(
            """
            SELECT id, alert_id, actor_id, acknowledged_at
            FROM monitoring_alert_acknowledgements
            WHERE alert_id = ? AND actor_id = ?
            """,
            (alert_id, principal.subject),
        ).fetchone()
        connection.commit()
    except HTTPException:
        connection.rollback()
        raise
    except sqlite3.Error as error:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível registar a confirmação de receção do alerta.",
        ) from error
    if acknowledgement is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A confirmação de receção não ficou persistida.",
        )
    return MonitoringAlertAcknowledgement(
        acknowledgement_id=acknowledgement["id"],
        alert_id=acknowledgement["alert_id"],
        actor_id=acknowledgement["actor_id"],
        acknowledged_at=datetime.fromisoformat(acknowledgement["acknowledged_at"]),
        status="acknowledged",
    )


@app.get(
    "/api/v1/alerts/rules",
    response_model=MonitoringAlertRuleHistory,
    tags=["alerts"],
)
def list_monitoring_alert_rules(
    connection: Connection,
    principal: CurrentPrincipal,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> MonitoringAlertRuleHistory:
    mission_id = _require_alert_configuration_access(principal, request)
    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM monitoring_alert_rules WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()[0]
        rows = connection.execute(
            """
            SELECT rule_json, active, updated_by, updated_at
            FROM monitoring_alert_rules
            WHERE mission_id = ?
            ORDER BY rule_id
            LIMIT ? OFFSET ?
            """,
            (mission_id, limit, offset),
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar a configuração de regras.",
        ) from error
    try:
        return MonitoringAlertRuleHistory(
            items=[
                MonitoringAlertRuleRecord(
                    rule=MonitoringAlertRule.model_validate_json(row["rule_json"]),
                    active=bool(row["active"]),
                    updated_by=row["updated_by"],
                    updated_at=datetime.fromisoformat(row["updated_at"]),
                )
                for row in rows
            ],
            total=total,
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A configuração persistida de regras contém dados inválidos.",
        ) from error


@app.put(
    "/api/v1/alerts/rules/{rule_id}",
    response_model=MonitoringAlertRuleRecord,
    tags=["alerts"],
)
def upsert_monitoring_alert_rule(
    payload: MonitoringAlertRuleUpdate,
    rule_id: Annotated[str, Path(min_length=1, max_length=100)],
    connection: Connection,
    principal: CurrentPrincipal,
    request: Request,
) -> MonitoringAlertRuleRecord:
    mission_id = _require_alert_configuration_access(principal, request)
    if not rule_id.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="rule_id não pode estar vazio.",
        )
    changed_at = datetime.now(timezone.utc)
    changed_at_iso = changed_at.isoformat()
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            """
            SELECT version, rule_json, active
            FROM monitoring_alert_rules
            WHERE mission_id = ? AND rule_id = ?
            """,
            (mission_id, rule_id),
        ).fetchone()
        if existing is None:
            if payload.expected_version != 0:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A regra não existe; expected_version tem de ser 0.",
                )
            next_version = 1
            action = "created"
            previous_rule_json = None
            previous_active = None
        else:
            if payload.expected_version != existing["version"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A versão da regra mudou; consulte a configuração atual.",
                )
            next_version = existing["version"] + 1
            previous_rule_json = existing["rule_json"]
            previous_active = existing["active"]
            action = "reactivated" if not existing["active"] else "updated"

        if existing is None or not existing["active"]:
            active_count = connection.execute(
                """
                SELECT COUNT(*) FROM monitoring_alert_rules
                WHERE mission_id = ? AND active = 1
                """,
                (mission_id,),
            ).fetchone()[0]
            if active_count >= MAX_ACTIVE_MONITORING_ALERT_RULES:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A missão já atingiu o máximo de regras ativas.",
                )

        updated_rule = MonitoringAlertRule(
            rule_id=rule_id,
            version=next_version,
            metric=payload.metric,
            minimum_value=payload.minimum_value,
            maximum_value=payload.maximum_value,
            rationale=payload.rationale,
            source_reference=payload.source_reference,
        )
        current_rule_json = updated_rule.model_dump_json()
        connection.execute(
            """
            INSERT INTO monitoring_alert_rules (
                mission_id, rule_id, version, rule_json, active, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT (mission_id, rule_id) DO UPDATE SET
                version = excluded.version,
                rule_json = excluded.rule_json,
                active = 1,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            """,
            (
                mission_id,
                rule_id,
                next_version,
                current_rule_json,
                principal.subject,
                changed_at_iso,
            ),
        )
        connection.execute(
            """
            INSERT INTO monitoring_alert_rule_changes (
                mission_id, rule_id, version, action, actor_id, changed_at,
                previous_active, current_active, previous_rule_json,
                current_rule_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                mission_id,
                rule_id,
                next_version,
                action,
                principal.subject,
                changed_at_iso,
                previous_active,
                previous_rule_json,
                current_rule_json,
            ),
        )
        connection.commit()
    except HTTPException:
        connection.rollback()
        raise
    except sqlite3.Error as error:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível guardar a versão da regra de monitorização.",
        ) from error
    return MonitoringAlertRuleRecord(
        rule=updated_rule,
        active=True,
        updated_by=principal.subject,
        updated_at=changed_at,
    )


@app.post(
    "/api/v1/alerts/rules/{rule_id}/deactivate",
    response_model=MonitoringAlertRuleRecord,
    tags=["alerts"],
)
def deactivate_monitoring_alert_rule(
    payload: MonitoringAlertRuleVersion,
    rule_id: Annotated[str, Path(min_length=1, max_length=100)],
    connection: Connection,
    principal: CurrentPrincipal,
    request: Request,
) -> MonitoringAlertRuleRecord:
    mission_id = _require_alert_configuration_access(principal, request)
    changed_at = datetime.now(timezone.utc)
    changed_at_iso = changed_at.isoformat()
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            """
            SELECT version, rule_json, active
            FROM monitoring_alert_rules
            WHERE mission_id = ? AND rule_id = ?
            """,
            (mission_id, rule_id),
        ).fetchone()
        if existing is None or not existing["active"]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Regra ativa não encontrada.",
            )
        if payload.expected_version != existing["version"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A versão da regra mudou; consulte a configuração atual.",
            )

        previous_rule = MonitoringAlertRule.model_validate_json(existing["rule_json"])
        deactivated_rule = previous_rule.model_copy(
            update={"version": existing["version"] + 1}
        )
        current_rule_json = deactivated_rule.model_dump_json()
        connection.execute(
            """
            UPDATE monitoring_alert_rules
            SET version = ?, rule_json = ?, active = 0, updated_by = ?, updated_at = ?
            WHERE mission_id = ? AND rule_id = ? AND version = ? AND active = 1
            """,
            (
                deactivated_rule.version,
                current_rule_json,
                principal.subject,
                changed_at_iso,
                mission_id,
                rule_id,
                existing["version"],
            ),
        )
        connection.execute(
            """
            INSERT INTO monitoring_alert_rule_changes (
                mission_id, rule_id, version, action, actor_id, changed_at,
                previous_active, current_active, previous_rule_json,
                current_rule_json
            ) VALUES (?, ?, ?, 'deactivated', ?, ?, 1, 0, ?, ?)
            """,
            (
                mission_id,
                rule_id,
                deactivated_rule.version,
                principal.subject,
                changed_at_iso,
                existing["rule_json"],
                current_rule_json,
            ),
        )
        connection.commit()
    except HTTPException:
        connection.rollback()
        raise
    except (sqlite3.Error, ValueError) as error:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível desativar a regra de monitorização.",
        ) from error
    return MonitoringAlertRuleRecord(
        rule=deactivated_rule,
        active=False,
        updated_by=principal.subject,
        updated_at=changed_at,
    )


@app.get(
    "/api/v1/alerts/rules/audit",
    response_model=MonitoringAlertRuleAudit,
    tags=["alerts"],
)
def get_monitoring_alert_rule_audit(
    connection: Connection,
    principal: CurrentPrincipal,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> MonitoringAlertRuleAudit:
    mission_id = _require_alert_configuration_access(principal, request)
    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM monitoring_alert_rule_changes WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()[0]
        rows = connection.execute(
            """
            SELECT * FROM monitoring_alert_rule_changes
            WHERE mission_id = ?
            ORDER BY changed_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (mission_id, limit, offset),
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar a auditoria das regras.",
        ) from error
    try:
        return MonitoringAlertRuleAudit(
            items=[
                MonitoringAlertRuleChange(
                    change_id=row["id"],
                    mission_id=row["mission_id"],
                    rule_id=row["rule_id"],
                    version=row["version"],
                    action=row["action"],
                    actor_id=row["actor_id"],
                    changed_at=datetime.fromisoformat(row["changed_at"]),
                    previous_active=(
                        bool(row["previous_active"])
                        if row["previous_active"] is not None
                        else None
                    ),
                    current_active=bool(row["current_active"]),
                    previous_rule=(
                        MonitoringAlertRule.model_validate_json(
                            row["previous_rule_json"]
                        )
                        if row["previous_rule_json"] is not None
                        else None
                    ),
                    current_rule=MonitoringAlertRule.model_validate_json(
                        row["current_rule_json"]
                    ),
                )
                for row in rows
            ],
            total=total,
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A auditoria das regras contém dados inválidos.",
        ) from error


@app.get(
    "/api/v1/sync/batches/{batch_id}",
    response_model=SyncBatchStatus,
    tags=["sync"],
)
def get_sync_batch_status(
    batch_id: UUID,
    connection: Connection,
    principal: CurrentPrincipal,
) -> SyncBatchStatus:
    if principal.actor_type != "device":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint requer uma identidade de dispositivo.",
        )
    require_permission(principal, "sync:write")

    try:
        batch = connection.execute(
            "SELECT * FROM sync_batches WHERE batch_id = ?",
            (str(batch_id),),
        ).fetchone()
        if batch is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Lote de sincronização não encontrado.",
            )
        if batch["source_device_id"] != principal.subject:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="O lote pertence a outro dispositivo.",
            )
        rows = connection.execute(
            """
            SELECT reading_id, sequence_number, status
            FROM sync_batch_items
            WHERE batch_id = ?
            ORDER BY sequence_number
            """,
            (str(batch_id),),
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar o estado da sincronização.",
        ) from error

    return SyncBatchStatus(
        batch_id=batch["batch_id"],
        source_device_id=batch["source_device_id"],
        status=batch["status"],
        received_at=datetime.fromisoformat(batch["received_at"]),
        items=[
            SyncAcknowledgementItem(
                reading_id=row["reading_id"],
                sequence_number=row["sequence_number"],
                status=row["status"],
            )
            for row in rows
        ],
    )


@app.get(
    "/api/v1/readings",
    response_model=ReadingHistory,
    tags=["readings"],
)
def get_readings(
    connection: Connection,
    principal: CurrentPrincipal,
    astronaut_id: Annotated[str, Query(min_length=1, max_length=100)],
    metric: Metric | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ReadingHistory:
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint requer uma identidade de utilizador.",
        )
    require_permission(principal, "readings:read")
    require_astronaut_scope(principal, astronaut_id)

    if start is not None and (start.tzinfo is None or start.utcoffset() is None):
        raise HTTPException(status_code=422, detail="start tem de incluir fuso horário.")
    if end is not None and (end.tzinfo is None or end.utcoffset() is None):
        raise HTTPException(status_code=422, detail="end tem de incluir fuso horário.")
    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=422, detail="start não pode ser posterior a end.")

    conditions = ["astronaut_id = ?"]
    parameters: list[object] = [astronaut_id]
    if metric is not None:
        conditions.append("metric = ?")
        parameters.append(metric.value)
    if start is not None:
        conditions.append("measured_at >= ?")
        parameters.append(start.astimezone(timezone.utc).isoformat())
    if end is not None:
        conditions.append("measured_at <= ?")
        parameters.append(end.astimezone(timezone.utc).isoformat())
    where_clause = " AND ".join(conditions)

    try:
        total = connection.execute(
            f"SELECT COUNT(*) FROM health_readings WHERE {where_clause}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT * FROM health_readings
            WHERE {where_clause}
            ORDER BY measured_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*parameters, limit, offset],
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar o histórico de saúde.",
        ) from error

    return ReadingHistory(items=[_serialize_reading(row) for row in rows], total=total)


@app.get(
    "/api/v1/readings/analysis",
    response_model=ReadingAnalysis,
    tags=["readings"],
)
def analyze_readings(
    connection: Connection,
    principal: CurrentPrincipal,
    astronaut_id: Annotated[str, Query(min_length=1, max_length=100)],
    metric: Metric,
    start: datetime,
    end: datetime,
    glucose_context: GlucoseContext | None = None,
) -> ReadingAnalysis:
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint requer uma identidade de utilizador.",
        )
    require_permission(principal, "readings:read")
    require_astronaut_scope(principal, astronaut_id)

    if start.tzinfo is None or start.utcoffset() is None:
        raise HTTPException(status_code=422, detail="start tem de incluir fuso horário.")
    if end.tzinfo is None or end.utcoffset() is None:
        raise HTTPException(status_code=422, detail="end tem de incluir fuso horário.")
    if start > end:
        raise HTTPException(status_code=422, detail="start não pode ser posterior a end.")
    if metric == Metric.BLOOD_GLUCOSE and glucose_context is None:
        raise HTTPException(
            status_code=422,
            detail="glucose_context é obrigatório para analisar glicemia.",
        )
    if metric != Metric.BLOOD_GLUCOSE and glucose_context is not None:
        raise HTTPException(
            status_code=422,
            detail="glucose_context só pode ser usado na análise de glicemia.",
        )

    conditions = [
        "astronaut_id = ?",
        "metric = ?",
        "measured_at >= ?",
        "measured_at <= ?",
    ]
    parameters: list[object] = [
        astronaut_id,
        metric.value,
        start.astimezone(timezone.utc).isoformat(),
        end.astimezone(timezone.utc).isoformat(),
    ]
    if glucose_context is not None:
        conditions.append("glucose_context = ?")
        parameters.append(glucose_context.value)

    try:
        rows = connection.execute(
            f"""
            SELECT value, measured_at
            FROM health_readings
            WHERE {" AND ".join(conditions)}
            ORDER BY measured_at, id
            """,
            parameters,
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar os dados para análise.",
        ) from error

    if not rows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Não existem medições no período e contexto solicitados.",
        )

    try:
        return summarize_readings(
            [dict(row) for row in rows],
            astronaut_id=astronaut_id,
            metric=metric,
            glucose_context=glucose_context,
            period_start=start.astimezone(timezone.utc),
            period_end=end.astimezone(timezone.utc),
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Os dados persistidos não podem ser analisados com segurança.",
        ) from error


@app.get(
    "/api/v1/readings/coverage",
    response_model=ReadingCoverage,
    tags=["readings"],
)
def get_reading_coverage(
    connection: Connection,
    principal: CurrentPrincipal,
    astronaut_id: Annotated[str, Query(min_length=1, max_length=100)],
    start: datetime,
    end: datetime,
) -> ReadingCoverage:
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint requer uma identidade de utilizador.",
        )
    require_permission(principal, "readings:read")
    require_astronaut_scope(principal, astronaut_id)

    if start.tzinfo is None or start.utcoffset() is None:
        raise HTTPException(status_code=422, detail="start tem de incluir fuso horário.")
    if end.tzinfo is None or end.utcoffset() is None:
        raise HTTPException(status_code=422, detail="end tem de incluir fuso horário.")
    if start > end:
        raise HTTPException(status_code=422, detail="start não pode ser posterior a end.")

    try:
        rows = connection.execute(
            """
            SELECT metric, COUNT(*) AS sample_count, MAX(measured_at) AS latest_measured_at
            FROM health_readings
            WHERE astronaut_id = ? AND measured_at >= ? AND measured_at <= ?
            GROUP BY metric
            """,
            (
                astronaut_id,
                start.astimezone(timezone.utc).isoformat(),
                end.astimezone(timezone.utc).isoformat(),
            ),
        ).fetchall()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível consultar a cobertura dos indicadores.",
        ) from error

    observed: dict[Metric, tuple[int, datetime | None]] = {}
    try:
        for row in rows:
            metric = Metric(row["metric"])
            latest_measured_at = (
                datetime.fromisoformat(row["latest_measured_at"])
                if row["latest_measured_at"] is not None
                else None
            )
            observed[metric] = (row["sample_count"], latest_measured_at)
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Os dados persistidos contêm um indicador ou instante inválido.",
        ) from error

    return ReadingCoverage(
        astronaut_id=astronaut_id,
        period_start=start.astimezone(timezone.utc),
        period_end=end.astimezone(timezone.utc),
        indicators=[
            IndicatorCoverage(
                metric=metric,
                unit=METRIC_UNITS[metric],
                sample_count=observed[metric][0] if metric in observed else 0,
                latest_measured_at=observed[metric][1] if metric in observed else None,
            )
            for metric in Metric
        ],
        scope="observed_counts_only",
    )


@app.get(
    "/api/v1/readings/operations-summary",
    response_model=ReadingOperationsSummary,
    tags=["readings"],
)
def get_reading_operations_summary(
    connection: Connection,
    principal: CurrentPrincipal,
    astronaut_id: Annotated[str, Query(min_length=1, max_length=100)],
    start: datetime,
    end: datetime,
) -> ReadingOperationsSummary:
    if principal.actor_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint requer uma identidade de utilizador.",
        )
    require_permission(principal, "readings:read")
    require_astronaut_scope(principal, astronaut_id)

    if start.tzinfo is None or start.utcoffset() is None:
        raise HTTPException(status_code=422, detail="start tem de incluir fuso horário.")
    if end.tzinfo is None or end.utcoffset() is None:
        raise HTTPException(status_code=422, detail="end tem de incluir fuso horário.")
    if start > end:
        raise HTTPException(status_code=422, detail="start não pode ser posterior a end.")

    period_start = start.astimezone(timezone.utc)
    period_end = end.astimezone(timezone.utc)
    start_iso = period_start.isoformat()
    end_iso = period_end.isoformat()
    try:
        by_origin_rows = connection.execute(
            """
            SELECT declared_origin, COUNT(*) AS record_count,
                   MAX(received_at) AS latest_received_at
            FROM health_readings
            WHERE astronaut_id = ? AND received_at >= ? AND received_at <= ?
            GROUP BY declared_origin
            """,
            (astronaut_id, start_iso, end_iso),
        ).fetchall()
        indicator_rows = connection.execute(
            """
            SELECT metric, COUNT(*) AS record_count,
                   MAX(received_at) AS latest_received_at
            FROM health_readings
            WHERE astronaut_id = ? AND received_at >= ? AND received_at <= ?
            GROUP BY metric
            """,
            (astronaut_id, start_iso, end_iso),
        ).fetchall()
        event_rows = connection.execute(
            """
            SELECT outcome, SUM(record_count) AS record_count
            FROM ingestion_events
            WHERE astronaut_id = ? AND occurred_at >= ? AND occurred_at <= ?
            GROUP BY outcome
            """,
            (astronaut_id, start_iso, end_iso),
        ).fetchall()
        last_received_row = connection.execute(
            """
            SELECT MAX(received_at)
            FROM health_readings
            WHERE astronaut_id = ? AND received_at >= ? AND received_at <= ?
            """,
            (astronaut_id, start_iso, end_iso),
        ).fetchone()
        legacy_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM health_readings
            WHERE astronaut_id = ? AND received_at IS NULL
            """,
            (astronaut_id,),
        ).fetchone()[0]
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível compor o resumo operacional de ingestão.",
        ) from error

    by_origin: dict[str, int] = {}
    try:
        for row in by_origin_rows:
            origin = DataOrigin(row["declared_origin"])
            by_origin[origin.value] = row["record_count"]
        by_metric = {
            Metric(row["metric"]): (
                row["record_count"],
                datetime.fromisoformat(row["latest_received_at"])
                if row["latest_received_at"] is not None
                else None,
            )
            for row in indicator_rows
        }
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Os dados persistidos contêm origem, indicador ou instante inválido.",
        ) from error

    events = {row["outcome"]: row["record_count"] for row in event_rows}
    latest_received = last_received_row[0]
    return ReadingOperationsSummary(
        astronaut_id=astronaut_id,
        period_start=period_start,
        period_end=period_end,
        last_received_at=(
            datetime.fromisoformat(latest_received) if latest_received else None
        ),
        valid_record_count=sum(by_origin.values()),
        rejected_record_count=events.get("rejected", 0),
        duplicate_record_count=events.get("duplicate", 0),
        conflict_record_count=events.get("conflict", 0),
        records_without_receipt_time=legacy_count,
        origins=[
            OriginCount(
                declared_origin=origin,
                record_count=by_origin.get(origin.value, 0),
                verification="unverified_declaration",
            )
            for origin in DataOrigin
        ],
        indicators=[
            OperationsIndicatorCount(
                metric=metric,
                unit=METRIC_UNITS[metric],
                valid_record_count=by_metric[metric][0] if metric in by_metric else 0,
                latest_received_at=by_metric[metric][1] if metric in by_metric else None,
            )
            for metric in Metric
        ],
        scope="operational_ingestion_summary",
    )
