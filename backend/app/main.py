from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import sqlite3
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError

from app.analysis import summarize_readings
from app.auth import (
    CurrentPrincipal,
    require_astronaut_scope,
    require_permission,
)
from app.database import connect_database, get_connection, initialize_database
from app.identity_bootstrap import (
    IdentityBootstrapError,
    MissionIdentityBootstrap,
    load_identity_bootstrap,
)
from app.provisioning import (
    MissionProvisioningError,
    install_mission_delegations,
    load_provisioned_mission_configuration,
)
from app.schemas import (
    METRIC_UNITS,
    TECHNICAL_LIMITS,
    DataOrigin,
    GlucoseContext,
    HealthReading,
    IndicatorCoverage,
    Metric,
    OfflineSyncBatchInput,
    OperationsIndicatorCount,
    ReadingBatchInput,
    ReadingAnalysis,
    ReadingCoverage,
    ReadingHistory,
    ReadingOperationsSummary,
    OriginCount,
    SyncAcknowledgement,
    SyncAcknowledgementItem,
    SyncBatchStatus,
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    initialize_database()
    application.state.identity_bootstrap = None
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
        except MissionProvisioningError as error:
            raise RuntimeError(
                "A delegação provisionada da missão não pôde ser validada."
            ) from error
        finally:
            connection.close()
        application.state.identity_bootstrap = bootstrap
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
        tuple[ReadingBatchInput, UUID | None, dict[UUID, int] | None]
    ],
    sync_batch: tuple[UUID, UUID, str] | None = None,
) -> tuple[list[HealthReading], list[SyncAcknowledgementItem]]:
    records: list[HealthReading] = []
    acknowledgements: list[SyncAcknowledgementItem] = []
    try:
        with connection:
            if sync_batch is not None:
                batch_id, source_device_id, payload_sha256 = sync_batch
                existing_batch = connection.execute(
                    "SELECT * FROM sync_batches WHERE batch_id = ?",
                    (str(batch_id),),
                ).fetchone()
                if existing_batch is not None:
                    if (
                        existing_batch["source_device_id"] != str(source_device_id)
                        or existing_batch["payload_sha256"] != payload_sha256
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
                            for payload, _, _ in reading_batches
                            for _ in payload.measurements
                        ],
                    )
                    if sync_batch is not None:
                        acknowledgements.sort(key=lambda item: item.sequence_number)
                    return records, acknowledgements

                connection.execute(
                    """
                    INSERT INTO sync_batches (
                        batch_id, source_device_id, payload_sha256, received_at, status
                    ) VALUES (?, ?, ?, ?, 'persisted')
                    """,
                    (
                        str(batch_id),
                        str(source_device_id),
                        payload_sha256,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

            for payload, source_device_id, sequences_by_id in reading_batches:
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
                                sequence_number, received_at, declared_origin
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                            ),
                        )
                        row = connection.execute(
                            "SELECT * FROM health_readings WHERE id = ?",
                            (cursor.lastrowid,),
                        ).fetchone()
                        acknowledgement_status = "accepted"
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
    return records, acknowledgements


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}


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
    records, _ = _persist_readings(connection, [(payload, None, None)])
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

    reading_batches = [
        (
            reading,
            payload.source_device_id,
            {
                measurement.reading_id: measurement.sequence_number
                for measurement in reading.measurements
            },
        )
        for reading in payload.readings
    ]
    canonical_payload = json.dumps(
        payload.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    payload_sha256 = hashlib.sha256(canonical_payload).hexdigest()
    _, acknowledgements = _persist_readings(
        connection,
        reading_batches,
        (payload.batch_id, payload.source_device_id, payload_sha256),
    )
    return SyncAcknowledgement(batch_id=payload.batch_id, items=acknowledgements)


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
