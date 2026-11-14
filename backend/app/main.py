from contextlib import asynccontextmanager
from datetime import datetime, timezone
import sqlite3
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, status

from app.database import get_connection, initialize_database
from app.schemas import (
    METRIC_UNITS,
    TECHNICAL_LIMITS,
    HealthReading,
    Metric,
    OfflineSyncBatchInput,
    ReadingBatchInput,
    ReadingHistory,
    SyncAcknowledgement,
    SyncAcknowledgementItem,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
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
        glucose_context=row["glucose_context"],
        source_device_id=row["source_device_id"],
        sequence_number=row["sequence_number"],
    )


def _persist_readings(
    connection: sqlite3.Connection,
    reading_batches: list[
        tuple[ReadingBatchInput, UUID | None, dict[UUID, int] | None]
    ],
) -> tuple[list[HealthReading], list[SyncAcknowledgementItem]]:
    records: list[HealthReading] = []
    acknowledgements: list[SyncAcknowledgementItem] = []
    try:
        with connection:
            for payload, source_device_id, sequences_by_id in reading_batches:
                measured_at = payload.measured_at.astimezone(timezone.utc).isoformat()
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
                        )
                        if not is_same_reading:
                            raise HTTPException(
                                status_code=status.HTTP_409_CONFLICT,
                                detail="reading_id já existe com conteúdo diferente.",
                            )
                        row = existing
                        acknowledgement_status = "already_received"
                    else:
                        cursor = connection.execute(
                            """
                            INSERT INTO health_readings (
                                astronaut_id, metric, value, unit, measured_at,
                                glucose_context, reading_id, source_device_id,
                                sequence_number
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                            ),
                        )
                        row = connection.execute(
                            "SELECT * FROM health_readings WHERE id = ?",
                            (cursor.lastrowid,),
                        ).fetchone()
                        acknowledgement_status = "accepted"
                    records.append(_serialize_reading(row))
                    if sequence_number is not None:
                        acknowledgements.append(
                            SyncAcknowledgementItem(
                                reading_id=reading_id,
                                sequence_number=sequence_number,
                                status=acknowledgement_status,
                            )
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
def create_readings(payload: ReadingBatchInput, connection: Connection) -> list[HealthReading]:
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
) -> SyncAcknowledgement:
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
    _, acknowledgements = _persist_readings(connection, reading_batches)
    return SyncAcknowledgement(batch_id=payload.batch_id, items=acknowledgements)


@app.get(
    "/api/v1/readings",
    response_model=ReadingHistory,
    tags=["readings"],
)
def get_readings(
    connection: Connection,
    astronaut_id: Annotated[str, Query(min_length=1, max_length=100)],
    metric: Metric | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ReadingHistory:
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
