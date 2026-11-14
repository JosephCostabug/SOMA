from datetime import datetime, timezone
from enum import StrEnum
from math import isfinite
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Metric(StrEnum):
    SYSTOLIC_BLOOD_PRESSURE = "systolic_blood_pressure"
    DIASTOLIC_BLOOD_PRESSURE = "diastolic_blood_pressure"
    HEART_RATE = "heart_rate"
    BLOOD_GLUCOSE = "blood_glucose"
    BODY_TEMPERATURE = "body_temperature"
    SLEEP_DURATION = "sleep_duration"
    MOOD = "mood"
    BLOOD_OXYGEN = "blood_oxygen"


METRIC_UNITS = {
    Metric.SYSTOLIC_BLOOD_PRESSURE: "mmHg",
    Metric.DIASTOLIC_BLOOD_PRESSURE: "mmHg",
    Metric.HEART_RATE: "bpm",
    Metric.BLOOD_GLUCOSE: "mg/dL",
    Metric.BODY_TEMPERATURE: "°C",
    Metric.SLEEP_DURATION: "hours",
    Metric.MOOD: "1-5",
    Metric.BLOOD_OXYGEN: "%",
}

TECHNICAL_LIMITS = {
    Metric.SYSTOLIC_BLOOD_PRESSURE: (40, 250),
    Metric.DIASTOLIC_BLOOD_PRESSURE: (20, 150),
    Metric.HEART_RATE: (20, 250),
    Metric.BLOOD_GLUCOSE: (0, 600),
    Metric.BODY_TEMPERATURE: (25, 45),
    Metric.SLEEP_DURATION: (0, 24),
    Metric.MOOD: (1, 5),
    Metric.BLOOD_OXYGEN: (0, 100),
}


class GlucoseContext(StrEnum):
    FASTING = "fasting"
    AFTER_MEAL = "after_meal"
    RANDOM = "random"
    UNKNOWN = "unknown"


class DataOrigin(StrEnum):
    NASA = "nasa"
    SIMULATED = "simulated"
    MANUAL = "manual"


class MeasurementInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric: Metric
    value: float
    reading_id: UUID | None = None

    @model_validator(mode="after")
    def validate_technical_value(self) -> "MeasurementInput":
        if not isfinite(self.value):
            raise ValueError("O valor tem de ser um número finito.")

        minimum, maximum = TECHNICAL_LIMITS[self.metric]
        if not minimum <= self.value <= maximum:
            raise ValueError(
                f"{self.metric.value} tem de estar entre {minimum} e {maximum} "
                f"{METRIC_UNITS[self.metric]}."
            )
        if self.metric in {
            Metric.SYSTOLIC_BLOOD_PRESSURE,
            Metric.DIASTOLIC_BLOOD_PRESSURE,
            Metric.HEART_RATE,
            Metric.MOOD,
        } and not self.value.is_integer():
            raise ValueError(f"{self.metric.value} tem de ser um número inteiro.")
        return self


class ReadingBatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    astronaut_id: str = Field(min_length=1, max_length=100)
    measured_at: datetime
    measurements: list[MeasurementInput] = Field(min_length=1)
    glucose_context: GlucoseContext | None = None
    declared_origin: DataOrigin = DataOrigin.MANUAL

    @model_validator(mode="after")
    def validate_reading_batch(self) -> "ReadingBatchInput":
        if self.measured_at.tzinfo is None or self.measured_at.utcoffset() is None:
            raise ValueError("measured_at tem de incluir fuso horário.")
        self.measured_at = self.measured_at.astimezone(timezone.utc)

        metrics = [measurement.metric for measurement in self.measurements]
        if len(metrics) != len(set(metrics)):
            raise ValueError("Cada indicador só pode aparecer uma vez no registo.")

        has_glucose = Metric.BLOOD_GLUCOSE in metrics
        if has_glucose and self.glucose_context is None:
            raise ValueError("glucose_context é obrigatório quando há uma medição de glicemia.")
        if self.glucose_context is not None and not has_glucose:
            raise ValueError("glucose_context só pode ser indicado com glicemia.")

        systolic = Metric.SYSTOLIC_BLOOD_PRESSURE
        diastolic = Metric.DIASTOLIC_BLOOD_PRESSURE
        values = {measurement.metric: measurement.value for measurement in self.measurements}
        if (systolic in values) != (diastolic in values):
            raise ValueError("A pressão arterial requer valores sistólico e diastólico.")
        if systolic in values and values[diastolic] >= values[systolic]:
            raise ValueError("A pressão diastólica tem de ser inferior à sistólica.")
        return self


class OfflineMeasurementInput(MeasurementInput):
    reading_id: UUID
    sequence_number: int = Field(ge=1)


class OfflineReadingInput(ReadingBatchInput):
    measurements: list[OfflineMeasurementInput] = Field(min_length=1)


class OfflineSyncBatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    batch_id: UUID
    source_device_id: UUID
    readings: list[OfflineReadingInput] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_sync_batch(self) -> "OfflineSyncBatchInput":
        if sum(len(reading.measurements) for reading in self.readings) > 100:
            raise ValueError("Um lote pode conter no máximo 100 medições.")

        sequences = [
            measurement.sequence_number
            for reading in self.readings
            for measurement in reading.measurements
        ]
        if len(sequences) != len(set(sequences)):
            raise ValueError("sequence_number tem de ser único dentro do lote.")

        reading_ids = [
            measurement.reading_id
            for reading in self.readings
            for measurement in reading.measurements
        ]
        if len(reading_ids) != len(set(reading_ids)):
            raise ValueError("reading_id tem de ser único dentro do lote.")
        return self


class HealthReading(BaseModel):
    id: int
    reading_id: UUID | None
    astronaut_id: str
    metric: Metric
    value: float
    unit: str
    measured_at: datetime
    received_at: datetime | None = None
    glucose_context: GlucoseContext | None
    declared_origin: DataOrigin
    origin_verification: Literal["unverified_declaration"]
    source_device_id: UUID | None = None
    sequence_number: int | None = None


class ReadingHistory(BaseModel):
    items: list[HealthReading]
    total: int


class ReadingAnalysis(BaseModel):
    astronaut_id: str
    metric: Metric
    unit: str
    glucose_context: GlucoseContext | None
    period_start: datetime
    period_end: datetime
    sample_count: int
    minimum: float
    maximum: float
    mean: float
    median: float
    sample_standard_deviation: float | None
    latest_value: float
    latest_measured_at: datetime
    trend_slope_per_day: float | None
    scope: Literal["descriptive_only"]


class IndicatorCoverage(BaseModel):
    metric: Metric
    unit: str
    sample_count: int
    latest_measured_at: datetime | None


class ReadingCoverage(BaseModel):
    astronaut_id: str
    period_start: datetime
    period_end: datetime
    indicators: list[IndicatorCoverage]
    scope: Literal["observed_counts_only"]


class OriginCount(BaseModel):
    declared_origin: DataOrigin
    record_count: int
    verification: Literal["unverified_declaration"]


class OperationsIndicatorCount(BaseModel):
    metric: Metric
    unit: str
    valid_record_count: int
    latest_received_at: datetime | None


class ReadingOperationsSummary(BaseModel):
    astronaut_id: str
    period_start: datetime
    period_end: datetime
    last_received_at: datetime | None
    valid_record_count: int
    rejected_record_count: int
    duplicate_record_count: int
    conflict_record_count: int
    records_without_receipt_time: int
    origins: list[OriginCount]
    indicators: list[OperationsIndicatorCount]
    scope: Literal["operational_ingestion_summary"]


class SyncAcknowledgementItem(BaseModel):
    reading_id: UUID
    sequence_number: int
    status: Literal["accepted", "already_received"]


class SyncAcknowledgement(BaseModel):
    batch_id: UUID
    items: list[SyncAcknowledgementItem]


class SyncBatchStatus(BaseModel):
    batch_id: UUID
    source_device_id: UUID
    status: Literal["persisted"]
    received_at: datetime
    items: list[SyncAcknowledgementItem]
