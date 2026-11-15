from datetime import datetime, timezone
from enum import StrEnum
from math import isfinite
from typing import Literal, Self
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


class OSDRDatasetImport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    import_id: UUID
    accession: str
    file_name: str
    file_sha256: str
    file_size_bytes: int
    record_count: int
    imported_at: datetime
    source_file_updated_at: datetime | None
    source_api_url: str
    source_download_url: str
    citation: str
    citation_status: Literal["not_verified"]
    provenance: Literal["nasa_osdr"]
    license_status: Literal["not_verified"]
    parser_version: str
    normalization_status: Literal["not_performed"]


class OSDRDatasetImportRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_row_number: int
    origin: Literal["nasa"]
    source_values: dict[str, str | None]


class OSDRDatasetImportRecords(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    import_id: UUID
    accession: str
    file_name: str
    offset: int
    limit: int
    total: int
    items: list[OSDRDatasetImportRecord]


class OSDRDatasetImportList(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: list[OSDRDatasetImport]
    total: int


class AuthenticationChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=200)
    actor_type: Literal["user", "device"]


class AuthenticationChallenge(BaseModel):
    challenge_id: UUID
    nonce: str
    subject: str
    actor_type: Literal["user", "device"]
    mission_id: str
    issuer: str
    key_id: str
    issued_at: datetime
    expires_at: datetime


class AuthenticationTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: UUID
    proof: str = Field(min_length=1, max_length=16384)
    permissions: list[str] = Field(min_length=1, max_length=100)
    astronaut_ids: list[str] = Field(min_length=1, max_length=100)
    access_lifetime_seconds: int = Field(gt=0, strict=True)

    @model_validator(mode="after")
    def validate_unique_claims(self) -> Self:
        if (
            len(self.permissions) != len(set(self.permissions))
            or any(not item for item in self.permissions)
        ):
            raise ValueError("As permissões têm de ser únicas e não vazias.")
        if (
            len(self.astronaut_ids) != len(set(self.astronaut_ids))
            or any(not item for item in self.astronaut_ids)
        ):
            raise ValueError("Os escopos têm de ser únicos e não vazios.")
        return self


class AuthenticationTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["Bearer"] = "Bearer"
    access_expires_at: datetime
    refresh_expires_at: datetime


class AuthenticationRefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=512)
    access_lifetime_seconds: int = Field(gt=0, strict=True)


class AuthenticationRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=512)


class MonitoringAlertRuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    metric: Metric
    minimum_value: float | None = None
    maximum_value: float | None = None
    rationale: str = Field(min_length=1, max_length=500)
    source_reference: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_definition(self) -> Self:
        minimum, maximum = TECHNICAL_LIMITS[self.metric]
        if not self.rationale.strip() or not self.source_reference.strip():
            raise ValueError("A justificação e a referência da regra não podem estar vazias.")
        if self.minimum_value is None and self.maximum_value is None:
            raise ValueError("A regra tem de configurar um limite mínimo ou máximo.")
        for value in (self.minimum_value, self.maximum_value):
            if value is not None and (
                not isfinite(value) or not minimum <= value <= maximum
            ):
                raise ValueError(
                    "Os limites da regra têm de ser finitos e estar dentro dos "
                    "limites técnicos do indicador."
                )
        if (
            self.minimum_value is not None
            and self.maximum_value is not None
            and self.minimum_value >= self.maximum_value
        ):
            raise ValueError("O limite mínimo tem de ser inferior ao máximo.")
        return self


class MonitoringAlertRule(MonitoringAlertRuleDefinition):
    rule_id: str = Field(min_length=1, max_length=100)
    version: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_rule_id(self) -> Self:
        if not self.rule_id.strip():
            raise ValueError("rule_id não pode estar vazio.")
        return self


class MonitoringAlertRuleUpdate(MonitoringAlertRuleDefinition):
    expected_version: int = Field(ge=0, strict=True)


class MonitoringAlertRuleVersion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: int = Field(ge=1, strict=True)


class MonitoringAlertRuleRecord(BaseModel):
    rule: MonitoringAlertRule
    active: bool
    updated_by: str
    updated_at: datetime


class MonitoringAlertRuleHistory(BaseModel):
    items: list[MonitoringAlertRuleRecord]
    total: int


class MonitoringAlertRuleChange(BaseModel):
    change_id: int
    mission_id: str
    rule_id: str
    version: int
    action: Literal["provisioned", "created", "updated", "reactivated", "deactivated"]
    actor_id: str
    changed_at: datetime
    previous_active: bool | None
    current_active: bool
    previous_rule: MonitoringAlertRule | None
    current_rule: MonitoringAlertRule


class MonitoringAlertRuleAudit(BaseModel):
    items: list[MonitoringAlertRuleChange]
    total: int


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


class EarthSyncMeasurementInput(OfflineMeasurementInput):
    earth_sync_eligible: bool = Field(strict=True)


class OfflineReadingInput(ReadingBatchInput):
    measurements: list[OfflineMeasurementInput] = Field(min_length=1)


class EarthSyncReadingInput(ReadingBatchInput):
    measurements: list[EarthSyncMeasurementInput] = Field(min_length=1)


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


class EarthSyncBatchInput(OfflineSyncBatchInput):
    readings: list[EarthSyncReadingInput] = Field(min_length=1, max_length=100)


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


class MonitoringAlert(BaseModel):
    alert_id: int
    astronaut_id: str
    reading_id: UUID
    rule_id: str
    rule_version: int
    metric: Metric
    value: float
    unit: str
    direction: Literal["below_minimum", "above_maximum"]
    configured_limit: float
    rationale: str
    source_reference: str
    measured_at: datetime
    generated_at: datetime
    acknowledgement_count: int = Field(ge=0)
    acknowledged_by_current_user: bool
    interpretation: Literal["monitoring_support_not_diagnosis"]


class MonitoringAlertHistory(BaseModel):
    items: list[MonitoringAlert]
    total: int


class MonitoringAlertAcknowledgement(BaseModel):
    acknowledgement_id: int
    alert_id: int
    actor_id: str
    acknowledged_at: datetime
    status: Literal["acknowledged"]


class SyncAcknowledgementItem(BaseModel):
    reading_id: UUID
    sequence_number: int
    status: Literal["accepted", "already_received"]


class SyncAcknowledgement(BaseModel):
    batch_id: UUID
    items: list[SyncAcknowledgementItem]


class EarthSyncAdmissionAcknowledgement(BaseModel):
    batch_id: UUID
    onboard_status: Literal["persisted"] = "persisted"
    items: list[SyncAcknowledgementItem]
    earth_delivery_status: Literal[
        "not_requested",
        "no_new_eligible_items",
        "pending",
        "acknowledged_durable",
        "rejected_permanent",
        "conflict_isolated",
    ]
    delivery_batch_id: UUID | None = None


class EarthSyncDeliveryStatus(BaseModel):
    delivery_batch_id: UUID
    origin_batch_id: UUID
    source_service_id: str
    destination_service_id: str
    payload_sha256: str
    status: Literal[
        "pending",
        "in_flight",
        "retry_wait",
        "acknowledged_durable",
        "rejected_permanent",
        "conflict_isolated",
    ]
    created_at: datetime
    attempt_count: int
    last_attempt_at: datetime | None
    next_attempt_at: datetime | None
    acknowledged_at: datetime | None
    error_code: str | None


class EarthSyncReceiptResponse(BaseModel):
    receipt: str


class SyncBatchStatus(BaseModel):
    batch_id: UUID
    source_device_id: UUID
    status: Literal["persisted"]
    received_at: datetime
    items: list[SyncAcknowledgementItem]
