from datetime import datetime, timezone
from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ActorType(StrEnum):
    USER = "user"
    DEVICE = "device"
    SERVICE = "service"


class IdentityState(StrEnum):
    PENDING = "pending"
    PROVISIONED = "provisioned"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class MissionState(StrEnum):
    PLANNED = "planned"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    COMPLETED = "completed"


class DelegationState(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} tem de incluir fuso horário.")
    return value.astimezone(timezone.utc)


class GroundIdentityAuthority(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str = Field(min_length=1, max_length=200)
    trusted_key_ids: frozenset[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_key_ids(self) -> Self:
        if any(not key_id for key_id in self.trusted_key_ids):
            raise ValueError("Os identificadores de chave confiáveis não podem ser vazios.")
        return self


class Mission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mission_id: str = Field(min_length=1, max_length=100)
    state: MissionState
    valid_from: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_validity(self) -> Self:
        valid_from = _require_aware(self.valid_from, "valid_from")
        expires_at = _require_aware(self.expires_at, "expires_at")
        if valid_from >= expires_at:
            raise ValueError("valid_from tem de ser anterior a expires_at.")
        object.__setattr__(self, "valid_from", valid_from)
        object.__setattr__(self, "expires_at", expires_at)
        return self


class MissionIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_id: str = Field(min_length=1, max_length=200)
    mission_id: str = Field(min_length=1, max_length=100)
    actor_type: ActorType
    state: IdentityState
    permissions: frozenset[str]
    astronaut_ids: frozenset[str]
    valid_from: datetime
    expires_at: datetime
    key_id: str | None = None
    public_key_thumbprint: str | None = None

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        valid_from = _require_aware(self.valid_from, "valid_from")
        expires_at = _require_aware(self.expires_at, "expires_at")
        if valid_from >= expires_at:
            raise ValueError("valid_from tem de ser anterior a expires_at.")
        if any(not permission for permission in self.permissions):
            raise ValueError("As permissões não podem conter valores vazios.")
        if any(not astronaut_id for astronaut_id in self.astronaut_ids):
            raise ValueError("Os escopos de astronauta não podem conter valores vazios.")
        if self.actor_type in {ActorType.DEVICE, ActorType.SERVICE} and (
            not self.key_id or not self.public_key_thumbprint
        ):
            raise ValueError(
                "Dispositivos e serviços requerem key_id e public_key_thumbprint."
            )
        object.__setattr__(self, "valid_from", valid_from)
        object.__setattr__(self, "expires_at", expires_at)
        return self


class MissionDelegation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    delegation_id: UUID
    mission_id: str = Field(min_length=1, max_length=100)
    ground_issuer: str = Field(min_length=1, max_length=200)
    ground_key_id: str = Field(min_length=1, max_length=100)
    onboard_service_id: str = Field(min_length=1, max_length=200)
    onboard_key_id: str = Field(min_length=1, max_length=100)
    allowed_actor_types: frozenset[ActorType] = Field(min_length=1)
    permissions: frozenset[str]
    astronaut_ids: frozenset[str]
    policy_id: str = Field(min_length=1, max_length=100)
    state: DelegationState
    issued_at: datetime
    valid_from: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    max_token_lifetime_seconds: int = Field(gt=0, strict=True)

    @model_validator(mode="after")
    def validate_delegation(self) -> Self:
        issued_at = _require_aware(self.issued_at, "issued_at")
        valid_from = _require_aware(self.valid_from, "valid_from")
        expires_at = _require_aware(self.expires_at, "expires_at")
        revoked_at = (
            _require_aware(self.revoked_at, "revoked_at")
            if self.revoked_at is not None
            else None
        )
        if issued_at > valid_from:
            raise ValueError("issued_at não pode ser posterior a valid_from.")
        if valid_from >= expires_at:
            raise ValueError("valid_from tem de ser anterior a expires_at.")
        if expires_at <= issued_at:
            raise ValueError("expires_at tem de ser posterior a issued_at.")
        if any(not permission for permission in self.permissions):
            raise ValueError("As permissões delegadas não podem conter valores vazios.")
        if any(not astronaut_id for astronaut_id in self.astronaut_ids):
            raise ValueError("Os escopos delegados não podem conter valores vazios.")
        if self.state == DelegationState.REVOKED and revoked_at is None:
            raise ValueError("Uma delegação revogada requer revoked_at.")
        if self.state != DelegationState.REVOKED and revoked_at is not None:
            raise ValueError("revoked_at só pode ser indicado numa delegação revogada.")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "valid_from", valid_from)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "revoked_at", revoked_at)
        return self

    def permits_token(
        self,
        *,
        mission_id: str,
        actor_type: ActorType,
        permissions: frozenset[str],
        astronaut_ids: frozenset[str],
        issued_at: datetime,
        expires_at: datetime,
    ) -> bool:
        token_issued_at = _require_aware(issued_at, "issued_at")
        token_expires_at = _require_aware(expires_at, "expires_at")
        return (
            self.state == DelegationState.ACTIVE
            and
            mission_id == self.mission_id
            and actor_type in self.allowed_actor_types
            and permissions <= self.permissions
            and astronaut_ids <= self.astronaut_ids
            and self.valid_from <= token_issued_at < self.expires_at
            and token_issued_at < token_expires_at <= self.expires_at
            and (
                token_expires_at - token_issued_at
            ).total_seconds()
            <= self.max_token_lifetime_seconds
        )


class MissionIdentityConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mission: Mission
    ground_authority: GroundIdentityAuthority
    identities: tuple[MissionIdentity, ...]
    delegations: tuple[MissionDelegation, ...]

    @model_validator(mode="after")
    def validate_mission_relationships(self) -> Self:
        mission_id = self.mission.mission_id
        identity_ids = [identity.identity_id for identity in self.identities]
        delegation_ids = [delegation.delegation_id for delegation in self.delegations]
        if len(identity_ids) != len(set(identity_ids)):
            raise ValueError("identity_id tem de ser único dentro da missão.")
        if len(delegation_ids) != len(set(delegation_ids)):
            raise ValueError("delegation_id tem de ser único dentro da missão.")

        identities_by_id = {identity.identity_id: identity for identity in self.identities}
        for identity in self.identities:
            if identity.mission_id != mission_id:
                raise ValueError("A identidade pertence a outra missão.")
            if (
                identity.valid_from < self.mission.valid_from
                or identity.expires_at > self.mission.expires_at
            ):
                raise ValueError("A validade da identidade tem de caber na missão.")

        for delegation in self.delegations:
            if delegation.mission_id != mission_id:
                raise ValueError("A delegação pertence a outra missão.")
            if delegation.ground_issuer != self.ground_authority.issuer:
                raise ValueError("A delegação foi emitida por outra autoridade terrestre.")
            if delegation.ground_key_id not in self.ground_authority.trusted_key_ids:
                raise ValueError("A chave terrestre da delegação não é confiável.")
            if (
                delegation.issued_at < self.mission.valid_from
                or delegation.valid_from < self.mission.valid_from
                or delegation.expires_at > self.mission.expires_at
            ):
                raise ValueError("A validade da delegação tem de caber na missão.")
            onboard_identity = identities_by_id.get(delegation.onboard_service_id)
            if (
                onboard_identity is None
                or onboard_identity.actor_type != ActorType.SERVICE
                or onboard_identity.key_id != delegation.onboard_key_id
            ):
                raise ValueError(
                    "A delegação tem de referenciar o serviço a bordo e a sua chave."
                )
            if (
                delegation.valid_from < onboard_identity.valid_from
                or delegation.expires_at > onboard_identity.expires_at
            ):
                raise ValueError(
                    "A validade da delegação tem de caber na validade do serviço a bordo."
                )
            if delegation.state == DelegationState.ACTIVE and onboard_identity.state not in {
                IdentityState.PROVISIONED,
                IdentityState.ACTIVE,
            }:
                raise ValueError(
                    "Uma delegação ativa requer a identidade do serviço provisionada."
                )
            if delegation.permissions - onboard_identity.permissions:
                raise ValueError(
                    "A delegação não pode exceder as permissões do serviço provisionado."
                )
            if delegation.astronaut_ids - onboard_identity.astronaut_ids:
                raise ValueError(
                    "A delegação não pode exceder o escopo do serviço provisionado."
                )
        return self
