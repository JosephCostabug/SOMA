from datetime import datetime, timezone
from enum import StrEnum
from math import isfinite
from typing import Literal, Self

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.exceptions import InvalidKeyError, InvalidTokenError
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.mission_identity import (
    ActorType,
    DelegationState,
    IdentityState,
    MissionIdentityConfiguration,
    MissionState,
    MissionDelegation,
)


class KeyPurpose(StrEnum):
    GROUND_DELEGATION = "ground_delegation"
    ONBOARD_TOKEN = "onboard_token"
    DEVICE_AUTHENTICATION = "device_authentication"


class KeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class KeyConfigurationError(ValueError):
    pass


class DelegationVerificationError(ValueError):
    pass


class MissionIdentityConfigurationError(ValueError):
    pass


def _utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} tem de incluir fuso horário.")
    return value.astimezone(timezone.utc)


class VerificationKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(min_length=1, max_length=100)
    issuer: str = Field(min_length=1, max_length=200)
    algorithm: Literal["RS256"] = "RS256"
    purpose: KeyPurpose
    state: KeyState
    public_key_pem: str = Field(min_length=1)
    valid_from: datetime
    signing_not_after: datetime
    verify_not_after: datetime
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def validate_key(self) -> Self:
        valid_from = _utc(self.valid_from, "valid_from")
        signing_not_after = _utc(self.signing_not_after, "signing_not_after")
        verify_not_after = _utc(self.verify_not_after, "verify_not_after")
        revoked_at = _utc(self.revoked_at, "revoked_at") if self.revoked_at else None
        if not valid_from < signing_not_after <= verify_not_after:
            raise ValueError(
                "A validade de assinatura tem de preceder a validade final de verificação."
            )
        if self.state == KeyState.REVOKED and revoked_at is None:
            raise ValueError("Uma chave revogada requer revoked_at.")
        if self.state != KeyState.REVOKED and revoked_at is not None:
            raise ValueError("revoked_at só pode ser indicado numa chave revogada.")
        try:
            public_key = serialization.load_pem_public_key(
                self.public_key_pem.encode("ascii")
            )
        except (ValueError, TypeError, UnicodeEncodeError) as error:
            raise ValueError("public_key_pem não contém uma chave pública PEM válida.") from error
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
            raise ValueError("A chave RS256 tem de ser RSA com pelo menos 2048 bits.")
        object.__setattr__(self, "valid_from", valid_from)
        object.__setattr__(self, "signing_not_after", signing_not_after)
        object.__setattr__(self, "verify_not_after", verify_not_after)
        object.__setattr__(self, "revoked_at", revoked_at)
        return self


class VerificationKeySet(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str = Field(min_length=1, max_length=200)
    trusted_key_ids: frozenset[str] = Field(min_length=1)
    keys: tuple[VerificationKey, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_key_set(self) -> Self:
        key_ids = [key.key_id for key in self.keys]
        if len(key_ids) != len(set(key_ids)):
            raise ValueError("key_id tem de ser único no conjunto de chaves.")
        if set(key_ids) != set(self.trusted_key_ids):
            raise ValueError("O conjunto de chaves tem de corresponder à lista confiável.")
        if any(key.issuer != self.issuer for key in self.keys):
            raise ValueError("Todas as chaves têm de pertencer à autoridade configurada.")
        if any(key.purpose != KeyPurpose.GROUND_DELEGATION for key in self.keys):
            raise ValueError(
                "A verificação de delegações só aceita chaves da autoridade terrestre."
            )
        return self

    def get_ground_key(self, key_id: str) -> VerificationKey:
        for key in self.keys:
            if key.key_id == key_id:
                return key
        raise KeyConfigurationError("A chave de assinatura não está na lista confiável.")


def _numeric_date(claims: dict[str, object], name: str) -> datetime:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DelegationVerificationError(f"A claim temporal {name} é inválida.")
    if not isfinite(value):
        raise DelegationVerificationError(f"A claim temporal {name} é inválida.")
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise DelegationVerificationError(
            f"A claim temporal {name} está fora do intervalo suportado."
        ) from error


def verify_ground_delegation(
    token: str,
    *,
    key_set: VerificationKeySet,
    expected_mission_id: str,
    expected_onboard_service_id: str,
    now: datetime,
) -> MissionDelegation:
    """Verify a ground-signed delegation using only pre-provisioned public keys."""
    try:
        current_time = _utc(now, "now")
    except ValueError as error:
        raise DelegationVerificationError(str(error)) from error
    try:
        header = jwt.get_unverified_header(token)
    except (InvalidTokenError, TypeError, ValueError) as error:
        raise DelegationVerificationError("O envelope da delegação é inválido.") from error

    if (
        set(header) != {"alg", "kid", "typ"}
        or header.get("alg") != "RS256"
        or header.get("typ") != "mission-delegation+jwt"
        or not isinstance(header.get("kid"), str)
    ):
        raise DelegationVerificationError("O cabeçalho da delegação não é permitido.")

    try:
        key = key_set.get_ground_key(header["kid"])
    except KeyConfigurationError as error:
        raise DelegationVerificationError(str(error)) from error

    if key.state == KeyState.REVOKED:
        raise DelegationVerificationError("A chave de assinatura foi revogada.")

    try:
        claims = jwt.decode(
            token,
            key.public_key_pem,
            algorithms=["RS256"],
            issuer=key_set.issuer,
            audience=expected_onboard_service_id,
            options={
                "require": ["iss", "aud", "iat", "nbf", "exp", "jti", "delegation"],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except InvalidKeyError as error:
        raise KeyConfigurationError("A chave pública confiável é inválida.") from error
    except InvalidTokenError as error:
        raise DelegationVerificationError(
            "A assinatura ou as claims da delegação são inválidas."
        ) from error

    if set(claims) != {"iss", "aud", "iat", "nbf", "exp", "jti", "delegation"}:
        raise DelegationVerificationError("A delegação contém claims não permitidas.")
    if claims["aud"] != expected_onboard_service_id:
        raise DelegationVerificationError("A delegação destina-se a outro serviço.")
    if not isinstance(claims["delegation"], dict):
        raise DelegationVerificationError("O conteúdo da delegação é inválido.")

    issued_at = _numeric_date(claims, "iat")
    not_before = _numeric_date(claims, "nbf")
    expires_at = _numeric_date(claims, "exp")
    if not issued_at <= not_before <= current_time < expires_at:
        raise DelegationVerificationError("A delegação ainda não é válida ou expirou.")
    if not key.valid_from <= issued_at <= key.signing_not_after:
        raise DelegationVerificationError(
            "A delegação foi emitida fora da validade de assinatura da chave."
        )
    if expires_at > key.verify_not_after:
        raise DelegationVerificationError(
            "A delegação excede a validade de verificação da chave."
        )
    if key.state == KeyState.RETIRED and issued_at > key.signing_not_after:
        raise DelegationVerificationError(
            "Uma chave retirada não pode assinar novas delegações."
        )
    if key.revoked_at is not None and current_time >= key.revoked_at:
        raise DelegationVerificationError("A chave de assinatura foi revogada.")

    try:
        delegation = MissionDelegation.model_validate(claims["delegation"])
    except ValueError as error:
        raise DelegationVerificationError(
            "O conteúdo validado da delegação é inválido."
        ) from error

    if (
        str(delegation.delegation_id) != claims["jti"]
        or delegation.ground_issuer != claims["iss"]
        or delegation.ground_key_id != key.key_id
        or delegation.onboard_service_id != expected_onboard_service_id
        or delegation.mission_id != expected_mission_id
        or delegation.issued_at != issued_at
        or delegation.valid_from != not_before
        or delegation.expires_at != expires_at
        or delegation.state != DelegationState.ACTIVE
    ):
        raise DelegationVerificationError(
            "A delegação não corresponde à autoridade, missão ou validade esperada."
        )
    return delegation


def load_signed_mission_identity_configuration(
    configuration: MissionIdentityConfiguration,
    *,
    signed_delegation_tokens: tuple[str, ...],
    key_set: VerificationKeySet,
    expected_onboard_service_id: str,
    now: datetime,
) -> MissionIdentityConfiguration:
    """Load mission identity configuration using only signed ground delegations."""
    try:
        current_time = _utc(now, "now")
    except ValueError as error:
        raise MissionIdentityConfigurationError(str(error)) from error

    if configuration.delegations:
        raise MissionIdentityConfigurationError(
            "A configuração base não pode conter delegações sem verificação criptográfica."
        )
    if not signed_delegation_tokens:
        raise MissionIdentityConfigurationError(
            "É necessária pelo menos uma delegação terrestre assinada."
        )
    if (
        key_set.issuer != configuration.ground_authority.issuer
        or key_set.trusted_key_ids != configuration.ground_authority.trusted_key_ids
    ):
        raise MissionIdentityConfigurationError(
            "O conjunto de chaves não corresponde à autoridade terrestre configurada."
        )
    if configuration.mission.state != MissionState.ACTIVE:
        raise MissionIdentityConfigurationError(
            "A missão tem de estar ativa para carregar delegações."
        )
    if not configuration.mission.valid_from <= current_time < configuration.mission.expires_at:
        raise MissionIdentityConfigurationError(
            "A missão não está dentro do seu período de validade."
        )

    onboard_identity = next(
        (
            identity
            for identity in configuration.identities
            if identity.identity_id == expected_onboard_service_id
        ),
        None,
    )
    if (
        onboard_identity is None
        or onboard_identity.actor_type != ActorType.SERVICE
        or onboard_identity.state not in {IdentityState.PROVISIONED, IdentityState.ACTIVE}
    ):
        raise MissionIdentityConfigurationError(
            "O serviço a bordo esperado não está provisionado e ativo."
        )

    delegations = tuple(
        verify_ground_delegation(
            token,
            key_set=key_set,
            expected_mission_id=configuration.mission.mission_id,
            expected_onboard_service_id=expected_onboard_service_id,
            now=current_time,
        )
        for token in signed_delegation_tokens
    )
    configuration_data = configuration.model_dump(mode="python")
    configuration_data["delegations"] = delegations
    try:
        return MissionIdentityConfiguration.model_validate(configuration_data)
    except ValueError as error:
        raise MissionIdentityConfigurationError(
            "As delegações assinadas não correspondem à configuração da missão."
        ) from error
