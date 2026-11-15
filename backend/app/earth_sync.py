from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import ssl
import sqlite3
from typing import Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.database import connect_database, initialize_database
from app.identity_bootstrap import read_protected_file
from app.schemas import Metric


class EarthSyncConfigurationError(ValueError):
    pass


class EarthSyncProtocolError(ValueError):
    pass


class _SerializablePublicKey(Protocol):
    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes: ...


class EarthSyncItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reading_id: UUID
    astronaut_id: str = Field(min_length=1, max_length=100)
    metric: Metric
    value: float = Field(allow_inf_nan=False)
    unit: str = Field(min_length=1, max_length=30)
    measured_at: datetime
    received_at: datetime
    glucose_context: str | None = Field(default=None, max_length=30)
    declared_origin: Literal["nasa", "simulated", "manual"]
    source_device_id: UUID
    sequence_number: int = Field(ge=1)
    origin_batch_id: UUID

    @field_validator("measured_at", "received_at")
    @classmethod
    def require_aware_timestamps(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Os instantes do lote têm de incluir fuso horário.")
        return value


class EarthSyncEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[1]
    delivery_batch_id: UUID
    origin_batch_id: UUID
    source_service_id: str = Field(min_length=1, max_length=200)
    destination_service_id: str = Field(min_length=1, max_length=200)
    created_at: datetime
    items: list[EarthSyncItem] = Field(min_length=1, max_length=100)

    @field_validator("created_at")
    @classmethod
    def require_aware_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at tem de incluir fuso horário.")
        return value

    @model_validator(mode="after")
    def validate_origin_batch_and_sequences(self) -> EarthSyncEnvelope:
        if any(item.origin_batch_id != self.origin_batch_id for item in self.items):
            raise ValueError("Todos os itens têm de referir o lote de origem.")
        device_sequences = [
            (item.source_device_id, item.sequence_number) for item in self.items
        ]
        if len(device_sequences) != len(set(device_sequences)):
            raise ValueError("O lote contém sequências de dispositivo duplicadas.")
        return self


@dataclass(frozen=True)
class EarthSyncSettings:
    role: Literal["onboard", "earth"]
    local_service_id: str
    peer_service_id: str
    signing_key: rsa.RSAPrivateKey
    peer_public_key: rsa.RSAPublicKey
    receiver_url: str | None = None
    ssl_context: ssl.SSLContext | None = None
    request_timeout_seconds: int | None = None
    retry_base_seconds: int | None = None
    retry_max_seconds: int | None = None
    lease_seconds: int | None = None


@dataclass(frozen=True)
class EarthSyncReceipt:
    http_status: int
    token: str


@dataclass(frozen=True)
class EarthSyncWorkerResult:
    attempted: int
    acknowledged: int
    rejected: int
    conflicts: int
    retry_scheduled: int


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise EarthSyncConfigurationError(f"{name} não foi configurado.")
    return value.strip()


def _positive_integer(name: str) -> int:
    value = _required_environment(name)
    try:
        parsed = int(value)
    except ValueError as error:
        raise EarthSyncConfigurationError(
            f"{name} tem de ser um inteiro positivo."
        ) from error
    if parsed < 1:
        raise EarthSyncConfigurationError(f"{name} tem de ser um inteiro positivo.")
    return parsed


def _read_private_rsa_key(path_name: str) -> rsa.RSAPrivateKey:
    path = _required_environment(path_name)
    try:
        encoded = read_protected_file(
            path,
            max_bytes=16_384,
            label=f"chave privada de sincronização ({path_name})",
        )
        key = serialization.load_pem_private_key(encoded, password=None)
    except (OSError, TypeError, ValueError) as error:
        raise EarthSyncConfigurationError(
            f"A chave privada configurada em {path_name} não é válida."
        ) from error
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise EarthSyncConfigurationError(
            f"{path_name} tem de conter uma chave RSA de pelo menos 2048 bits."
        )
    return key


def _read_peer_rsa_key(path_name: str) -> rsa.RSAPublicKey:
    path = _required_environment(path_name)
    try:
        encoded = read_protected_file(
            path,
            max_bytes=1_048_576,
            label=f"chave pública de sincronização ({path_name})",
        )
        key = serialization.load_pem_public_key(encoded)
    except (OSError, TypeError, ValueError) as error:
        raise EarthSyncConfigurationError(
            f"A chave pública configurada em {path_name} não é válida."
        ) from error
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise EarthSyncConfigurationError(
            f"{path_name} tem de conter uma chave RSA de pelo menos 2048 bits."
        )
    return key


def _validate_protected_path(path_name: str, *, label: str) -> str:
    path = _required_environment(path_name)
    read_protected_file(path, max_bytes=1_048_576, label=label)
    return path


def _public_key_bytes(public_key: _SerializablePublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def validate_tls_identity(
    certificate_path: str,
    private_key_path: str,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    try:
        certificate_bytes = read_protected_file(
            certificate_path,
            max_bytes=1_048_576,
            label="certificado TLS",
        )
        private_key_bytes = read_protected_file(
            private_key_path,
            max_bytes=16_384,
            label="chave privada TLS",
        )
        certificate = x509.load_pem_x509_certificate(certificate_bytes)
        tls_private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
        )
        certificate_public_key = certificate.public_key()
        tls_public_key = tls_private_key.public_key()
    except (OSError, TypeError, ValueError) as error:
        raise EarthSyncConfigurationError(
            "O certificado ou a chave privada TLS não é válido."
        ) from error
    if _public_key_bytes(certificate_public_key) != _public_key_bytes(tls_public_key):
        raise EarthSyncConfigurationError(
            "O certificado TLS não corresponde à chave privada TLS."
        )
    if _public_key_bytes(tls_public_key) == _public_key_bytes(signing_key.public_key()):
        raise EarthSyncConfigurationError(
            "A chave privada TLS não pode ser reutilizada para assinar tokens."
        )


def load_earth_sync_settings() -> EarthSyncSettings:
    role = _required_environment("EARTH_SYNC_ROLE")
    if role not in {"onboard", "earth"}:
        raise EarthSyncConfigurationError(
            "EARTH_SYNC_ROLE tem de ser 'onboard' ou 'earth'."
        )
    local_service_id = _required_environment("EARTH_SYNC_LOCAL_SERVICE_ID")
    peer_service_id = _required_environment("EARTH_SYNC_PEER_SERVICE_ID")
    if local_service_id == peer_service_id:
        raise EarthSyncConfigurationError(
            "Os serviços local e peer têm de possuir identidades diferentes."
        )
    signing_key = _read_private_rsa_key("EARTH_SYNC_SIGNING_KEY_PATH")
    peer_public_key = _read_peer_rsa_key("EARTH_SYNC_PEER_PUBLIC_KEY_PATH")
    if _public_key_bytes(signing_key.public_key()) == _public_key_bytes(peer_public_key):
        raise EarthSyncConfigurationError(
            "Os serviços onboard e Terra têm de usar chaves de assinatura distintas."
        )

    if role == "earth":
        return EarthSyncSettings(
            role="earth",
            local_service_id=local_service_id,
            peer_service_id=peer_service_id,
            signing_key=signing_key,
            peer_public_key=peer_public_key,
        )

    receiver_url = _required_environment("EARTH_SYNC_RECEIVER_URL")
    parsed_url = urlparse(receiver_url)
    try:
        receiver_port = parsed_url.port
    except ValueError as error:
        raise EarthSyncConfigurationError(
            "EARTH_SYNC_RECEIVER_URL contém uma porta inválida."
        ) from error
    if (
        parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.fragment
        or parsed_url.query
        or parsed_url.path != "/api/v1/sync/earth/batches"
        or (receiver_port is not None and not 1 <= receiver_port <= 65535)
    ):
        raise EarthSyncConfigurationError(
            "EARTH_SYNC_RECEIVER_URL tem de apontar por HTTPS para o endpoint "
            "bordo-Terra, sem credenciais nem query string."
        )
    ca_bundle_path = _validate_protected_path(
        "EARTH_SYNC_CA_BUNDLE_PATH",
        label="CA TLS do serviço terrestre",
    )
    client_cert_path = _validate_protected_path(
        "EARTH_SYNC_CLIENT_CERT_PATH",
        label="certificado cliente onboard",
    )
    client_key_path = _validate_protected_path(
        "EARTH_SYNC_CLIENT_KEY_PATH",
        label="chave privada TLS onboard",
    )
    validate_tls_identity(client_cert_path, client_key_path, signing_key)
    try:
        ssl_context = ssl.create_default_context(cafile=ca_bundle_path)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.load_cert_chain(
            certfile=client_cert_path,
            keyfile=client_key_path,
        )
    except (OSError, ssl.SSLError, ValueError) as error:
        raise EarthSyncConfigurationError(
            "A configuração mTLS do envio onboard é inválida."
        ) from error

    timeout = _positive_integer("EARTH_SYNC_REQUEST_TIMEOUT_SECONDS")
    retry_base = _positive_integer("EARTH_SYNC_RETRY_BASE_SECONDS")
    retry_max = _positive_integer("EARTH_SYNC_RETRY_MAX_SECONDS")
    lease = _positive_integer("EARTH_SYNC_LEASE_SECONDS")
    if retry_max < retry_base:
        raise EarthSyncConfigurationError(
            "EARTH_SYNC_RETRY_MAX_SECONDS não pode ser inferior ao intervalo base."
        )
    if lease <= timeout:
        raise EarthSyncConfigurationError(
            "EARTH_SYNC_LEASE_SECONDS tem de exceder o timeout do pedido."
        )
    return EarthSyncSettings(
        role="onboard",
        local_service_id=local_service_id,
        peer_service_id=peer_service_id,
        signing_key=signing_key,
        peer_public_key=peer_public_key,
        receiver_url=receiver_url,
        ssl_context=ssl_context,
        request_timeout_seconds=timeout,
        retry_base_seconds=retry_base,
        retry_max_seconds=retry_max,
        lease_seconds=lease,
    )


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def payload_digest(payload_json: str) -> str:
    try:
        payload = json.loads(payload_json)
        canonical = canonical_json(payload)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise EarthSyncProtocolError("O snapshot da outbox não é JSON válido.") from error
    if canonical != payload_json:
        raise EarthSyncProtocolError(
            "O snapshot da outbox não está na forma canónica do protocolo."
        )
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def create_request_token(
    settings: EarthSyncSettings,
    *,
    payload: dict[str, object],
    payload_sha256: str,
    now: datetime | None = None,
) -> str:
    if settings.role != "onboard" or settings.request_timeout_seconds is None:
        raise EarthSyncProtocolError("A configuração não é de emissor onboard.")
    issued_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    claims = {
        "iss": settings.local_service_id,
        "sub": settings.local_service_id,
        "aud": settings.peer_service_id,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + timedelta(seconds=settings.request_timeout_seconds + 60),
        "jti": str(uuid4()),
        "protocol_version": 1,
        "delivery_batch_id": payload.get("delivery_batch_id"),
        "payload_sha256": payload_sha256,
    }
    return jwt.encode(claims, settings.signing_key, algorithm="RS256")


def _verify_request_token(
    settings: EarthSyncSettings,
    *,
    token: str,
    payload: dict[str, object],
) -> dict[str, object]:
    try:
        header = jwt.get_unverified_header(token)
    except (jwt.InvalidTokenError, TypeError, ValueError) as error:
        raise EarthSyncProtocolError("O token do serviço emissor é inválido.") from error
    if set(header) != {"alg", "typ"} or header.get("alg") != "RS256":
        raise EarthSyncProtocolError("O cabeçalho do token de serviço não é permitido.")
    try:
        claims = jwt.decode(
            token,
            settings.peer_public_key,
            algorithms=["RS256"],
            issuer=settings.peer_service_id,
            audience=settings.local_service_id,
            leeway=5,
            options={
                "require": [
                    "iss",
                    "sub",
                    "aud",
                    "iat",
                    "nbf",
                    "exp",
                    "jti",
                    "protocol_version",
                    "delivery_batch_id",
                    "payload_sha256",
                ]
            },
        )
    except jwt.InvalidTokenError as error:
        raise EarthSyncProtocolError("A autenticação do serviço emissor falhou.") from error
    if set(claims) != {
        "iss",
        "sub",
        "aud",
        "iat",
        "nbf",
        "exp",
        "jti",
        "protocol_version",
        "delivery_batch_id",
        "payload_sha256",
    }:
        raise EarthSyncProtocolError("O token de serviço contém claims não permitidas.")
    try:
        canonical_hash = hashlib.sha256(
            canonical_json(payload).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError) as error:
        raise EarthSyncProtocolError("O payload não é JSON canónico válido.") from error
    if (
        claims["sub"] != settings.peer_service_id
        or claims["protocol_version"] != 1
        or claims["delivery_batch_id"] != payload.get("delivery_batch_id")
        or claims["payload_sha256"] != canonical_hash
    ):
        raise EarthSyncProtocolError(
            "O token de serviço não corresponde ao lote recebido."
        )
    return claims


def _create_receipt_token(
    settings: EarthSyncSettings,
    *,
    delivery_batch_id: str,
    payload_sha256: str,
    receipt_status: Literal[
        "persisted",
        "already_persisted",
        "rejected_permanent",
        "conflict_isolated",
    ],
    accepted_reading_ids: list[str],
    result_code: str | None = None,
    now: datetime | None = None,
) -> str:
    receipt_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    claims: dict[str, object] = {
        "iss": settings.local_service_id,
        "aud": settings.peer_service_id,
        "iat": receipt_time,
        "nbf": receipt_time,
        "jti": str(uuid4()),
        "delivery_batch_id": delivery_batch_id,
        "payload_sha256": payload_sha256,
        "status": receipt_status,
        "accepted_reading_ids": accepted_reading_ids,
        "result_code": result_code or receipt_status,
        "recorded_at": receipt_time.isoformat(),
    }
    return jwt.encode(claims, settings.signing_key, algorithm="RS256")


def verify_receipt_token(
    settings: EarthSyncSettings,
    *,
    token: str,
    delivery_batch_id: str,
    payload_sha256: str,
    expected_reading_ids: set[str],
) -> dict[str, object]:
    try:
        header = jwt.get_unverified_header(token)
    except (jwt.InvalidTokenError, TypeError, ValueError) as error:
        raise EarthSyncProtocolError("O cabeçalho do recibo é inválido.") from error
    if set(header) != {"alg", "typ"} or header.get("alg") != "RS256":
        raise EarthSyncProtocolError("O cabeçalho do recibo não é permitido.")
    try:
        claims = jwt.decode(
            token,
            settings.peer_public_key,
            algorithms=["RS256"],
            issuer=settings.peer_service_id,
            audience=settings.local_service_id,
            leeway=5,
            options={
                "require": [
                    "iss",
                    "aud",
                    "iat",
                    "nbf",
                    "jti",
                    "delivery_batch_id",
                    "payload_sha256",
                    "status",
                    "accepted_reading_ids",
                    "result_code",
                    "recorded_at",
                ]
            },
        )
    except jwt.InvalidTokenError as error:
        raise EarthSyncProtocolError("O recibo terrestre não é autenticável.") from error
    if set(claims) != {
        "iss",
        "aud",
        "iat",
        "nbf",
        "jti",
        "delivery_batch_id",
        "payload_sha256",
        "status",
        "accepted_reading_ids",
        "result_code",
        "recorded_at",
    }:
        raise EarthSyncProtocolError("O recibo contém claims não permitidas.")
    if (
        claims["delivery_batch_id"] != delivery_batch_id
        or claims["payload_sha256"] != payload_sha256
        or not isinstance(claims["accepted_reading_ids"], list)
        or any(not isinstance(item, str) for item in claims["accepted_reading_ids"])
        or len(claims["accepted_reading_ids"])
        != len(set(claims["accepted_reading_ids"]))
    ):
        raise EarthSyncProtocolError("O recibo não corresponde ao lote enviado.")
    receipt_status = claims["status"]
    if not isinstance(receipt_status, str):
        raise EarthSyncProtocolError("O recibo declara um estado inválido.")
    if (
        not isinstance(claims["result_code"], str)
        or not claims["result_code"]
        or not isinstance(claims["recorded_at"], str)
    ):
        raise EarthSyncProtocolError("O recibo não contém os campos de resultado válidos.")
    try:
        recorded_at = datetime.fromisoformat(claims["recorded_at"])
    except ValueError as error:
        raise EarthSyncProtocolError("O instante de persistência do recibo é inválido.") from error
    if recorded_at.tzinfo is None or recorded_at.utcoffset() is None:
        raise EarthSyncProtocolError("O instante de persistência não tem fuso horário.")
    if receipt_status in {"persisted", "already_persisted"}:
        if set(claims["accepted_reading_ids"]) != expected_reading_ids:
            raise EarthSyncProtocolError(
                "O recibo não confirma exatamente as medições do lote."
            )
    elif receipt_status in {"rejected_permanent", "conflict_isolated"}:
        if claims["accepted_reading_ids"]:
            raise EarthSyncProtocolError(
                "Um lote rejeitado não pode confirmar medições."
            )
    else:
        raise EarthSyncProtocolError("O recibo declara um estado desconhecido.")
    return claims


def _persist_receiver_result(
    connection: sqlite3.Connection,
    *,
    delivery_batch_id: str,
    origin_batch_id: str,
    source_service_id: str,
    payload_sha256: str,
    payload_json: str,
    receipt_token: str,
    result_status: str,
    recorded_at: str,
    items: list[EarthSyncItem] | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO earth_received_batches (
            delivery_batch_id, origin_batch_id, source_service_id,
            payload_sha256, payload_json, receipt_jwt, status, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            delivery_batch_id,
            origin_batch_id,
            source_service_id,
            payload_sha256,
            payload_json,
            receipt_token,
            result_status,
            recorded_at,
        ),
    )
    if result_status not in {"persisted", "already_persisted"}:
        return
    for item in items or []:
        item_json = canonical_json(item.model_dump(mode="json"))
        item_hash = hashlib.sha256(item_json.encode("utf-8")).hexdigest()
        existing_item = connection.execute(
            """
            SELECT item_sha256 FROM earth_received_items WHERE reading_id = ?
            """,
            (str(item.reading_id),),
        ).fetchone()
        if existing_item is None:
            connection.execute(
                """
                INSERT INTO earth_received_items (
                    reading_id, source_device_id, sequence_number, item_sha256,
                    item_json, first_delivery_batch_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(item.reading_id),
                    str(item.source_device_id),
                    item.sequence_number,
                    item_hash,
                    item_json,
                    delivery_batch_id,
                ),
            )
        connection.execute(
            """
            INSERT INTO earth_received_batch_items (
                delivery_batch_id, reading_id, item_sha256
            ) VALUES (?, ?, ?)
            """,
            (delivery_batch_id, str(item.reading_id), item_hash),
        )


def _record_conflict(
    connection: sqlite3.Connection,
    *,
    settings: EarthSyncSettings,
    delivery_batch_id: str,
    origin_batch_id: str,
    payload_sha256: str,
    payload_json: str,
    source_service_id: str,
    conflict_code: str,
    now: datetime,
) -> EarthSyncReceipt:
    existing = connection.execute(
        """
        SELECT receipt_jwt FROM earth_sync_conflicts
        WHERE delivery_batch_id = ? AND payload_sha256 = ?
        """,
        (delivery_batch_id, payload_sha256),
    ).fetchone()
    if existing is not None:
        connection.commit()
        return EarthSyncReceipt(http_status=409, token=existing["receipt_jwt"])
    recorded_at = now.astimezone(timezone.utc).isoformat()
    receipt = _create_receipt_token(
        settings,
        delivery_batch_id=delivery_batch_id,
        payload_sha256=payload_sha256,
        receipt_status="conflict_isolated",
        accepted_reading_ids=[],
        result_code=conflict_code,
        now=now,
    )
    connection.execute(
        """
        INSERT INTO earth_sync_conflicts (
            delivery_batch_id, origin_batch_id, source_service_id,
            payload_sha256, payload_json, conflict_code, receipt_jwt, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            delivery_batch_id,
            origin_batch_id,
            source_service_id,
            payload_sha256,
            payload_json,
            conflict_code,
            receipt,
            recorded_at,
        ),
    )
    connection.commit()
    return EarthSyncReceipt(http_status=409, token=receipt)


def receive_earth_sync_payload(
    connection: sqlite3.Connection,
    settings: EarthSyncSettings,
    *,
    payload: dict[str, object],
    bearer_token: str,
) -> EarthSyncReceipt:
    if settings.role != "earth":
        raise EarthSyncProtocolError("O serviço não está configurado como receptor Terra.")
    payload_json = canonical_json(payload)
    payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    claims = _verify_request_token(
        settings,
        token=bearer_token,
        payload=payload,
    )
    delivery_batch_id = str(claims["delivery_batch_id"])
    origin_batch_id = str(payload.get("origin_batch_id", "unknown"))
    now = datetime.now(timezone.utc)
    connection.execute("BEGIN IMMEDIATE")
    try:
        previous = connection.execute(
            """
            SELECT payload_sha256, receipt_jwt, status
            FROM earth_received_batches
            WHERE delivery_batch_id = ?
            """,
            (delivery_batch_id,),
        ).fetchone()
        if previous is not None:
            if previous["payload_sha256"] == payload_sha256:
                connection.commit()
                return EarthSyncReceipt(
                    http_status=200
                    if previous["status"] in {"persisted", "already_persisted"}
                    else 422,
                    token=previous["receipt_jwt"],
                )
            result = _record_conflict(
                connection,
                settings=settings,
                delivery_batch_id=delivery_batch_id,
                origin_batch_id=origin_batch_id,
                payload_sha256=payload_sha256,
                payload_json=payload_json,
                source_service_id=settings.peer_service_id,
                conflict_code="delivery_batch_id_reused",
                now=now,
            )
            return result

        prior_conflict = connection.execute(
            """
            SELECT receipt_jwt FROM earth_sync_conflicts
            WHERE delivery_batch_id = ? AND payload_sha256 = ?
            """,
            (delivery_batch_id, payload_sha256),
        ).fetchone()
        if prior_conflict is not None:
            connection.commit()
            return EarthSyncReceipt(http_status=409, token=prior_conflict["receipt_jwt"])

        try:
            envelope = EarthSyncEnvelope.model_validate(payload)
        except ValidationError:
            recorded_at = now.isoformat()
            receipt = _create_receipt_token(
                settings,
                delivery_batch_id=delivery_batch_id,
                payload_sha256=payload_sha256,
                receipt_status="rejected_permanent",
                accepted_reading_ids=[],
                result_code="invalid_envelope",
                now=now,
            )
            _persist_receiver_result(
                connection,
                delivery_batch_id=delivery_batch_id,
                origin_batch_id=origin_batch_id,
                source_service_id=settings.peer_service_id,
                payload_sha256=payload_sha256,
                payload_json=payload_json,
                receipt_token=receipt,
                result_status="rejected_permanent",
                recorded_at=recorded_at,
            )
            connection.commit()
            return EarthSyncReceipt(http_status=422, token=receipt)

        if (
            envelope.delivery_batch_id != UUID(delivery_batch_id)
            or envelope.source_service_id != settings.peer_service_id
            or envelope.destination_service_id != settings.local_service_id
            or envelope.protocol_version != claims["protocol_version"]
        ):
            result = _record_conflict(
                connection,
                settings=settings,
                delivery_batch_id=delivery_batch_id,
                origin_batch_id=str(envelope.origin_batch_id),
                payload_sha256=payload_sha256,
                payload_json=payload_json,
                source_service_id=settings.peer_service_id,
                conflict_code="service_or_batch_identity_mismatch",
                now=now,
            )
            return result

        reading_ids = [str(item.reading_id) for item in envelope.items]
        if len(reading_ids) != len(set(reading_ids)):
            recorded_at = now.isoformat()
            receipt = _create_receipt_token(
                settings,
                delivery_batch_id=delivery_batch_id,
                payload_sha256=payload_sha256,
                receipt_status="rejected_permanent",
                accepted_reading_ids=[],
                result_code="duplicate_reading_id_in_batch",
                now=now,
            )
            _persist_receiver_result(
                connection,
                delivery_batch_id=delivery_batch_id,
                origin_batch_id=str(envelope.origin_batch_id),
                source_service_id=settings.peer_service_id,
                payload_sha256=payload_sha256,
                payload_json=payload_json,
                receipt_token=receipt,
                result_status="rejected_permanent",
                recorded_at=recorded_at,
            )
            connection.commit()
            return EarthSyncReceipt(http_status=422, token=receipt)

        conflicting_ids: list[str] = []
        duplicate_ids: set[str] = set()
        for item in envelope.items:
            item_json = canonical_json(item.model_dump(mode="json"))
            item_hash = hashlib.sha256(item_json.encode("utf-8")).hexdigest()
            stored_item = connection.execute(
                """
                SELECT item_sha256 FROM earth_received_items
                WHERE reading_id = ?
                """,
                (str(item.reading_id),),
            ).fetchone()
            if stored_item is not None and stored_item["item_sha256"] != item_hash:
                conflicting_ids.append(str(item.reading_id))
            elif stored_item is not None:
                duplicate_ids.add(str(item.reading_id))
            stored_sequence = connection.execute(
                """
                SELECT reading_id FROM earth_received_items
                WHERE source_device_id = ? AND sequence_number = ?
                """,
                (str(item.source_device_id), item.sequence_number),
            ).fetchone()
            if (
                stored_sequence is not None
                and stored_sequence["reading_id"] != str(item.reading_id)
            ):
                conflicting_ids.append(str(item.reading_id))
        if conflicting_ids:
            result = _record_conflict(
                connection,
                settings=settings,
                delivery_batch_id=delivery_batch_id,
                origin_batch_id=str(envelope.origin_batch_id),
                payload_sha256=payload_sha256,
                payload_json=payload_json,
                source_service_id=settings.peer_service_id,
                conflict_code="reading_id_content_conflict",
                now=now,
            )
            return result

        result_status = "already_persisted" if duplicate_ids else "persisted"
        receipt_status = (
            "already_persisted" if duplicate_ids else "persisted"
        )
        recorded_at = now.isoformat()
        receipt = _create_receipt_token(
            settings,
            delivery_batch_id=delivery_batch_id,
            payload_sha256=payload_sha256,
            receipt_status=receipt_status,
            accepted_reading_ids=reading_ids,
            now=now,
        )
        _persist_receiver_result(
            connection,
            delivery_batch_id=delivery_batch_id,
            origin_batch_id=str(envelope.origin_batch_id),
            source_service_id=settings.peer_service_id,
            payload_sha256=payload_sha256,
            payload_json=payload_json,
            receipt_token=receipt,
            result_status=result_status,
            recorded_at=recorded_at,
            items=list(envelope.items),
        )
        connection.commit()
        return EarthSyncReceipt(http_status=200, token=receipt)
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


def _send_batch(
    settings: EarthSyncSettings,
    *,
    payload_json: str,
    payload_sha256: str,
) -> tuple[int, str]:
    if (
        settings.receiver_url is None
        or settings.ssl_context is None
        or settings.request_timeout_seconds is None
    ):
        raise EarthSyncProtocolError("A configuração HTTPS onboard está incompleta.")
    payload = json.loads(payload_json)
    token = create_request_token(
        settings,
        payload=payload,
        payload_sha256=payload_sha256,
    )
    request = Request(
        settings.receiver_url,
        data=payload_json.encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        response = urlopen(
            request,
            context=settings.ssl_context,
            timeout=settings.request_timeout_seconds,
        )
        with response:
            status_code = response.status
            response_body = response.read(65_537)
    except HTTPError as error:
        status_code = error.code
        response_body = error.read(65_537)
    except (OSError, URLError, TimeoutError, ssl.SSLError) as error:
        raise EarthSyncProtocolError("O envio HTTPS/mTLS falhou.") from error
    if len(response_body) > 65_536:
        raise EarthSyncProtocolError("A resposta do receptor excede o limite do protocolo.")
    try:
        response_data = json.loads(response_body)
        receipt_token = response_data["receipt"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise EarthSyncProtocolError("O receptor não devolveu um recibo válido.") from error
    if not isinstance(receipt_token, str):
        raise EarthSyncProtocolError("O token do recibo não é uma string.")
    return status_code, receipt_token


def _claim_next_due_batch(
    connection: sqlite3.Connection,
    settings: EarthSyncSettings,
    *,
    worker_id: str,
    now: datetime,
) -> sqlite3.Row | None:
    if settings.role != "onboard" or settings.lease_seconds is None:
        raise EarthSyncProtocolError("A configuração não é de worker onboard.")
    now_iso = now.astimezone(timezone.utc).isoformat()
    lease_expiry = (now + timedelta(seconds=settings.lease_seconds)).isoformat()
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            UPDATE earth_outbound_batches
            SET status = 'retry_wait', next_attempt_at = ?,
                lease_owner = NULL, lease_expires_at = NULL,
                error_code = 'worker_lease_expired'
            WHERE status = 'in_flight' AND lease_expires_at <= ?
            """,
            (now_iso, now_iso),
        )
        row = connection.execute(
            """
            SELECT * FROM earth_outbound_batches
            WHERE destination_service_id = ?
              AND status IN ('pending', 'retry_wait')
              AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
            ORDER BY created_at, delivery_batch_id
            LIMIT 1
            """,
            (settings.peer_service_id, now_iso),
        ).fetchone()
        if row is None:
            connection.commit()
            return None
        connection.execute(
            """
            UPDATE earth_outbound_batches
            SET status = 'in_flight', attempt_count = attempt_count + 1,
                last_attempt_at = ?, next_attempt_at = NULL,
                lease_owner = ?, lease_expires_at = ?
            WHERE delivery_batch_id = ?
            """,
            (now_iso, worker_id, lease_expiry, row["delivery_batch_id"]),
        )
        claimed = connection.execute(
            "SELECT * FROM earth_outbound_batches WHERE delivery_batch_id = ?",
            (row["delivery_batch_id"],),
        ).fetchone()
        connection.commit()
        return claimed
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


def _schedule_retry(
    connection: sqlite3.Connection,
    settings: EarthSyncSettings,
    *,
    batch_id: str,
    worker_id: str,
    attempt_count: int,
    error_code: str,
    now: datetime,
) -> None:
    if settings.retry_base_seconds is None or settings.retry_max_seconds is None:
        raise EarthSyncProtocolError("A política de retry onboard não está configurada.")
    exponent = min(max(attempt_count - 1, 0), 62)
    delay_seconds = min(
        settings.retry_base_seconds * (2**exponent),
        settings.retry_max_seconds,
    )
    next_attempt = (now + timedelta(seconds=delay_seconds)).astimezone(timezone.utc)
    with connection:
        connection.execute(
            """
            UPDATE earth_outbound_batches
            SET status = 'retry_wait', next_attempt_at = ?,
                lease_owner = NULL, lease_expires_at = NULL, error_code = ?
            WHERE delivery_batch_id = ? AND status = 'in_flight'
              AND lease_owner = ?
            """,
            (next_attempt.isoformat(), error_code, batch_id, worker_id),
        )


def _apply_receipt(
    connection: sqlite3.Connection,
    settings: EarthSyncSettings,
    *,
    row: sqlite3.Row,
    worker_id: str,
    http_status: int,
    receipt_token: str,
    now: datetime,
) -> str:
    payload_json = row["payload_json"]
    payload_hash = payload_digest(payload_json)
    payload = json.loads(payload_json)
    expected_ids = {
        str(item["reading_id"])
        for item in payload["items"]
    }
    receipt = verify_receipt_token(
        settings,
        token=receipt_token,
        delivery_batch_id=row["delivery_batch_id"],
        payload_sha256=payload_hash,
        expected_reading_ids=expected_ids,
    )
    receipt_status = receipt["status"]
    if receipt_status in {"persisted", "already_persisted"} and http_status != 200:
        raise EarthSyncProtocolError("O código HTTP não corresponde ao recibo de sucesso.")
    if receipt_status == "conflict_isolated" and http_status != 409:
        raise EarthSyncProtocolError("O código HTTP não corresponde ao recibo de conflito.")
    if receipt_status == "rejected_permanent" and http_status != 422:
        raise EarthSyncProtocolError("O código HTTP não corresponde ao recibo de rejeição.")
    status_by_receipt = {
        "persisted": "acknowledged_durable",
        "already_persisted": "acknowledged_durable",
        "rejected_permanent": "rejected_permanent",
        "conflict_isolated": "conflict_isolated",
    }
    final_status = status_by_receipt[receipt_status]
    acknowledged_at = (
        receipt["recorded_at"]
        if final_status == "acknowledged_durable"
        else None
    )
    with connection:
        cursor = connection.execute(
            """
            UPDATE earth_outbound_batches
            SET status = ?, receipt_json = ?, acknowledged_at = ?,
                lease_owner = NULL, lease_expires_at = NULL,
                next_attempt_at = NULL, error_code = ?
            WHERE delivery_batch_id = ? AND status = 'in_flight'
              AND lease_owner = ?
            """,
            (
                final_status,
                receipt_token,
                acknowledged_at,
                (
                    None
                    if final_status == "acknowledged_durable"
                    else receipt.get("result_code")
                ),
                row["delivery_batch_id"],
                worker_id,
            ),
        )
        if cursor.rowcount != 1:
            raise EarthSyncProtocolError(
                "O worker perdeu a lease antes de persistir o resultado."
            )
    return final_status


def process_due_outbox_batches(
    connection: sqlite3.Connection,
    settings: EarthSyncSettings,
    *,
    worker_id: str | None = None,
    now_provider=None,
) -> EarthSyncWorkerResult:
    if settings.role != "onboard":
        raise EarthSyncProtocolError("Só o serviço onboard pode executar o worker.")
    worker = worker_id or str(uuid4())
    clock = now_provider or (lambda: datetime.now(timezone.utc))
    attempted = acknowledged = rejected = conflicts = retry_scheduled = 0
    while True:
        now = clock()
        row = _claim_next_due_batch(
            connection,
            settings,
            worker_id=worker,
            now=now,
        )
        if row is None:
            break
        attempted += 1
        try:
            digest = payload_digest(row["payload_json"])
            if digest != row["payload_sha256"]:
                raise EarthSyncProtocolError("O hash persistido da outbox não corresponde.")
            http_status, receipt_token = _send_batch(
                settings,
                payload_json=row["payload_json"],
                payload_sha256=digest,
            )
            final_status = _apply_receipt(
                connection,
                settings,
                row=row,
                worker_id=worker,
                http_status=http_status,
                receipt_token=receipt_token,
                now=clock(),
            )
        except (EarthSyncProtocolError, OSError, ValueError, jwt.InvalidTokenError):
            _schedule_retry(
                connection,
                settings,
                batch_id=row["delivery_batch_id"],
                worker_id=worker,
                attempt_count=row["attempt_count"],
                error_code="delivery_or_receipt_validation_failed",
                now=clock(),
            )
            retry_scheduled += 1
            continue
        if final_status == "acknowledged_durable":
            acknowledged += 1
        elif final_status == "rejected_permanent":
            rejected += 1
        else:
            conflicts += 1
    return EarthSyncWorkerResult(
        attempted=attempted,
        acknowledged=acknowledged,
        rejected=rejected,
        conflicts=conflicts,
        retry_scheduled=retry_scheduled,
    )


def run_worker_once() -> EarthSyncWorkerResult:
    settings = load_earth_sync_settings()
    if settings.role != "onboard":
        raise EarthSyncConfigurationError(
            "EARTH_SYNC_ROLE tem de ser 'onboard' para executar o worker."
        )
    initialize_database()
    with closing(connect_database()) as connection:
        return process_due_outbox_batches(connection, settings)
