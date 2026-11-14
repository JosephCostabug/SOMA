import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.identity_bootstrap import OnboardTokenVerifier
from app.mission_identity import (
    ActorType,
    IdentityState,
    MissionIdentityConfiguration,
    MissionState,
)


class CredentialIssueError(ValueError):
    pass


class RefreshTokenError(ValueError):
    pass


class RefreshTokenReuseError(RefreshTokenError):
    pass


@dataclass(frozen=True)
class IssuedCredentials:
    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime


class OnboardTokenService:
    """Issue scoped access tokens and one-time rotating opaque refresh tokens."""

    def __init__(
        self,
        *,
        private_key_pem: str,
        key_id: str,
        verifier: OnboardTokenVerifier,
    ) -> None:
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode("ascii"),
                password=None,
            )
        except (ValueError, TypeError, UnicodeEncodeError) as error:
            raise CredentialIssueError("A chave privada onboard não é uma PEM válida.") from error
        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
            raise CredentialIssueError(
                "A chave privada onboard deve ser RSA de pelo menos 2048 bits."
            )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        if key_id != verifier.key_id or public_pem != verifier.public_key_pem:
            raise CredentialIssueError(
                "A chave privada não corresponde à chave pública onboard provisionada."
            )
        self._private_key = private_key
        self._key_id = key_id
        self._verifier = verifier

    def issue(
        self,
        connection: sqlite3.Connection,
        *,
        configuration: MissionIdentityConfiguration,
        subject: str,
        actor_type: ActorType,
        permissions: frozenset[str],
        astronaut_ids: frozenset[str],
        access_lifetime_seconds: int,
        now: datetime,
    ) -> IssuedCredentials:
        if connection.in_transaction:
            raise CredentialIssueError(
                "A emissão requer uma conexão sem transação ativa."
            )
        try:
            connection.execute("BEGIN IMMEDIATE")
            credentials = self._issue_with_family(
                connection,
                configuration=configuration,
                subject=subject,
                actor_type=actor_type,
                permissions=permissions,
                astronaut_ids=astronaut_ids,
                access_lifetime_seconds=access_lifetime_seconds,
                now=now,
                family_id=str(uuid4()),
            )
            connection.commit()
        except sqlite3.Error as error:
            if connection.in_transaction:
                connection.rollback()
            raise CredentialIssueError(
                "Não foi possível persistir a sessão de credenciais."
            ) from error
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        return credentials

    def refresh(
        self,
        connection: sqlite3.Connection,
        *,
        configuration: MissionIdentityConfiguration,
        refresh_token: str,
        access_lifetime_seconds: int,
        now: datetime,
    ) -> IssuedCredentials:
        current_time = _aware_utc(now)
        if connection.in_transaction:
            raise RefreshTokenError(
                "A renovação requer uma conexão sem transação ativa."
            )
        token_hash = _refresh_hash(refresh_token)
        reuse_detected = False
        issued: IssuedCredentials | None = None
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM onboard_refresh_sessions WHERE token_sha256 = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                raise RefreshTokenError("Refresh token desconhecido ou inválido.")
            if row["used_at"] is not None or row["revoked_at"] is not None:
                self._revoke_family(connection, row["family_id"], current_time)
                reuse_detected = row["used_at"] is not None
                connection.commit()
            elif datetime.fromisoformat(row["expires_at"]) <= current_time:
                connection.rollback()
                raise RefreshTokenError("Refresh token expirado.")
            else:
                permissions = frozenset(json.loads(row["permissions_json"]))
                astronaut_ids = frozenset(json.loads(row["astronaut_ids_json"]))
                identity = _active_identity(
                    configuration,
                    subject=row["subject"],
                    actor_type=ActorType(row["actor_type"]),
                    now=current_time,
                )
                if (
                    row["mission_id"] != configuration.mission.mission_id
                    or not permissions <= identity.permissions
                    or not astronaut_ids <= identity.astronaut_ids
                ):
                    self._revoke_family(connection, row["family_id"], current_time)
                    connection.commit()
                    raise RefreshTokenError(
                        "A identidade ou os escopos do refresh token já não são válidos."
                    )

                issued = self._issue_with_family(
                    connection,
                    configuration=configuration,
                    subject=row["subject"],
                    actor_type=ActorType(row["actor_type"]),
                    permissions=permissions,
                    astronaut_ids=astronaut_ids,
                    access_lifetime_seconds=access_lifetime_seconds,
                    now=current_time,
                    family_id=row["family_id"],
                    refresh_expiration=datetime.fromisoformat(row["expires_at"]),
                )
                connection.execute(
                    """
                    UPDATE onboard_refresh_sessions
                    SET used_at = ?
                    WHERE token_sha256 = ? AND used_at IS NULL AND revoked_at IS NULL
                    """,
                    (current_time.isoformat(), token_hash),
                )
                connection.commit()
        except sqlite3.Error as error:
            if connection.in_transaction:
                connection.rollback()
            raise RefreshTokenError("Não foi possível processar o refresh token.") from error
        except RefreshTokenReuseError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except RefreshTokenError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise

        if reuse_detected:
            raise RefreshTokenReuseError(
                "Refresh token reutilizado; toda a família foi revogada."
            )
        if issued is None:
            raise RefreshTokenError("Não foi possível completar a renovação.")
        return issued

    def revoke_family(
        self,
        connection: sqlite3.Connection,
        *,
        refresh_token: str,
        now: datetime,
    ) -> None:
        current_time = _aware_utc(now)
        if connection.in_transaction:
            raise RefreshTokenError(
                "A revogação requer uma conexão sem transação ativa."
            )
        try:
            with connection:
                row = connection.execute(
                    "SELECT family_id FROM onboard_refresh_sessions WHERE token_sha256 = ?",
                    (_refresh_hash(refresh_token),),
                ).fetchone()
                if row is None:
                    raise RefreshTokenError("Refresh token desconhecido ou inválido.")
                self._revoke_family(connection, row["family_id"], current_time)
        except sqlite3.Error as error:
            raise RefreshTokenError("Não foi possível revogar as credenciais.") from error

    def _issue_with_family(
        self,
        connection: sqlite3.Connection,
        *,
        configuration: MissionIdentityConfiguration,
        subject: str,
        actor_type: ActorType,
        permissions: frozenset[str],
        astronaut_ids: frozenset[str],
        access_lifetime_seconds: int,
        now: datetime,
        family_id: str,
        refresh_expiration: datetime | None = None,
    ) -> IssuedCredentials:
        current_time = _aware_utc(now).replace(microsecond=0)
        if (
            isinstance(access_lifetime_seconds, bool)
            or not isinstance(access_lifetime_seconds, int)
            or access_lifetime_seconds <= 0
        ):
            raise CredentialIssueError("A validade do token tem de ser positiva.")
        if configuration.mission.state != MissionState.ACTIVE:
            raise CredentialIssueError("A missão não está ativa.")
        if not configuration.mission.valid_from <= current_time < configuration.mission.expires_at:
            raise CredentialIssueError("A missão está fora da validade.")
        identity = _active_identity(
            configuration,
            subject=subject,
            actor_type=actor_type,
            now=current_time,
        )
        if not permissions or not permissions <= identity.permissions:
            raise CredentialIssueError(
                "As permissões solicitadas excedem ou não identificam a identidade."
            )
        if not astronaut_ids or not astronaut_ids <= identity.astronaut_ids:
            raise CredentialIssueError(
                "Os escopos solicitados excedem ou não identificam a identidade."
            )

        service = next(
            (
                item
                for item in configuration.identities
                if item.actor_type == ActorType.SERVICE
                and item.key_id == self._verifier.key_id
            ),
            None,
        )
        if (
            service is None
            or service.state != IdentityState.ACTIVE
            or not service.valid_from <= current_time < service.expires_at
        ):
            raise CredentialIssueError("O serviço emissor onboard não está ativo.")
        matching_delegation = next(
            (
                delegation
                for delegation in configuration.delegations
                if delegation.onboard_service_id == service.identity_id
                and delegation.onboard_key_id == self._key_id
                and delegation.permits_token(
                    mission_id=configuration.mission.mission_id,
                    actor_type=actor_type,
                    permissions=permissions,
                    astronaut_ids=astronaut_ids,
                    issued_at=current_time,
                    expires_at=current_time + timedelta(seconds=access_lifetime_seconds),
                )
            ),
            None,
        )
        if matching_delegation is None:
            raise CredentialIssueError(
                "A validade, as permissões ou os escopos excedem a delegação ativa."
            )

        access_expiration = current_time + timedelta(seconds=access_lifetime_seconds)
        actual_refresh_expiration = min(
            refresh_expiration or matching_delegation.expires_at,
            matching_delegation.expires_at,
            identity.expires_at,
            configuration.mission.expires_at,
        )
        if actual_refresh_expiration <= current_time:
            raise CredentialIssueError("A delegação não permite uma sessão renovável.")

        access_jti = str(uuid4())
        claims = {
            "sub": subject,
            "iss": service.identity_id,
            "aud": self._verifier.audience,
            "iat": int(current_time.timestamp()),
            "nbf": int(current_time.timestamp()),
            "exp": int(access_expiration.timestamp()),
            "jti": access_jti,
            "mission_id": configuration.mission.mission_id,
            "actor_type": actor_type.value,
            "astronaut_ids": sorted(astronaut_ids),
            "permissions": sorted(permissions),
        }
        access_token = jwt.encode(
            claims,
            self._private_key,
            algorithm="RS256",
            headers={"kid": self._key_id, "typ": "JWT"},
        )
        refresh_token = secrets.token_urlsafe(48)
        try:
            connection.execute(
                """
                INSERT INTO onboard_access_tokens (jti, family_id, expires_at)
                VALUES (?, ?, ?)
                """,
                (access_jti, family_id, access_expiration.isoformat()),
            )
            connection.execute(
                """
                INSERT INTO onboard_refresh_sessions (
                    token_sha256, family_id, mission_id, subject, actor_type,
                    permissions_json, astronaut_ids_json, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _refresh_hash(refresh_token),
                    family_id,
                    configuration.mission.mission_id,
                    subject,
                    actor_type.value,
                    json.dumps(sorted(permissions), separators=(",", ":")),
                    json.dumps(sorted(astronaut_ids), separators=(",", ":")),
                    actual_refresh_expiration.isoformat(),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise CredentialIssueError(
                "Não foi possível persistir a sessão de credenciais."
            ) from error
        return IssuedCredentials(
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_at=access_expiration,
            refresh_expires_at=actual_refresh_expiration,
        )

    @staticmethod
    def _revoke_family(
        connection: sqlite3.Connection,
        family_id: str,
        now: datetime,
    ) -> None:
        connection.execute(
            """
            UPDATE onboard_refresh_sessions
            SET revoked_at = COALESCE(revoked_at, ?)
            WHERE family_id = ?
            """,
            (now.isoformat(), family_id),
        )
        connection.execute(
            """
            UPDATE onboard_access_tokens
            SET revoked_at = COALESCE(revoked_at, ?)
            WHERE family_id = ?
            """,
            (now.isoformat(), family_id),
        )


def _active_identity(
    configuration: MissionIdentityConfiguration,
    *,
    subject: str,
    actor_type: ActorType,
    now: datetime,
):
    if configuration.mission.state != MissionState.ACTIVE:
        raise CredentialIssueError("A missão não está ativa.")
    identity = next(
        (item for item in configuration.identities if item.identity_id == subject),
        None,
    )
    if (
        identity is None
        or identity.actor_type != actor_type
        or identity.state != IdentityState.ACTIVE
        or not identity.valid_from <= now < identity.expires_at
    ):
        raise CredentialIssueError("A identidade não está ativa ou provisionada.")
    return identity


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CredentialIssueError("O instante tem de incluir fuso horário.")
    return value.astimezone(timezone.utc)


def _refresh_hash(token: str) -> str:
    if not token or len(token) > 512:
        raise RefreshTokenError("Refresh token desconhecido ou inválido.")
    try:
        encoded = token.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise RefreshTokenError("Refresh token desconhecido ou inválido.") from error
    return hashlib.sha256(encoded).hexdigest()
