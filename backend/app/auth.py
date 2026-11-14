from dataclasses import dataclass
from datetime import datetime, timezone
import math
import sqlite3
from typing import Annotated, Literal

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidKeyError, InvalidTokenError

from app.database import get_connection
from app.identity_bootstrap import MissionIdentityBootstrap
from app.mission_identity import ActorType, IdentityState, MissionState
from app.provisioning import (
    MissionProvisioningError,
    load_provisioned_mission_configuration,
)


@dataclass(frozen=True)
class Principal:
    subject: str
    actor_type: Literal["user", "device"]
    astronaut_ids: frozenset[str]
    permissions: frozenset[str]


bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _claim_time(claims: dict[str, object], name: str) -> datetime:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _unauthorized(f"A claim temporal {name} é inválida.")
    try:
        if not math.isfinite(value):
            raise _unauthorized(f"A claim temporal {name} é inválida.")
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise _unauthorized(f"A claim temporal {name} é inválida.") from error


def get_current_principal(
    request: Request,
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
) -> Principal:
    if credentials is None:
        raise _unauthorized("É necessário um token Bearer.")

    bootstrap: MissionIdentityBootstrap | None = getattr(
        request.app.state,
        "identity_bootstrap",
        None,
    )
    if bootstrap is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="O bootstrap da identidade da missão não está configurado.",
        )

    now = datetime.now(timezone.utc)
    try:
        configuration = load_provisioned_mission_configuration(
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

    service_id = bootstrap.onboard_token_verifier.onboard_service_id(configuration)
    onboard_service = next(
        identity
        for identity in configuration.identities
        if identity.identity_id == service_id
    )
    try:
        header = jwt.get_unverified_header(credentials.credentials)
    except (InvalidTokenError, TypeError, ValueError) as error:
        raise _unauthorized("Token inválido.") from error

    if (
        set(header) != {"alg", "kid", "typ"}
        or header.get("alg") != "RS256"
        or header.get("kid") != bootstrap.onboard_token_verifier.key_id
        or header.get("typ") != "JWT"
    ):
        raise _unauthorized("O cabeçalho do token não é permitido.")

    try:
        claims = jwt.decode(
            credentials.credentials,
            bootstrap.onboard_token_verifier.public_key_pem,
            algorithms=["RS256"],
            issuer=service_id,
            audience=bootstrap.onboard_token_verifier.audience,
            options={
                "require": [
                    "sub",
                    "iss",
                    "aud",
                    "iat",
                    "nbf",
                    "exp",
                    "jti",
                    "mission_id",
                    "actor_type",
                    "astronaut_ids",
                    "permissions",
                ]
            },
        )
    except InvalidKeyError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A chave onboard de validação não é válida.",
        ) from error
    except InvalidTokenError as error:
        raise _unauthorized("Token inválido ou expirado.") from error

    if set(claims) != {
        "sub",
        "iss",
        "aud",
        "iat",
        "nbf",
        "exp",
        "jti",
        "mission_id",
        "actor_type",
        "astronaut_ids",
        "permissions",
    }:
        raise _unauthorized("O token contém claims não permitidas.")

    subject = claims.get("sub")
    token_id = claims.get("jti")
    actor_type = claims.get("actor_type")
    mission_id = claims.get("mission_id")
    astronaut_ids = claims.get("astronaut_ids")
    permissions = claims.get("permissions")
    if (
        not isinstance(subject, str)
        or not subject
        or not isinstance(token_id, str)
        or not token_id
        or not isinstance(actor_type, str)
        or actor_type not in {ActorType.USER.value, ActorType.DEVICE.value}
        or mission_id != configuration.mission.mission_id
        or not isinstance(astronaut_ids, list)
        or any(not isinstance(item, str) or not item for item in astronaut_ids)
        or len(astronaut_ids) != len(set(astronaut_ids))
        or not isinstance(permissions, list)
        or any(not isinstance(item, str) or not item for item in permissions)
        or len(permissions) != len(set(permissions))
    ):
        raise _unauthorized("As claims de identidade do token são inválidas.")

    if (
        configuration.mission.state != MissionState.ACTIVE
        or not configuration.mission.valid_from <= now < configuration.mission.expires_at
        or onboard_service.state != IdentityState.ACTIVE
        or not onboard_service.valid_from <= now < onboard_service.expires_at
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A missão ou o serviço a bordo não está ativo e dentro da validade.",
        )

    identity = next(
        (item for item in configuration.identities if item.identity_id == subject),
        None,
    )
    expected_actor_type = ActorType(actor_type)
    if (
        identity is None
        or identity.actor_type != expected_actor_type
        or identity.state != IdentityState.ACTIVE
        or not identity.valid_from <= now < identity.expires_at
    ):
        raise _unauthorized("A identidade não está ativa ou provisionada para a missão.")

    token_permissions = frozenset(permissions)
    token_astronaut_ids = frozenset(astronaut_ids)
    if (
        not token_permissions <= identity.permissions
        or not token_astronaut_ids <= identity.astronaut_ids
    ):
        raise _unauthorized("O token excede as permissões da identidade provisionada.")

    issued_at = _claim_time(claims, "iat")
    not_before = _claim_time(claims, "nbf")
    expires_at = _claim_time(claims, "exp")
    if not issued_at <= not_before <= now < expires_at:
        raise _unauthorized("A validade temporal do token é inválida.")
    permitted_by_delegation = any(
        delegation.permits_token(
            mission_id=configuration.mission.mission_id,
            actor_type=expected_actor_type,
            permissions=token_permissions,
            astronaut_ids=token_astronaut_ids,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        for delegation in configuration.delegations
    )
    if not permitted_by_delegation:
        raise _unauthorized("O token não está coberto por uma delegação ativa.")

    try:
        access_token_record = connection.execute(
            "SELECT revoked_at FROM onboard_access_tokens WHERE jti = ?",
            (token_id,),
        ).fetchone()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Não foi possível consultar o estado local da credencial.",
        ) from error
    if access_token_record is None or access_token_record["revoked_at"] is not None:
        raise _unauthorized("O token foi revogado ou não está registado localmente.")

    validated_actor_type: Literal["user", "device"]
    if actor_type == ActorType.USER.value:
        validated_actor_type = "user"
    else:
        validated_actor_type = "device"
    return Principal(
        subject=subject,
        actor_type=validated_actor_type,
        astronaut_ids=token_astronaut_ids,
        permissions=token_permissions,
    )


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]


def require_permission(principal: Principal, permission: str) -> None:
    if permission not in principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="O token não tem a permissão necessária.",
        )


def require_astronaut_scope(principal: Principal, astronaut_id: str) -> None:
    if astronaut_id not in principal.astronaut_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="O token não tem acesso a este astronauta.",
        )
