import os
from dataclasses import dataclass
from typing import Annotated, Literal

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidKeyError, InvalidTokenError


@dataclass(frozen=True)
class Principal:
    subject: str
    actor_type: Literal["user", "device"]
    astronaut_ids: frozenset[str]
    permissions: frozenset[str]


bearer_scheme = HTTPBearer(auto_error=False)


def get_current_principal(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
) -> Principal:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="É necessário um token Bearer válido.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    public_key = os.environ.get("AUTH_PUBLIC_KEY", "").replace("\\n", "\n")
    issuer = os.environ.get("AUTH_ISSUER")
    audience = os.environ.get("AUTH_AUDIENCE")
    if not public_key or not issuer or not audience:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A validação de identidade não está configurada.",
        )

    try:
        claims = jwt.decode(
            credentials.credentials,
            public_key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            options={
                "require": [
                    "sub",
                    "exp",
                    "iat",
                    "actor_type",
                    "astronaut_ids",
                    "permissions",
                ]
            },
        )
    except InvalidKeyError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A chave de validação de identidade não é válida.",
        ) from error
    except InvalidTokenError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error

    subject = claims.get("sub")
    actor_type = claims.get("actor_type")
    astronaut_ids = claims.get("astronaut_ids")
    permissions = claims.get("permissions")
    if (
        not isinstance(subject, str)
        or not subject
        or not isinstance(actor_type, str)
        or actor_type not in {"user", "device"}
        or not isinstance(astronaut_ids, list)
        or any(not isinstance(item, str) or not item for item in astronaut_ids)
        or not isinstance(permissions, list)
        or any(not isinstance(item, str) or not item for item in permissions)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="As permissões do token são inválidas.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    validated_actor_type: Literal["user", "device"]
    if actor_type == "user":
        validated_actor_type = "user"
    else:
        validated_actor_type = "device"

    return Principal(
        subject=subject,
        actor_type=validated_actor_type,
        astronaut_ids=frozenset(astronaut_ids),
        permissions=frozenset(permissions),
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
