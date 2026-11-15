import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Self

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.key_management import VerificationKeySet
from app.mission_identity import ActorType, MissionIdentityConfiguration
from app.schemas import MonitoringAlertRule


class IdentityBootstrapError(ValueError):
    pass


def read_protected_file(path: str | Path, *, max_bytes: int, label: str) -> bytes:
    protected_path = Path(path)
    if not protected_path.is_absolute():
        raise IdentityBootstrapError(f"O caminho de {label} tem de ser absoluto.")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        file_descriptor = os.open(protected_path, flags)
        with os.fdopen(file_descriptor, "rb") as protected_file:
            file_stat = os.fstat(protected_file.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise IdentityBootstrapError(f"O ficheiro de {label} tem de ser regular.")
            if file_stat.st_size > max_bytes:
                raise IdentityBootstrapError(f"O ficheiro de {label} excede o tamanho permitido.")
            if os.name == "posix":
                if file_stat.st_uid != os.geteuid() or file_stat.st_mode & 0o077:
                    raise IdentityBootstrapError(
                        f"O ficheiro de {label} deve pertencer à conta do serviço e "
                        "não permitir acesso a grupo/outros (chmod 600)."
                    )
            elif os.name == "nt":
                if getattr(file_stat, "st_file_attributes", 0) & 0x400:
                    raise IdentityBootstrapError(f"O ficheiro de {label} não pode ser reparse point.")
                _validate_windows_file_acl(protected_file.fileno())
            content = protected_file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise IdentityBootstrapError(f"O ficheiro de {label} excede o tamanho permitido.")
        return content
    except IdentityBootstrapError:
        raise
    except OSError as error:
        raise IdentityBootstrapError(f"Não foi possível ler o ficheiro protegido de {label}.") from error


def _validate_windows_file_acl(file_descriptor: int) -> None:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    owner_sid = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    result = advapi32.GetSecurityInfo(
        msvcrt.get_osfhandle(file_descriptor),
        1,
        0x1 | 0x4,
        ctypes.byref(owner_sid),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if result != 0:
        raise IdentityBootstrapError("Não foi possível verificar a ACL do bootstrap.")

    token = wintypes.HANDLE()
    token_user_buffer = None
    try:
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0008,
            ctypes.byref(token),
        ):
            raise IdentityBootstrapError("Não foi possível identificar o utilizador do serviço.")
        required_size = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            1,
            None,
            0,
            ctypes.byref(required_size),
        )
        token_user_buffer = ctypes.create_string_buffer(required_size.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            token_user_buffer,
            required_size,
            ctypes.byref(required_size),
        ):
            raise IdentityBootstrapError("Não foi possível identificar o utilizador do serviço.")
        current_user_sid = ctypes.cast(
            token_user_buffer,
            ctypes.POINTER(ctypes.c_void_p),
        ).contents.value

        def sid_string(sid: ctypes.c_void_p) -> str:
            string_sid = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(string_sid)):
                raise IdentityBootstrapError("A ACL do bootstrap contém um SID inválido.")
            try:
                return string_sid.value
            finally:
                kernel32.LocalFree(string_sid)

        if not owner_sid.value or sid_string(owner_sid) != sid_string(
            ctypes.c_void_p(current_user_sid)
        ):
            raise IdentityBootstrapError(
                "O ficheiro de bootstrap tem de pertencer à conta do serviço."
            )
        if not dacl.value:
            raise IdentityBootstrapError("O bootstrap não pode ter uma ACL permissiva.")

        class AclSizeInformation(ctypes.Structure):
            _fields_ = [
                ("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD),
            ]

        acl_info = AclSizeInformation()
        if not advapi32.GetAclInformation(
            dacl,
            ctypes.byref(acl_info),
            ctypes.sizeof(acl_info),
            2,
        ):
            raise IdentityBootstrapError("Não foi possível ler a ACL do bootstrap.")

        trusted_sids = {
            sid_string(owner_sid),
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-3-4",
        }
        for ace_index in range(acl_info.AceCount):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, ace_index, ctypes.byref(ace)):
                raise IdentityBootstrapError("Não foi possível ler uma entrada da ACL.")
            ace_header = ctypes.string_at(ace, 4)
            ace_type = ace_header[0]
            if ace_type == 0:
                allowed_sid = ctypes.c_void_p(ace.value + 8)
                if sid_string(allowed_sid) not in trusted_sids:
                    raise IdentityBootstrapError(
                        "A ACL do bootstrap concede acesso a uma conta não confiável."
                    )
            elif ace_type not in {1, 2, 3, 6, 7, 10}:
                raise IdentityBootstrapError(
                    "A ACL do bootstrap contém uma entrada de acesso não suportada."
                )
    finally:
        if token.value:
            kernel32.CloseHandle(token)
        if security_descriptor.value:
            kernel32.LocalFree(security_descriptor)


class OnboardTokenVerifier(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(min_length=1, max_length=100)
    public_key_pem: str = Field(min_length=1)
    audience: str = Field(min_length=1, max_length=200)

    def validate_for(self, configuration: MissionIdentityConfiguration) -> None:
        services = [
            identity
            for identity in configuration.identities
            if identity.actor_type == ActorType.SERVICE and identity.key_id == self.key_id
        ]
        if len(services) != 1:
            raise ValueError(
                "A chave de token tem de corresponder a um único serviço a bordo."
            )
        service = services[0]
        try:
            key = serialization.load_pem_public_key(self.public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError) as error:
            raise ValueError("A chave de token onboard não é uma PEM válida.") from error
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise ValueError("A chave de token onboard deve ser RSA de pelo menos 2048 bits.")
        fingerprint = hashlib.sha256(
            key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        if service.public_key_thumbprint != f"sha256:{fingerprint}":
            raise ValueError(
                "A impressão digital da chave de token não corresponde à identidade onboard."
            )

    def onboard_service_id(self, configuration: MissionIdentityConfiguration) -> str:
        service = next(
            identity
            for identity in configuration.identities
            if identity.actor_type == ActorType.SERVICE and identity.key_id == self.key_id
        )
        return service.identity_id


class AuthenticationPublicKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_id: str = Field(min_length=1, max_length=200)
    key_id: str = Field(min_length=1, max_length=100)
    public_key_pem: str = Field(min_length=1, max_length=8192)


class MissionIdentityBootstrap(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    base_configuration: MissionIdentityConfiguration
    ground_keys: VerificationKeySet
    onboard_token_verifier: OnboardTokenVerifier
    initial_signed_delegation_tokens: tuple[str, ...] = Field(min_length=1)
    monitoring_alert_rules: tuple[MonitoringAlertRule, ...] = Field(
        default=(),
        max_length=100,
    )
    authentication_keys: tuple[AuthenticationPublicKey, ...] = Field(
        default=(),
        max_length=500,
    )

    @model_validator(mode="after")
    def validate_bootstrap(self) -> Self:
        if self.base_configuration.delegations:
            raise ValueError(
                "A configuração de bootstrap não pode conter delegações não verificadas."
            )
        if (
            self.ground_keys.issuer != self.base_configuration.ground_authority.issuer
            or self.ground_keys.trusted_key_ids
            != self.base_configuration.ground_authority.trusted_key_ids
        ):
            raise ValueError(
                "As chaves de bootstrap não correspondem à autoridade terrestre."
            )
        if any(not token for token in self.initial_signed_delegation_tokens):
            raise ValueError("Os tokens de delegação iniciais não podem estar vazios.")
        rule_ids = [rule.rule_id for rule in self.monitoring_alert_rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Os identificadores das regras de alerta têm de ser únicos.")
        authentication_identity_ids = [
            key.identity_id for key in self.authentication_keys
        ]
        if len(authentication_identity_ids) != len(set(authentication_identity_ids)):
            raise ValueError("Cada identidade só pode ter uma chave de autenticação ativa.")
        identities = {
            identity.identity_id: identity
            for identity in self.base_configuration.identities
        }
        for authentication_key in self.authentication_keys:
            identity = identities.get(authentication_key.identity_id)
            if (
                identity is None
                or identity.actor_type not in {ActorType.USER, ActorType.DEVICE}
                or identity.key_id != authentication_key.key_id
                or identity.public_key_thumbprint is None
            ):
                raise ValueError(
                    "A chave de autenticação tem de corresponder a uma identidade "
                    "de utilizador/dispositivo provisionada."
                )
            try:
                key = serialization.load_pem_public_key(
                    authentication_key.public_key_pem.encode("ascii")
                )
            except (ValueError, TypeError, UnicodeEncodeError) as error:
                raise ValueError("Uma chave de autenticação não é uma PEM válida.") from error
            if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
                raise ValueError(
                    "As chaves de autenticação têm de ser RSA de pelo menos 2048 bits."
                )
            fingerprint = hashlib.sha256(
                key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest()
            if identity.public_key_thumbprint != f"sha256:{fingerprint}":
                raise ValueError(
                    "A chave de autenticação não corresponde à impressão digital "
                    "da identidade provisionada."
                )
        self.onboard_token_verifier.validate_for(self.base_configuration)
        return self


def load_identity_bootstrap(path: str | Path) -> MissionIdentityBootstrap:
    try:
        content = read_protected_file(
            path,
            max_bytes=1_048_576,
            label="bootstrap",
        )
        data = json.loads(content)
        return MissionIdentityBootstrap.model_validate(data)
    except IdentityBootstrapError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise IdentityBootstrapError(
            "Não foi possível carregar uma configuração de bootstrap válida."
        ) from error
