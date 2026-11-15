import os
import ssl
import sys

from app.earth_sync import (
    EarthSyncConfigurationError,
    load_earth_sync_settings,
    validate_tls_identity,
)
from app.identity_bootstrap import read_protected_file


def _required_path(name: str, *, label: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise EarthSyncConfigurationError(f"{name} não foi configurado.")
    path = value.strip()
    read_protected_file(path, max_bytes=1_048_576, label=label)
    return path


def _required_port() -> int:
    raw_port = os.environ.get("EARTH_SYNC_BIND_PORT")
    if raw_port is None:
        raise EarthSyncConfigurationError("EARTH_SYNC_BIND_PORT não foi configurado.")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise EarthSyncConfigurationError(
            "EARTH_SYNC_BIND_PORT tem de ser um inteiro entre 1 e 65535."
        ) from error
    if not 1 <= port <= 65535:
        raise EarthSyncConfigurationError(
            "EARTH_SYNC_BIND_PORT tem de ser um inteiro entre 1 e 65535."
        )
    return port


def main() -> int:
    try:
        settings = load_earth_sync_settings()
        if settings.role != "earth":
            raise EarthSyncConfigurationError(
                "EARTH_SYNC_ROLE tem de ser 'earth' para executar o receptor."
            )
        host = os.environ.get("EARTH_SYNC_BIND_HOST")
        if host is None or not host.strip():
            raise EarthSyncConfigurationError("EARTH_SYNC_BIND_HOST não foi configurado.")
        server_cert_path = _required_path(
            "EARTH_SYNC_SERVER_CERT_PATH",
            label="certificado TLS do receptor terrestre",
        )
        server_key_path = _required_path(
            "EARTH_SYNC_SERVER_KEY_PATH",
            label="chave privada TLS do receptor terrestre",
        )
        client_ca_path = _required_path(
            "EARTH_SYNC_CLIENT_CA_BUNDLE_PATH",
            label="CA de clientes mTLS do receptor terrestre",
        )
        validate_tls_identity(
            server_cert_path,
            server_key_path,
            settings.signing_key,
        )
        bind_port = _required_port()
    except EarthSyncConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 2

    import uvicorn

    os.environ["EARTH_SYNC_MTLS_ENFORCED"] = "1"
    uvicorn.run(
        "app.main:app",
        host=host.strip(),
        port=bind_port,
        ssl_certfile=server_cert_path,
        ssl_keyfile=server_key_path,
        ssl_ca_certs=client_ca_path,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
