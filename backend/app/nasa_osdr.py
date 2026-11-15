from datetime import date, datetime, timezone
import csv
import hashlib
import io
import json
import math
import re
from typing import Literal, Self
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.error import URLError
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from pydantic import BaseModel, ConfigDict


_OSDR_API_BASE_URL = "https://visualization.osdr.nasa.gov/biodata/api/v2/dataset"
_OSDR_QUERY_BASE_URL = "https://visualization.osdr.nasa.gov/biodata/api/v2/query/datasets/"
_OSDR_STUDY_BASE_URL = "https://osdr.nasa.gov/bio/repo/data/studies"
_MAX_RESPONSE_BYTES = 2_000_000
_MAX_PUBLIC_CMP_BYTES = 100_000
_REQUEST_TIMEOUT_SECONDS = 10
_ACCESSION_PATTERN = re.compile(r"OSD-[0-9]+")
_INSPIRATION4_CMP_ACCESSION = "OSD-575"
_INSPIRATION4_CMP_FILE = "LSDS-8_Comprehensive_Metabolic_Panel_CMP_TRANSFORMED.csv"
_INSPIRATION4_CMP_METRICS = (
    ("glucose", "Glicose sérica", "mg/dL", "glucose_value_milligram_per_deciliter"),
    ("albumin", "Albumina sérica", "g/dL", "albumin_value_gram_per_deciliter"),
    ("creatinine", "Creatinina sérica", "mg/dL", "creatinine_value_milligram_per_deciliter"),
    ("alt", "ALT", "U/L", "alt_value_units_per_liter"),
)


class OSDRMetadataError(Exception):
    pass


class OSDRStudyMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    accession: str
    title: str
    project_identifier: str | None
    mission_name: str | None
    mission_start_date: date | None
    mission_end_date: date | None
    material_type: str | None
    identifiers: tuple[str, ...]
    assay_technology_types: tuple[str, ...]
    assay_platforms: tuple[str, ...]
    source_api_url: str
    study_url: str
    citation: str
    retrieved_at: datetime
    license_status: Literal["not_verified"] = "not_verified"
    files_downloaded: bool = False


class OSDRDatasetSearchHit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    accession: str
    organism: str | None
    spaceflight_phase: str | None


class OSDRDatasetSearchResults(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[OSDRDatasetSearchHit, ...]
    filters: dict[str, str]
    retrieved_at: datetime


class OSDRDatasetFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    accession: str
    file_name: str
    file_format: str
    source_api_url: str
    download_url: str
    file_size_bytes: int | None
    restricted: bool | None
    remote_updated_at: datetime | None
    retrieved_at: datetime

    @classmethod
    def from_metadata(
        cls,
        *,
        accession: str,
        file_name: str,
        source_api_url: str,
        download_url: str,
        metadata: dict[str, object],
    ) -> Self:
        file_size = metadata.get("file_size")
        if file_size is not None and (
            isinstance(file_size, bool)
            or not isinstance(file_size, int)
            or file_size < 0
        ):
            raise OSDRMetadataError("O tamanho do ficheiro OSDR é inválido.")
        restricted = metadata.get("restricted")
        if restricted is not None and not isinstance(restricted, bool):
            raise OSDRMetadataError("O estado de acesso do ficheiro OSDR é inválido.")
        updated = metadata.get("date_updated")
        remote_updated_at = None
        if updated is not None:
            if isinstance(updated, bool) or not isinstance(updated, (int, float)):
                raise OSDRMetadataError("A data do ficheiro OSDR é inválida.")
            try:
                remote_updated_at = datetime.fromtimestamp(updated, tz=timezone.utc)
            except (OverflowError, OSError, ValueError) as error:
                raise OSDRMetadataError("A data do ficheiro OSDR é inválida.") from error
        return cls(
            accession=accession,
            file_name=file_name,
            file_format=file_name.rsplit(".", 1)[-1].lower()
            if "." in file_name
            else "unknown",
            source_api_url=source_api_url,
            download_url=download_url,
            file_size_bytes=file_size,
            restricted=restricted,
            remote_updated_at=remote_updated_at,
            retrieved_at=datetime.now(timezone.utc),
        )


class OSDRPublicSummaryPoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    timepoint: str
    mean: float | None
    observed_min: float | None
    observed_max: float | None
    sample_count: int
    missing_count: int


class OSDRPublicSummaryMetric(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: Literal["glucose", "albumin", "creatinine", "alt"]
    label: str
    unit: str
    source_column: str
    points: tuple[OSDRPublicSummaryPoint, ...]


class OSDRPublicInspiration4Dataset(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    accession: Literal["OSD-575"] = "OSD-575"
    title: str
    study_url: str
    source_api_url: str
    source_file_name: str
    source_file_url: str
    source_file_updated_at: datetime | None
    source_file_size_bytes: int
    source_file_sha256: str
    record_count: int
    sample_count: int
    retrieved_at: datetime
    restricted: Literal[False] = False
    license_status: Literal["not_verified"] = "not_verified"
    citation: str
    metrics: tuple[OSDRPublicSummaryMetric, ...]


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        _request,
        _response,
        _code,
        _message,
        _headers,
        _new_url,
    ):
        _ = (_request, _response, _code, _message, _headers, _new_url)
        return None


_OPENER = build_opener(_RejectRedirects)


class _ValidateDownloadRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request,
        response,
        code,
        message,
        headers,
        new_url,
    ):
        parsed = urlparse(new_url)
        hostname = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or not (
                hostname == "osdr.nasa.gov"
                or hostname == "genelab-alsda-repo-prod.s3.amazonaws.com"
            )
        ):
            raise OSDRMetadataError("O redirecionamento do ficheiro OSDR não é permitido.")
        return super().redirect_request(request, response, code, message, headers, new_url)


_DOWNLOAD_OPENER = build_opener(_ValidateDownloadRedirects)


def _request_json(url: str) -> object:
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "visualization.osdr.nasa.gov"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
    ):
        raise OSDRMetadataError("A URL da API OSDR não é permitida.")
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "space-health-backend"},
    )
    try:
        with _OPENER.open(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except (OSError, URLError, TimeoutError) as error:
        raise OSDRMetadataError("Não foi possível consultar a API NASA OSDR.") from error
    if len(body) > _MAX_RESPONSE_BYTES:
        raise OSDRMetadataError("A resposta NASA OSDR excede o limite permitido.")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OSDRMetadataError("A resposta NASA OSDR não contém JSON válido.") from error


def search_osdr_datasets(
    *,
    organism: str | None = None,
    spaceflight_phase: str | None = None,
) -> tuple[OSDRDatasetSearchHit, ...]:
    filters = {
        "study.characteristics.organism": organism,
        "study.factor value.spaceflight": spaceflight_phase,
    }
    active_filters = {
        key: value.strip()
        for key, value in filters.items()
        if value is not None and value.strip()
    }
    if not active_filters:
        raise ValueError("É necessário indicar pelo menos um filtro de descoberta OSDR.")

    field_names = (
        "study.characteristics.organism",
        "study.factor value.spaceflight",
    )
    query = [("format", "json.records"), *active_filters.items()]
    query_string = urlencode(query)
    unfiltered_fields = [
        quote(field, safe="")
        for field in field_names
        if field not in active_filters
    ]
    if unfiltered_fields:
        query_string = "&".join((query_string, *unfiltered_fields))
    payload = _request_json(f"{_OSDR_QUERY_BASE_URL}?{query_string}")
    if not isinstance(payload, list):
        raise OSDRMetadataError("A resposta de descoberta NASA OSDR é inválida.")
    hits: dict[str, OSDRDatasetSearchHit] = {}
    for row in payload:
        if not isinstance(row, dict):
            raise OSDRMetadataError("Um resultado de descoberta OSDR é inválido.")
        accession = row.get("id.accession")
        organism_value = row.get("study.characteristics.organism")
        phase_value = row.get("study.factor value.spaceflight")
        if (
            not isinstance(accession, str)
            or _ACCESSION_PATTERN.fullmatch(accession) is None
            or (organism_value is not None and not isinstance(organism_value, str))
            or (phase_value is not None and not isinstance(phase_value, str))
        ):
            raise OSDRMetadataError("Os campos de um resultado OSDR são inválidos.")
        hits.setdefault(
            accession,
            OSDRDatasetSearchHit(
                accession=accession,
                organism=organism_value,
                spaceflight_phase=phase_value,
            ),
        )
    return tuple(hits.values())


def _optional_string(metadata: dict[str, object], key: str) -> str | None:
    value = metadata.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise OSDRMetadataError(f"O metadado OSDR '{key}' tem formato inválido.")
    return value


def _string_tuple(metadata: dict[str, object], key: str) -> tuple[str, ...]:
    value = metadata.get(key, [])
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise OSDRMetadataError(f"O metadado OSDR '{key}' tem formato inválido.")
    return tuple(value)


def _optional_date(value: object, key: str) -> date | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise OSDRMetadataError(f"A data OSDR '{key}' tem formato inválido.")
    try:
        return datetime.strptime(value, "%m/%d/%Y").date()
    except ValueError as error:
        raise OSDRMetadataError(
            f"A data OSDR '{key}' tem formato inválido."
        ) from error


def _metadata_from_response(accession: str, payload: object) -> OSDRStudyMetadata:
    if not isinstance(payload, dict) or not isinstance(payload.get(accession), dict):
        raise OSDRMetadataError("A resposta OSDR não contém o estudo solicitado.")
    study = payload[accession]
    metadata = study.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("accession") != accession:
        raise OSDRMetadataError("Os metadados OSDR não correspondem ao accession.")

    title = _optional_string(metadata, "study title")
    mission = metadata.get("mission", {})
    if not isinstance(mission, dict):
        raise OSDRMetadataError("Os metadados de missão OSDR têm formato inválido.")
    if title is None:
        raise OSDRMetadataError("O estudo OSDR não tem título.")

    api_url = f"{_OSDR_API_BASE_URL}/{accession}/"
    study_url = f"{_OSDR_STUDY_BASE_URL}/{accession}"
    return OSDRStudyMetadata(
        accession=accession,
        title=title,
        project_identifier=_optional_string(metadata, "project identifier"),
        mission_name=_optional_string(mission, "name"),
        mission_start_date=_optional_date(mission.get("start date"), "start date"),
        mission_end_date=_optional_date(mission.get("end date"), "end date"),
        material_type=_optional_string(metadata, "material type"),
        identifiers=_string_tuple(metadata, "identifiers"),
        assay_technology_types=_string_tuple(
            metadata, "study assay technology type"
        ),
        assay_platforms=_string_tuple(
            metadata, "study assay technology platform"
        ),
        source_api_url=api_url,
        study_url=study_url,
        citation=f"NASA OSDR, {accession}: {title}.",
        retrieved_at=datetime.now(timezone.utc),
    )


def fetch_osdr_study_metadata(accession: str) -> OSDRStudyMetadata:
    if _ACCESSION_PATTERN.fullmatch(accession) is None:
        raise ValueError("O accession OSDR tem de seguir o formato OSD-<número>.")

    payload = _request_json(f"{_OSDR_API_BASE_URL}/{accession}/")
    return _metadata_from_response(accession, payload)


def fetch_osdr_dataset_files(accession: str) -> tuple[OSDRDatasetFile, ...]:
    if _ACCESSION_PATTERN.fullmatch(accession) is None:
        raise ValueError("O accession OSDR tem de seguir o formato OSD-<número>.")
    payload = _request_json(f"{_OSDR_API_BASE_URL}/{accession}/files/")
    if not isinstance(payload, dict) or not isinstance(payload.get(accession), dict):
        raise OSDRMetadataError("A resposta OSDR não contém o inventário solicitado.")
    files = payload[accession].get("files")
    if not isinstance(files, dict):
        raise OSDRMetadataError("O inventário de ficheiros OSDR é inválido.")

    result: list[OSDRDatasetFile] = []
    for file_name, entry in files.items():
        if not isinstance(file_name, str) or not file_name or not isinstance(entry, dict):
            raise OSDRMetadataError("Uma entrada de ficheiro OSDR é inválida.")
        source_api_url = entry.get("REST_URL")
        download_url = entry.get("URL")
        if not isinstance(source_api_url, str) or not isinstance(download_url, str):
            raise OSDRMetadataError("Os links de um ficheiro OSDR são inválidos.")
        expected_api_url = (
            f"{_OSDR_API_BASE_URL}/{accession}/file/{quote(file_name, safe='')}/"
        )
        if source_api_url != expected_api_url or not _is_official_download_url(
            download_url,
            accession=accession,
            file_name=file_name,
        ):
            raise OSDRMetadataError("Os links de um ficheiro OSDR não correspondem.")
        result.append(
            OSDRDatasetFile(
                accession=accession,
                file_name=file_name,
                file_format=file_name.rsplit(".", 1)[-1].lower()
                if "." in file_name
                else "unknown",
                source_api_url=source_api_url,
                download_url=download_url,
                file_size_bytes=None,
                restricted=None,
                remote_updated_at=None,
                retrieved_at=datetime.now(timezone.utc),
            )
        )
    return tuple(sorted(result, key=lambda item: item.file_name))


def fetch_osdr_dataset_file_metadata(
    accession: str,
    file_name: str,
) -> tuple[OSDRDatasetFile, dict[str, object]]:
    file_entry = next(
        (
            item
            for item in fetch_osdr_dataset_files(accession)
            if item.file_name == file_name
        ),
        None,
    )
    if file_entry is None:
        raise OSDRMetadataError("O ficheiro não consta do inventário NASA OSDR.")
    payload = _request_json(file_entry.source_api_url)
    if not isinstance(payload, dict) or not isinstance(payload.get(accession), dict):
        raise OSDRMetadataError("A resposta OSDR não contém os metadados do ficheiro.")
    files = payload[accession].get("files")
    if not isinstance(files, dict) or not isinstance(files.get(file_name), dict):
        raise OSDRMetadataError("Os metadados do ficheiro OSDR são inválidos.")
    metadata = files[file_name].get("metadata")
    if not isinstance(metadata, dict) or metadata.get("file_name") != file_name:
        raise OSDRMetadataError("Os metadados do ficheiro OSDR não correspondem.")
    return (
        OSDRDatasetFile.from_metadata(
            accession=accession,
            file_name=file_name,
            source_api_url=file_entry.source_api_url,
            download_url=file_entry.download_url,
            metadata=metadata,
        ),
        metadata,
    )


def _is_official_download_url(
    value: str,
    *,
    accession: str,
    file_name: str,
) -> bool:
    parsed = urlparse(value)
    query = parse_qs(parsed.query)
    return (
        parsed.scheme == "https"
        and parsed.hostname == "osdr.nasa.gov"
        and parsed.port in (None, 443)
        and parsed.username is None
        and parsed.password is None
        and parsed.path == f"/geode-py/ws/studies/{accession}/download"
        and query.get("file") == [file_name]
    )


def download_osdr_csv(
    dataset_file: OSDRDatasetFile,
    *,
    max_bytes: int,
) -> bytes:
    if (
        dataset_file.file_format != "csv"
        or dataset_file.restricted is not False
        or dataset_file.file_size_bytes is None
        or dataset_file.file_size_bytes > max_bytes
    ):
        raise OSDRMetadataError(
            "O ficheiro não é CSV público com tamanho dentro do limite configurado."
        )
    request = Request(
        dataset_file.download_url,
        headers={"Accept": "text/csv,application/octet-stream"},
    )
    try:
        with _DOWNLOAD_OPENER.open(
            request,
            timeout=_REQUEST_TIMEOUT_SECONDS,
        ) as response:
            body = response.read(dataset_file.file_size_bytes + 1)
    except (OSError, URLError, TimeoutError) as error:
        raise OSDRMetadataError("Não foi possível descarregar o ficheiro NASA OSDR.") from error
    if len(body) != dataset_file.file_size_bytes:
        raise OSDRMetadataError(
            "O tamanho descarregado não corresponde aos metadados NASA OSDR."
        )
    return body


def parse_osdr_csv(content: bytes) -> tuple[dict[str, str], ...]:
    try:
        text = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text, newline=""))
        headers = reader.fieldnames
        if (
            headers is None
            or not headers
            or any(not header or not header.strip() for header in headers)
            or len(headers) != len(set(headers))
        ):
            raise OSDRMetadataError("O CSV NASA OSDR não tem cabeçalhos válidos.")

        rows: list[dict[str, str]] = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise OSDRMetadataError(
                    "Uma linha do CSV NASA OSDR não corresponde aos cabeçalhos."
                )
            rows.append({header: row[header] for header in headers})
    except (csv.Error, UnicodeDecodeError) as error:
        raise OSDRMetadataError("O ficheiro NASA OSDR não é um CSV UTF-8 válido.") from error
    if not rows:
        raise OSDRMetadataError("O ficheiro NASA OSDR não contém registos.")
    return tuple(rows)


def fetch_osdr_inspiration4_cmp_summary() -> OSDRPublicInspiration4Dataset:
    study = fetch_osdr_study_metadata(_INSPIRATION4_CMP_ACCESSION)
    dataset_file, _ = fetch_osdr_dataset_file_metadata(
        _INSPIRATION4_CMP_ACCESSION,
        _INSPIRATION4_CMP_FILE,
    )
    if dataset_file.restricted is not False:
        raise OSDRMetadataError(
            "O ficheiro NASA OSDR não está marcado como publicamente acessível."
        )
    if (
        dataset_file.file_size_bytes is None
        or dataset_file.file_size_bytes > _MAX_PUBLIC_CMP_BYTES
    ):
        raise OSDRMetadataError(
            "O ficheiro NASA OSDR excede o limite de tamanho do painel público."
        )

    content = download_osdr_csv(
        dataset_file,
        max_bytes=_MAX_PUBLIC_CMP_BYTES,
    )
    rows = parse_osdr_csv(content)
    required_columns = {
        "Sample Name",
        *(column for _, _, _, column in _INSPIRATION4_CMP_METRICS),
    }
    if any(required_columns.difference(row) for row in rows):
        raise OSDRMetadataError(
            "O CSV NASA OSDR não contém as colunas CMP esperadas."
        )

    grouped_values: dict[str, dict[str, list[float]]] = {}
    sample_names: set[str] = set()
    for row in rows:
        sample_name = row["Sample Name"].strip()
        match = re.fullmatch(r".+_serum_([LR][+-]\d+)", sample_name)
        if match is None:
            raise OSDRMetadataError(
                "Um registo CMP NASA OSDR não identifica um ponto temporal esperado."
            )
        timepoint = match.group(1)
        sample_names.add(sample_name)
        values_by_metric = grouped_values.setdefault(timepoint, {})
        for key, _, _, source_column in _INSPIRATION4_CMP_METRICS:
            raw_value = row[source_column].strip()
            if raw_value.upper() in {"", "NA", "N/A"}:
                continue
            try:
                value = float(raw_value)
            except ValueError as error:
                raise OSDRMetadataError(
                    f"O valor da coluna NASA OSDR '{source_column}' não é numérico."
                ) from error
            if not math.isfinite(value):
                raise OSDRMetadataError(
                    f"O valor da coluna NASA OSDR '{source_column}' não é finito."
                )
            values_by_metric.setdefault(key, []).append(value)

    sorted_timepoints = sorted(grouped_values, key=lambda value: int(value[1:]))
    metrics = []
    for key, label, unit, source_column in _INSPIRATION4_CMP_METRICS:
        points = []
        for timepoint in sorted_timepoints:
            values = grouped_values[timepoint].get(key, [])
            group_size = sum(
                1
                for row in rows
                if row["Sample Name"].strip().endswith(f"_serum_{timepoint}")
            )
            points.append(
                OSDRPublicSummaryPoint(
                    timepoint=timepoint,
                    mean=round(sum(values) / len(values), 4) if values else None,
                    observed_min=min(values) if values else None,
                    observed_max=max(values) if values else None,
                    sample_count=len(values),
                    missing_count=group_size - len(values),
                )
            )
        metrics.append(
            OSDRPublicSummaryMetric(
                key=key,
                label=label,
                unit=unit,
                source_column=source_column,
                points=tuple(points),
            )
        )

    return OSDRPublicInspiration4Dataset(
        title=study.title,
        study_url=study.study_url,
        source_api_url=dataset_file.source_api_url,
        source_file_name=dataset_file.file_name,
        source_file_url=dataset_file.download_url,
        source_file_updated_at=dataset_file.remote_updated_at,
        source_file_size_bytes=dataset_file.file_size_bytes,
        source_file_sha256=hashlib.sha256(content).hexdigest(),
        record_count=len(rows),
        sample_count=len(sample_names),
        retrieved_at=datetime.now(timezone.utc),
        citation=study.citation,
        metrics=tuple(metrics),
    )
