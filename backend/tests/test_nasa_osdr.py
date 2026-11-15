from datetime import datetime, timezone
import json

import pytest

from app.nasa_osdr import (
    OSDRDatasetFile,
    OSDRMetadataError,
    download_osdr_csv,
    fetch_osdr_dataset_files,
    fetch_osdr_study_metadata,
    parse_osdr_csv,
    search_osdr_datasets,
)


class _Response:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        return False

    def read(self, limit: int) -> bytes:
        return self._body[:limit]


class _Opener:
    def __init__(self, body: bytes):
        self.body = body
        self.requested_url = None

    def open(self, request, timeout: int):
        self.requested_url = request.full_url
        assert timeout == 10
        return _Response(self.body)


def _osdr_response() -> bytes:
    return json.dumps(
        {
            "OSD-575": {
                "metadata": {
                    "accession": "OSD-575",
                    "study title": "Inspiration4 serum study",
                    "project identifier": "Inspiration4 Crew",
                    "mission": {
                        "name": "SpaceX Inspiration4",
                        "start date": "09/16/2021",
                        "end date": "09/18/2021",
                    },
                    "material type": "Serum",
                    "identifiers": ["LSDS-8", "GLDS-579"],
                    "study assay technology type": ["Multiplex"],
                    "study assay technology platform": ["Eve Technologies"],
                    "study publication author list": ["Not copied"],
                }
            }
        }
    ).encode()


def test_fetch_osdr_metadata_normalizes_whitelisted_fields(monkeypatch):
    import app.nasa_osdr as nasa_osdr

    opener = _Opener(_osdr_response())
    monkeypatch.setattr(nasa_osdr, "_OPENER", opener)

    metadata = fetch_osdr_study_metadata("OSD-575")

    assert opener.requested_url == (
        "https://visualization.osdr.nasa.gov/biodata/api/v2/dataset/OSD-575/"
    )
    assert metadata.mission_name == "SpaceX Inspiration4"
    assert metadata.mission_start_date.isoformat() == "2021-09-16"
    assert metadata.identifiers == ("LSDS-8", "GLDS-579")
    assert metadata.license_status == "not_verified"
    assert metadata.files_downloaded is False
    assert "author" not in metadata.model_dump_json().lower()


def test_fetch_osdr_metadata_rejects_non_osdr_accessions():
    with pytest.raises(ValueError, match="formato"):
        fetch_osdr_study_metadata("https://example.invalid/")


def test_fetch_osdr_metadata_rejects_mismatched_response(monkeypatch):
    import app.nasa_osdr as nasa_osdr

    monkeypatch.setattr(
        nasa_osdr,
        "_OPENER",
        _Opener(b'{"OSD-575":{"metadata":{"accession":"OSD-576"}}}'),
    )

    with pytest.raises(OSDRMetadataError, match="não correspondem"):
        fetch_osdr_study_metadata("OSD-575")


def test_search_osdr_datasets_uses_official_query_and_deduplicates(monkeypatch):
    import app.nasa_osdr as nasa_osdr

    opener = _Opener(
        json.dumps(
            [
                {
                    "id.accession": "OSD-575",
                    "study.characteristics.organism": "Homo sapiens",
                    "study.factor value.spaceflight": "in-flight",
                },
                {
                    "id.accession": "OSD-575",
                    "study.characteristics.organism": "Homo sapiens",
                    "study.factor value.spaceflight": "in-flight",
                },
            ]
        ).encode()
    )
    monkeypatch.setattr(nasa_osdr, "_OPENER", opener)

    results = search_osdr_datasets(organism="Homo sapiens")

    assert len(results) == 1
    assert results[0].accession == "OSD-575"
    assert results[0].organism == "Homo sapiens"
    assert "study.characteristics.organism=Homo+sapiens" in opener.requested_url
    assert "study.factor%20value.spaceflight" in opener.requested_url


def test_search_osdr_datasets_requires_a_filter():
    with pytest.raises(ValueError, match="pelo menos um filtro"):
        search_osdr_datasets()


def test_fetch_osdr_dataset_files_validates_official_urls(monkeypatch):
    import app.nasa_osdr as nasa_osdr

    files = {
        "OSD-575": {
            "files": {
                "cmp.csv": {
                    "REST_URL": (
                        "https://visualization.osdr.nasa.gov/biodata/api/v2/"
                        "dataset/OSD-575/file/cmp.csv/"
                    ),
                    "URL": (
                        "https://osdr.nasa.gov/geode-py/ws/studies/OSD-575/"
                        "download?source=datamanager&file=cmp.csv"
                    ),
                }
            }
        }
    }
    opener = _Opener(json.dumps(files).encode())
    monkeypatch.setattr(nasa_osdr, "_OPENER", opener)

    result = fetch_osdr_dataset_files("OSD-575")

    assert len(result) == 1
    assert result[0].file_name == "cmp.csv"
    assert result[0].file_format == "csv"
    assert result[0].restricted is None


def test_fetch_osdr_dataset_files_rejects_non_nasa_download_urls(monkeypatch):
    import app.nasa_osdr as nasa_osdr

    files = {
        "OSD-575": {
            "files": {
                "cmp.csv": {
                    "REST_URL": (
                        "https://visualization.osdr.nasa.gov/biodata/api/v2/"
                        "dataset/OSD-575/file/cmp.csv/"
                    ),
                    "URL": "https://example.invalid/cmp.csv",
                }
            }
        }
    }
    monkeypatch.setattr(nasa_osdr, "_OPENER", _Opener(json.dumps(files).encode()))

    with pytest.raises(OSDRMetadataError, match="não correspondem"):
        fetch_osdr_dataset_files("OSD-575")


def test_download_osdr_csv_requires_public_csv_and_matching_size(monkeypatch):
    import app.nasa_osdr as nasa_osdr

    dataset_file = OSDRDatasetFile(
        accession="OSD-575",
        file_name="cmp.csv",
        file_format="csv",
        source_api_url=(
            "https://visualization.osdr.nasa.gov/biodata/api/v2/"
            "dataset/OSD-575/file/cmp.csv/"
        ),
        download_url=(
            "https://osdr.nasa.gov/geode-py/ws/studies/OSD-575/"
            "download?source=datamanager&file=cmp.csv"
        ),
        file_size_bytes=7,
        restricted=False,
        remote_updated_at=None,
        retrieved_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(nasa_osdr, "_DOWNLOAD_OPENER", _Opener(b"a,b\n1,2\n"))

    with pytest.raises(OSDRMetadataError, match="tamanho descarregado"):
        download_osdr_csv(dataset_file, max_bytes=20)

    with pytest.raises(OSDRMetadataError, match="não é CSV público"):
        download_osdr_csv(
            dataset_file.model_copy(update={"restricted": True}),
            max_bytes=20,
        )


def test_parse_osdr_csv_preserves_source_headers_and_cell_text():
    rows = parse_osdr_csv(
        b"\xef\xbb\xbfmeasure_value_mg_per_dl,sample,qualifier\r\n95.50,S1,<x>\r\n"
    )

    assert rows == (
        {
            "measure_value_mg_per_dl": "95.50",
            "sample": "S1",
            "qualifier": "<x>",
        },
    )


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"duplicate,duplicate\n1,2\n",
        b"a,b\n1\n",
        b"a,b\n1,2,3\n",
        b"\xff",
    ],
)
def test_parse_osdr_csv_rejects_invalid_files(content):
    with pytest.raises(OSDRMetadataError):
        parse_osdr_csv(content)
