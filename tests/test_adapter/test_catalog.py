from pathlib import Path

from sentinel.adapter.catalog import CATALOG, SimulatorKind, get_spec

_ROOT = Path(__file__).resolve().parents[2]


def test_ids_are_unique():
    ids = [spec.id for spec in CATALOG]
    assert len(ids) == len(set(ids))


def test_existing_routers_are_implemented_and_use_settings_store():
    for router_id in ('sagemcom-xmo', 'miwifi-stok'):
        spec = get_spec(router_id)
        assert spec.implemented and spec.credential_store == 'settings'


def test_every_password_field_is_declared():
    assert all('password' in spec.fields for spec in CATALOG)


def test_unknown_id_returns_none():
    assert get_spec('nope') is None


def test_every_wiremock_router_has_a_stub_folder():
    for spec in CATALOG:
        if spec.simulator is SimulatorKind.WIREMOCK:
            assert any((_ROOT / 'wiremock' / 'mappings' / spec.id).glob('*.json')), spec.id


def test_every_docker_router_has_a_dockerfile():
    for spec in CATALOG:
        if spec.simulator is SimulatorKind.DOCKER:
            assert (_ROOT / 'tests' / 'simulators' / spec.id / 'Dockerfile').is_file(), spec.id


def test_wiremock_mappings_are_valid_json_with_request_and_response():
    import json
    for path in (_ROOT / 'wiremock' / 'mappings').glob('*/*.json'):
        data = json.loads(path.read_text())
        for mapping in data.get('mappings', [data]):
            assert 'request' in mapping and 'response' in mapping, path
