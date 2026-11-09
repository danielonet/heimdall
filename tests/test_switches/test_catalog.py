import re

from sentinel.adapter.catalog import SimulatorKind
from sentinel.switches.catalog import CATALOG, get_spec
from sentinel.switches.registry import DRIVERS
from sentinel.switches.web.definition import load_definition
from tests.test_switches.simulator import FIXTURES_DIR


def test_ids_are_unique_and_safe():
    ids = [s.id for s in CATALOG]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', i) for i in ids)


def test_every_entry_names_a_registered_driver_and_a_loadable_definition():
    for spec in CATALOG:
        assert spec.driver in DRIVERS, spec.id
        if spec.driver == 'web-definition':
            assert load_definition(spec.definition).id == spec.definition


def test_an_implemented_switch_has_fixtures_that_the_generic_suite_runs():
    """`implemented` means its fixture suite passes: no fixtures, no claim."""
    for spec in CATALOG:
        if spec.implemented and spec.simulator is SimulatorKind.FIXTURES:
            assert (FIXTURES_DIR / spec.id / 'fixture.json').is_file(), spec.id
            assert (FIXTURES_DIR / spec.id / 'expected.json').is_file(), spec.id


def test_tested_requires_implemented():
    assert all(s.implemented for s in CATALOG if s.tested)


def test_get_spec():
    assert get_spec('hc-swtgw218as') is CATALOG[0]
    assert get_spec('nope') is None


def test_to_dict_is_json_ready():
    import json
    json.dumps([s.to_dict() for s in CATALOG])
