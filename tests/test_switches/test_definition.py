import copy
import json

import pytest

from sentinel.switches.web.definition import DEFINITIONS_DIR, DefinitionError, load_definition, parse_definition

RAW = json.loads((DEFINITIONS_DIR / 'hc-swtgw218as.json').read_text())


def mutated(change):
    raw = copy.deepcopy(RAW)
    change(raw)
    return raw


def test_the_shipped_definitions_all_load():
    files = sorted(DEFINITIONS_DIR.glob('*.json'))
    assert files
    for path in files:
        assert load_definition(path.stem).id == path.stem


@pytest.mark.parametrize('change', [
    lambda r: r.update(surprise=1),                                          # unknown key
    lambda r: r['pages']['info'].update(url='http://203.0.113.9/'),         # a URL, not a path on the switch
    lambda r: r['pages']['info'].update(url='//203.0.113.9/info'),          # protocol-relative
    lambda r: r['auth']['fields'].update(Response='${os.system}'),          # not in the template whitelist
    lambda r: r['auth']['fields'].update(Response='${md5(secret)}'),        # unknown variable
    lambda r: r['identity'].update(page='nope'),                            # unknown page
    lambda r: r['ports'].update(port_id='(['),                              # not a regex
    lambda r: r['macs']['table']['columns'].update(mac='(['),
    lambda r: r['ports']['table']['columns'].pop('rx_bytes'),               # a required column
    lambda r: r['macs']['table'].update(header_match=[]),
    lambda r: r.update(id='Bad Id'),
    lambda r: r['pages']['macs']['paginate'].update(max_pages=100000),
])
def test_a_bad_definition_is_rejected_when_loaded(change):
    with pytest.raises(DefinitionError):
        parse_definition(mutated(change))


def test_an_id_cannot_climb_out_of_the_definitions_folder():
    with pytest.raises(DefinitionError):
        load_definition('../../etc/passwd')
