import pytest

from sentinel.switches.web.extract.html_table import column_index, find_table, labelled_values, parse_tables
from sentinel.switches.web.extract.values import parse_number, parse_speed_mbps, port_id


@pytest.mark.parametrize('text, fmt, expected', [
    ('1234', 'plain', 1234), ('1,234,567', 'plain', 1234567), (' 7 ', 'plain', 7),
    ('0-130522', 'hi_lo', 130522), ('2-5', 'hi_lo', 2 * 2**32 + 5), ('0-0', 'hi_lo', 0),
    ('', 'plain', None), ('n/a', 'plain', None), ('12-', 'hi_lo', None), ('1.5', 'plain', None),
])
def test_parse_number(text, fmt, expected):
    assert parse_number(text, fmt) == expected


def test_parse_number_rejects_an_unknown_format():
    with pytest.raises(ValueError):
        parse_number('1', 'hex')


@pytest.mark.parametrize('text, expected', [('1000M', 1000), ('10M', 10), ('1G', 1000), ('2G', 2000), ('Auto', None), ('', None)])
def test_parse_speed(text, expected):
    assert parse_speed_mbps(text) == expected


def test_port_id_takes_group_one_or_the_whole_match():
    assert port_id('Port 3', r'^Port\s*(\S+)$') == '3'
    assert port_id('CPU', r'^(\S+)$') == 'CPU'
    assert port_id('uplink', r'^Port\s*(\S+)$') is None


HTML = """
<table><tr><th>Port</th><th>Rx</th><th>Tx</th></tr>
<tr><td>Port 1</td><td>10</td><td>20</td></tr>
<tr><td>Port 2</td><td>30</td><td>40</td></tr></table>
<table><tr><th>Model:</td><td>X1</td><th>Firmware:</th><td>V2</td></tr></table>
<table><tr><td>layout</td><td><table><tr><th>MAC</th></tr><tr><td>aa</td></tr></table></td></tr></table>
"""


def test_tables_are_found_by_header_text_not_position():
    tables = parse_tables(HTML)
    table = find_table(tables, ['^Port$', 'Tx'])
    assert table.headers() == ['Port', 'Rx', 'Tx']
    assert table.data_rows() == [['Port 1', '10', '20'], ['Port 2', '30', '40']]
    assert find_table(tables, ['^Nothing$']) is None


def test_columns_are_located_by_header_even_if_their_order_changes():
    assert column_index(['Tx', 'Port', 'Rx'], '^Rx$') == 2
    assert column_index(['Tx', 'Port'], '^Rx$') is None


def test_labelled_values_tolerate_a_th_closed_by_td_and_nested_tables():
    assert labelled_values(parse_tables(HTML)) == {'Model:': 'X1', 'Firmware:': 'V2'}
    inner = find_table(parse_tables(HTML), ['^MAC$'])
    assert inner.data_rows() == [['aa']]
