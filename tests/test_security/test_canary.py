import json

from sentinel.security.canary import OpenCanaryIngester, OpenCanaryLogReader, honeypot_ports


def _event(logtype: int = 1000, **overrides) -> str:
    payload = {
        'logtype': logtype,
        'src_host': '10.100.102.50',
        'dst_host': '10.100.102.5',
        'logdata': {'SERVICE': 'ftp'},
    }
    payload.update(overrides)
    return json.dumps(payload)


class TestParseEvent:
    def test_interaction_event_produces_alert(self):
        ingester = OpenCanaryIngester()
        alert = ingester.parse_event(_event(logtype=1000))
        assert alert is not None
        assert alert.alert_type == 'HONEYPOT_ACCESS'
        assert alert.severity == 'CRITICAL'
        assert '10.100.102.50' in alert.description
        assert 'ftp' in alert.description

    def test_non_interaction_logtype_ignored(self):
        ingester = OpenCanaryIngester()
        alert = ingester.parse_event(_event(logtype=9999))
        assert alert is None

    def test_malformed_json_ignored(self):
        ingester = OpenCanaryIngester()
        assert ingester.parse_event('not json at all {{{') is None

    def test_missing_fields_use_defaults(self):
        ingester = OpenCanaryIngester()
        alert = ingester.parse_event(json.dumps({'logtype': 2000}))
        assert alert is not None
        assert 'unknown' in alert.description

    def test_raw_event_preserved_in_raw_data(self):
        ingester = OpenCanaryIngester()
        alert = ingester.parse_event(_event(logtype=3000))
        assert alert.raw_data['logtype'] == 3000


class TestOpenCanaryLogReader:
    def test_missing_file_returns_empty(self, tmp_path):
        reader = OpenCanaryLogReader(str(tmp_path / 'does-not-exist.log'))
        assert reader.read_new_lines() == []

    def test_reads_lines_written_so_far(self, tmp_path):
        log_path = tmp_path / 'opencanary.log'
        log_path.write_text(_event() + '\n')

        reader = OpenCanaryLogReader(str(log_path))
        lines = reader.read_new_lines()
        assert len(lines) == 1

    def test_second_read_only_returns_new_lines(self, tmp_path):
        log_path = tmp_path / 'opencanary.log'
        log_path.write_text(_event() + '\n')

        reader = OpenCanaryLogReader(str(log_path))
        reader.read_new_lines()  # consume the first line

        with open(log_path, 'a') as f:
            f.write(_event(logtype=2000) + '\n')

        second = reader.read_new_lines()
        assert len(second) == 1
        assert json.loads(second[0])['logtype'] == 2000

    def test_blank_lines_are_filtered(self, tmp_path):
        log_path = tmp_path / 'opencanary.log'
        log_path.write_text(_event() + '\n\n\n')

        reader = OpenCanaryLogReader(str(log_path))
        assert len(reader.read_new_lines()) == 1


class TestHoneypotPorts:
    def test_reads_enabled_services_with_explicit_and_default_ports(self, tmp_path):
        conf = tmp_path / 'opencanary.conf'
        conf.write_text(json.dumps({
            'ftp.enabled': True, 'ftp.port': 21,
            'ssh.enabled': True, 'ssh.port': 2222,
            'mysql.enabled': False, 'mysql.port': 3306,
            'smb.enabled': True,
            'logger': {'class': 'PyLogger'},
        }))
        assert honeypot_ports(str(conf)) == {21, 2222, 139, 445}

    def test_missing_or_broken_config_excludes_nothing(self, tmp_path):
        assert honeypot_ports(str(tmp_path / 'absent.conf')) == frozenset()
        broken = tmp_path / 'broken.conf'
        broken.write_text('{not json')
        assert honeypot_ports(str(broken)) == frozenset()

    def test_shipped_config_lists_the_decoy_ports(self):
        ports = honeypot_ports('opencanary/opencanary.conf')
        assert {21, 8880, 2222, 2323, 445} <= ports


class TestHoneypotPortsForScan:
    def _scheduler(self, **attrs):
        from sentinel.scheduler.scheduler import SentinelScheduler
        sched = object.__new__(SentinelScheduler)
        for key, value in attrs.items():
            setattr(sched, key, value)
        return sched

    def test_only_this_hosts_own_ip_gets_honeypot_ports_excluded(self):
        sched = self._scheduler(_opencanary_conf_path='opencanary/opencanary.conf', _local_ips={'10.0.0.2'})
        assert 2323 in sched._honeypot_ports_for('10.0.0.2')
        assert sched._honeypot_ports_for('10.0.0.50') == frozenset()

    def test_unconfigured_scheduler_excludes_nothing(self):
        assert self._scheduler()._honeypot_ports_for('10.0.0.2') == frozenset()
