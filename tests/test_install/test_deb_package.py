"""Build the .deb and check what it contains and how its scripts and the
`heimdall` command behave. Nothing is installed: the package is unpacked into
a temp dir, and maintainer scripts run against it through HEIMDALL_HOME."""
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(shutil.which('dpkg-deb') is None, reason='dpkg-deb not installed')


@pytest.fixture(scope='module')
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp('deb')
    subprocess.run(['bash', str(ROOT / 'install' / 'deb' / 'make-deb.sh'), 'v9.9.9'], check=True,
                   env={**os.environ, 'OUT_DIR': str(out)}, capture_output=True)
    return out


@pytest.fixture(scope='module')
def unpacked(built, tmp_path_factory):
    dest = tmp_path_factory.mktemp('root')
    subprocess.run(['dpkg-deb', '-x', str(built / 'heimdall_9.9.9_all.deb'), str(dest)], check=True)
    return dest


def field(built, name):
    out = subprocess.run(['dpkg-deb', '-f', str(built / 'heimdall_9.9.9_all.deb'), name],
                         check=True, capture_output=True, text=True)
    return out.stdout.strip()


class TestPackage:
    def test_outputs_exist(self, built):
        for name in ('heimdall_9.9.9_all.deb', 'heimdall_all.deb', 'heimdall_9.9.9_all.deb.sha256'):
            assert (built / name).is_file()
        assert (built / 'heimdall_all.deb').read_bytes() == (built / 'heimdall_9.9.9_all.deb').read_bytes()

    def test_checksum_matches(self, built):
        r = subprocess.run(['sha256sum', '-c', 'heimdall_9.9.9_all.deb.sha256'], cwd=built, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    def test_control_fields(self, built):
        assert field(built, 'Package') == 'heimdall'
        assert field(built, 'Version') == '9.9.9'  # the tag's leading 'v' is dropped
        assert field(built, 'Architecture') == 'all'
        depends = field(built, 'Depends')
        for dep in ('docker.io', 'docker-compose-v2', 'openssl', 'iproute2'):
            assert dep in depends

    def test_dev_build_version_sorts_before_releases(self, tmp_path):
        subprocess.run(['bash', str(ROOT / 'install' / 'deb' / 'make-deb.sh')], check=True,
                       env={**os.environ, 'OUT_DIR': str(tmp_path)}, capture_output=True)
        assert (tmp_path / 'heimdall_0.0.0~dev_all.deb').is_file()

    def test_payload(self, unpacked):
        opt = unpacked / 'opt' / 'heimdall'
        for rel in ('docker-compose.yml', 'setup.sh', 'VERSION', 'suricata/suricata.yaml', 'zeek/local.zeek',
                    'opencanary/opencanary.conf'):
            assert (opt / rel).is_file(), rel
        assert (opt / 'VERSION').read_text().strip() == 'v9.9.9'
        assert (unpacked / 'usr/bin/heimdall').is_file()
        assert (unpacked / 'lib/systemd/system/heimdall.service').is_file()
        assert (unpacked / 'usr/share/doc/heimdall/copyright').is_file()

    def test_ships_no_secrets_or_env(self, unpacked):
        opt = unpacked / 'opt' / 'heimdall'
        assert not (opt / '.env').exists()
        assert not (opt / 'secrets').exists()

    def test_nothing_group_or_world_writable(self, unpacked):
        for path in unpacked.rglob('*'):
            assert not (path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)), path

    def test_service_is_not_enabled_by_the_package(self, unpacked):
        # Starting a network sniffer on install, without a tier or router choice, would be wrong.
        assert not list(unpacked.rglob('*.wants'))
        assert 'ConditionPathExists=/opt/heimdall/.env' in (unpacked / 'lib/systemd/system/heimdall.service').read_text()


class TestMaintainerScripts:
    @pytest.fixture
    def home(self, unpacked, tmp_path):
        home = tmp_path / 'heimdall'
        shutil.copytree(unpacked / 'opt' / 'heimdall', home)
        return home

    def run_script(self, built, name, home, *args):
        ctl = built / 'ctl'
        if not ctl.exists():
            subprocess.run(['dpkg-deb', '-e', str(built / 'heimdall_9.9.9_all.deb'), str(ctl)], check=True)
        return subprocess.run(['sh', str(ctl / name), *args], capture_output=True, text=True,
                              env={**os.environ, 'HEIMDALL_HOME': str(home)})

    def test_fresh_install_prints_next_steps_and_creates_nothing(self, built, home):
        r = self.run_script(built, 'postinst', home, 'configure')
        assert r.returncode == 0
        assert 'sudo heimdall setup' in r.stdout
        assert not (home / '.env').exists()

    def test_upgrade_moves_image_tag_and_keeps_the_rest(self, built, home):
        (home / '.env').write_text('DEPLOYMENT_TIER=full\nIMAGE_TAG=0.0.1\nINITIAL_ROUTER=passive\n')
        r = self.run_script(built, 'postinst', home, 'configure', '0.0.1')
        assert r.returncode == 0
        env = (home / '.env').read_text()
        assert 'IMAGE_TAG=9.9.9' in env
        assert 'DEPLOYMENT_TIER=full' in env and 'INITIAL_ROUTER=passive' in env

    def test_purge_keeps_secrets(self, built, home):
        (home / '.env').write_text('IMAGE_TAG=9.9.9\n')
        r = self.run_script(built, 'postrm', home, 'purge')
        assert r.returncode == 0
        assert (home / '.env').exists()


class TestCommand:
    @pytest.fixture
    def cmd(self, unpacked, tmp_path):
        home = tmp_path / 'heimdall'
        shutil.copytree(unpacked / 'opt' / 'heimdall', home)
        env = {**os.environ, 'HEIMDALL_HOME': str(home)}
        exe = str(unpacked / 'usr/bin/heimdall')

        def run(*args, **kw):
            if 'input' not in kw:
                kw['stdin'] = subprocess.DEVNULL
            return subprocess.run([exe, *args], capture_output=True, text=True, env=env, **kw)
        run.home = home
        return run

    def test_version(self, cmd):
        assert cmd('version').stdout.strip() == 'v9.9.9'

    def test_help_and_unknown_command(self, cmd):
        assert 'heimdall setup' in cmd('help').stdout
        assert cmd('frobnicate').returncode == 2

    def test_start_refuses_before_setup(self, cmd):
        r = cmd('start')
        assert r.returncode != 0
        assert 'heimdall setup' in r.stderr

    def test_password_before_setup(self, cmd):
        assert cmd('password').returncode != 0

    def test_password_after_setup(self, cmd):
        (cmd.home / 'secrets').mkdir()
        (cmd.home / 'secrets' / 'admin_password.txt').write_text('s3cret\n')
        assert cmd('password').stdout.strip() == 's3cret'

    def test_reset_needs_explicit_confirmation(self, cmd):
        (cmd.home / '.env').write_text('x=1\n')
        r = cmd('reset', input='no\n')
        assert r.returncode != 0
        assert (cmd.home / '.env').exists()
