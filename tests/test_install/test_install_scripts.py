"""End-to-end tests of the install bundle: build it, run setup.sh and the
bootstrap script against it in a temp dir. A fake `docker` on PATH records
what would have been run, so no containers are started."""
import os
import pty
import select
import stat
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def dist(tmp_path_factory):
    out = tmp_path_factory.mktemp('dist')
    subprocess.run(['bash', str(ROOT / 'install' / 'make-bundle.sh'), 'v9.9.9'], check=True,
                   env={**os.environ, 'OUT_DIR': str(out)}, capture_output=True)
    return out


@pytest.fixture
def fake_bin(tmp_path):
    """A `docker` that logs its arguments, and an `ip` that reports a fixed LAN."""
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    log = tmp_path / 'docker.log'
    (bin_dir / 'docker').write_text(f'#!/bin/sh\necho "$@" >> {log}\nexit 0\n')
    (bin_dir / 'ip').write_text(
        '#!/bin/sh\n'
        'case "$*" in\n'
        '  *"route show default"*) echo "default via 192.168.7.1 dev enp3s0 proto dhcp" ;;\n'
        '  *"scope link"*) echo "192.168.7.0/24 proto kernel scope link src 192.168.7.50" ;;\n'
        'esac\n')
    for f in bin_dir.iterdir():
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return bin_dir, log


def run(cmd, cwd, fake_bin, **kw):
    bin_dir, _ = fake_bin
    env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}', **kw.pop('env', {})}
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, **kw)


def run_on_tty(cmd, cwd, fake_bin, answers, env=None, timeout=60):
    """Run `cmd` with a real controlling terminal and type `answers`, a list of (prompt, reply).

    Each reply is sent once its prompt has appeared. Returns (exit code, everything printed).
    """
    bin_dir, _ = fake_bin
    full_env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}', **(env or {})}
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execvpe(cmd[0], cmd, full_env)
    out, scanned, pending, deadline = b'', 0, list(answers), time.time() + timeout
    while time.time() < deadline:
        if not select.select([fd], [], [], 0.2)[0]:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        while pending and pending[0][0].encode() in out[scanned:]:
            prompt, reply = pending.pop(0)
            scanned += out[scanned:].index(prompt.encode()) + len(prompt)
            os.write(fd, reply.encode() + b'\n')
    else:
        os.kill(pid, 9)
    _, status = os.waitpid(pid, 0)
    assert not pending, f'prompts never appeared: {[p for p, _ in pending]}\n{out.decode(errors="replace")}'
    return os.waitstatus_to_exitcode(status), out.decode(errors='replace')


def extract(dist, dest):
    subprocess.run(['tar', '-xzf', str(dist / 'heimdall-bundle.tar.gz'), '-C', str(dest), '--strip-components=1'], check=True)


PASSWORD = 'correct-horse-battery'


def env_file(path):
    return dict(line.split('=', 1) for line in (path / '.env').read_text().splitlines() if '=' in line and not line.startswith('#'))


class TestBundle:
    def test_compose_runs_from_published_images_only(self, dist, tmp_path):
        extract(dist, tmp_path)
        compose = (tmp_path / 'docker-compose.yml').read_text()
        assert 'build:' not in compose
        assert 'wiremock' not in compose.lower()
        assert '${HEIMDALL_REGISTRY:-ghcr.io/danielonet/heimdall}/sentinel-backend' in compose
        assert 'USE_MOCK_ROUTER=${USE_MOCK_ROUTER:-false}' in compose  # never silently synthetic data
        for service in ('suricata:', 'zeek:', 'opencanary:', 'clamav:', 'postgres:', 'redis:', 'frontend:'):
            assert f'\n  {service}' in compose

    def test_ships_every_file_the_compose_file_mounts(self, dist, tmp_path):
        extract(dist, tmp_path)
        for path in ('suricata/suricata.yaml', 'opencanary/opencanary.conf', 'zeek/local.zeek', 'setup.sh', 'VERSION'):
            assert (tmp_path / path).is_file(), path

    def test_checksum_matches(self, dist):
        r = subprocess.run(['sha256sum', '-c', 'heimdall-bundle.tar.gz.sha256'], cwd=dist, capture_output=True)
        assert r.returncode == 0

    def test_compose_file_is_valid(self, dist, tmp_path):
        if subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode != 0:
            pytest.skip('docker compose not available')
        extract(dist, tmp_path)
        assert run(['./setup.sh', '--tier=full'], tmp_path, (Path('/usr/bin'), None)).returncode == 0
        r = subprocess.run(['docker', 'compose', 'config', '-q'], cwd=tmp_path, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


class TestSetup:
    def test_generates_unique_private_secrets_and_detects_the_lan(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        r = run(['./setup.sh', '--tier=intermediate'], tmp_path, fake_bin)
        assert r.returncode == 0, r.stderr
        for name in ('jwt_secret', 'db_pass', 'admin_password'):
            f = tmp_path / 'secrets' / f'{name}.txt'
            assert len(f.read_text().strip()) == 64 and stat.S_IMODE(f.stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / 'secrets').stat().st_mode) == 0o700
        for name in ('router_password', 'miwifi_password', 'smtp_password', 'otx_api_key', 'abusech_auth_key'):
            assert (tmp_path / 'secrets' / f'{name}.txt').read_text() == ''  # no CHANGE_ME placeholders
        assert (tmp_path / 'secrets' / 'routers').is_dir()
        env = dict(line.split('=', 1) for line in (tmp_path / '.env').read_text().splitlines() if '=' in line)
        assert env['SNIFF_IFACE'] == 'enp3s0' and env['LAN_SUBNET'] == '192.168.7.0/24'
        assert env['DEPLOYMENT_TIER'] == 'intermediate' and env['COMPOSE_PROFILES'] == 'intermediate'
        assert env['IMAGE_TAG'] == '9.9.9'  # image tags drop the release tag's leading v
        assert env['DB_PASS'] == (tmp_path / 'secrets' / 'db_pass.txt').read_text().strip()

    def test_minimal_tier_sets_no_compose_profile(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        run(['./setup.sh', '--tier=minimal'], tmp_path, fake_bin)
        assert '\nCOMPOSE_PROFILES=\n' in (tmp_path / '.env').read_text()

    def test_rerun_never_overwrites_secrets_or_env(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        run(['./setup.sh', '--tier=minimal'], tmp_path, fake_bin)
        before = {p.name: p.read_text() for p in [*(tmp_path / 'secrets').glob('*.txt'), tmp_path / '.env']}
        (tmp_path / 'secrets' / 'router_password.txt').write_text('mine')
        before['router_password.txt'] = 'mine'
        run(['./setup.sh', '--tier=full'], tmp_path, fake_bin)
        after = {p.name: p.read_text() for p in [*(tmp_path / 'secrets').glob('*.txt'), tmp_path / '.env']}
        assert after == before

    def test_two_installs_get_different_secrets(self, dist, tmp_path, fake_bin):
        a, b = tmp_path / 'a', tmp_path / 'b'
        for d in (a, b):
            d.mkdir()
            extract(dist, d)
            run(['./setup.sh', '--tier=minimal'], d, fake_bin)
        assert (a / 'secrets' / 'jwt_secret.txt').read_text() != (b / 'secrets' / 'jwt_secret.txt').read_text()

    def test_router_choice_is_recorded_for_first_boot(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        run(['./setup.sh', '--tier=minimal', '--router=passive'], tmp_path, fake_bin)
        assert '\nINITIAL_ROUTER=passive\n' in (tmp_path / '.env').read_text()

    def test_no_router_choice_leaves_the_setting_blank(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        run(['./setup.sh', '--tier=minimal'], tmp_path, fake_bin)
        assert '\nINITIAL_ROUTER=\n' in (tmp_path / '.env').read_text()

    def test_only_routers_needing_no_login_can_be_preselected(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        r = run(['./setup.sh', '--tier=minimal', '--router=openwrt-ubus'], tmp_path, fake_bin)
        assert r.returncode != 0 and 'Invalid --router' in r.stderr

    def test_rejects_a_bad_tier(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        r = run(['./setup.sh', '--tier=huge'], tmp_path, fake_bin)
        assert r.returncode != 0 and 'Invalid --tier' in r.stderr


class TestDashboardLogin:
    """The user name and password asked for at install time and used for the first sign-in."""

    def _pwfile(self, tmp_path, text=PASSWORD + '\n'):
        f = tmp_path / 'pw.txt'
        f.write_text(text)
        return f

    def test_unattended_defaults_to_admin_with_a_generated_password(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        assert run(['./setup.sh', '--tier=minimal'], tmp_path, fake_bin).returncode == 0
        assert env_file(tmp_path)['ADMIN_USERNAME'] == 'admin'
        assert len((tmp_path / 'secrets' / 'admin_password.txt').read_text().strip()) == 64

    def test_flags_set_the_login_and_the_password_stays_in_its_secret_file(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        pw = self._pwfile(tmp_path)
        r = run(['./setup.sh', '--tier=minimal', '--admin-user=alice', f'--admin-password-file={pw}'], tmp_path, fake_bin)
        assert r.returncode == 0, r.stderr
        secret = tmp_path / 'secrets' / 'admin_password.txt'
        assert secret.read_text() == PASSWORD + '\n' and stat.S_IMODE(secret.stat().st_mode) == 0o600
        assert env_file(tmp_path)['ADMIN_USERNAME'] == 'alice'
        assert PASSWORD not in (tmp_path / '.env').read_text()
        assert PASSWORD not in r.stdout + r.stderr
        assert 'alice' in r.stdout

    def test_a_password_file_without_a_trailing_newline_works(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        pw = self._pwfile(tmp_path, PASSWORD)
        assert run(['./setup.sh', '--tier=minimal', f'--admin-password-file={pw}'], tmp_path, fake_bin).returncode == 0
        assert (tmp_path / 'secrets' / 'admin_password.txt').read_text().strip() == PASSWORD

    @pytest.mark.parametrize('args, message', [
        (['--admin-user=ab'], 'Invalid --admin-user'),
        (['--admin-user=has space'], 'Invalid --admin-user'),
        (['--admin-user=bad/name'], 'Invalid --admin-user'),
    ])
    def test_rejects_a_bad_user_name_before_writing_anything(self, dist, tmp_path, fake_bin, args, message):
        extract(dist, tmp_path)
        r = run(['./setup.sh', '--tier=minimal', *args], tmp_path, fake_bin)
        assert r.returncode != 0 and message in r.stderr
        assert not (tmp_path / 'secrets').exists() and not (tmp_path / '.env').exists()

    @pytest.mark.parametrize('text, message', [
        ('short\n', 'at least 12'),
        ('x' * 129 + '\n', 'at most 128'),
        ('   leading-space-pw\n', 'start or end with a space'),
    ])
    def test_rejects_an_unusable_password_before_writing_anything(self, dist, tmp_path, fake_bin, text, message):
        extract(dist, tmp_path)
        pw = self._pwfile(tmp_path, text)
        r = run(['./setup.sh', '--tier=minimal', '--admin-user=bob', f'--admin-password-file={pw}'], tmp_path, fake_bin)
        assert r.returncode != 0 and message in r.stderr
        assert not (tmp_path / 'secrets').exists()

    def test_rejects_a_password_equal_to_the_user_name(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        pw = self._pwfile(tmp_path, 'same-name-1234\n')
        r = run(['./setup.sh', '--tier=minimal', '--admin-user=same-name-1234', f'--admin-password-file={pw}'], tmp_path, fake_bin)
        assert r.returncode != 0 and 'differ from the user name' in r.stderr

    def test_a_missing_or_empty_password_file_is_an_error(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        r = run(['./setup.sh', '--tier=minimal', f'--admin-password-file={tmp_path / "nope"}'], tmp_path, fake_bin)
        assert r.returncode != 0 and 'not found' in r.stderr
        empty = self._pwfile(tmp_path, '')
        r = run(['./setup.sh', '--tier=minimal', f'--admin-password-file={empty}'], tmp_path, fake_bin)
        assert r.returncode != 0 and 'is empty' in r.stderr

    def test_rerun_keeps_the_existing_login_and_says_so(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        pw = self._pwfile(tmp_path)
        run(['./setup.sh', '--tier=minimal', '--admin-user=alice', f'--admin-password-file={pw}'], tmp_path, fake_bin)
        other = self._pwfile(tmp_path, 'a-completely-other-pass\n')
        r = run(['./setup.sh', '--tier=minimal', '--admin-user=mallory', f'--admin-password-file={other}'], tmp_path, fake_bin)
        assert r.returncode == 0 and 'ignoring --admin-user' in r.stderr
        assert (tmp_path / 'secrets' / 'admin_password.txt').read_text().strip() == PASSWORD
        assert env_file(tmp_path)['ADMIN_USERNAME'] == 'alice'
        assert 'alice' in r.stdout

    def test_an_install_from_before_the_choice_existed_keeps_working(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        run(['./setup.sh', '--tier=minimal'], tmp_path, fake_bin)
        (tmp_path / '.env').write_text('\n'.join(l for l in (tmp_path / '.env').read_text().splitlines()
                                                 if not l.startswith('ADMIN_USERNAME')) + '\n')
        r = run(['./setup.sh', '--tier=minimal'], tmp_path, fake_bin)
        assert r.returncode == 0 and 'user admin' in r.stdout.replace('\x1b[1m', '').replace('\x1b[0m', '')
        assert 'ADMIN_USERNAME' not in (tmp_path / '.env').read_text()  # compose defaults it to admin

    def test_the_compose_file_passes_the_user_name_to_the_backend(self, dist, tmp_path):
        extract(dist, tmp_path)
        assert 'ADMIN_USERNAME=${ADMIN_USERNAME:-admin}' in (tmp_path / 'docker-compose.yml').read_text()

    def test_asks_on_a_terminal_and_hides_the_password(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        code, out = run_on_tty(['./setup.sh', '--tier=minimal', '--router=passive'], tmp_path, fake_bin, [
            ('User name [admin]: ', 'alice'),
            ('Password (', PASSWORD),
            ('Repeat the password: ', PASSWORD),
        ])
        assert code == 0, out
        assert PASSWORD not in out  # typed into a hidden prompt: never echoed back
        assert (tmp_path / 'secrets' / 'admin_password.txt').read_text().strip() == PASSWORD
        assert env_file(tmp_path)['ADMIN_USERNAME'] == 'alice'

    def test_enter_alone_gives_admin_and_a_generated_password(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        code, out = run_on_tty(['./setup.sh', '--tier=minimal', '--router=passive'], tmp_path, fake_bin, [
            ('User name [admin]: ', ''), ('Password (', ''),
        ])
        assert code == 0, out
        assert env_file(tmp_path)['ADMIN_USERNAME'] == 'admin'
        assert len((tmp_path / 'secrets' / 'admin_password.txt').read_text().strip()) == 64

    def test_the_prompt_asks_again_after_a_bad_answer(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        code, out = run_on_tty(['./setup.sh', '--tier=minimal', '--router=passive'], tmp_path, fake_bin, [
            ('User name [admin]: ', 'x'),            # too short
            ('User name [admin]: ', 'alice'),
            ('Password (', 'tooshort'),              # under 12
            ('Password (', PASSWORD),
            ('Repeat the password: ', 'different-one-12345'),
            ('Password (', PASSWORD),                # mismatch sends it back to the start
            ('Repeat the password: ', PASSWORD),
        ])
        assert code == 0, out
        assert 'Use 3-32 letters' in out and 'at least 12 characters' in out and 'differ' in out
        assert (tmp_path / 'secrets' / 'admin_password.txt').read_text().strip() == PASSWORD

    def test_a_rerun_on_a_terminal_does_not_ask_again(self, dist, tmp_path, fake_bin):
        extract(dist, tmp_path)
        run(['./setup.sh', '--tier=minimal', '--router=passive'], tmp_path, fake_bin)
        code, out = run_on_tty(['./setup.sh', '--tier=minimal', '--router=passive'], tmp_path, fake_bin, [])
        assert code == 0 and 'Dashboard login' not in out


class TestBootstrap:
    def _install(self, dist, tmp_path, fake_bin, *args):
        return run(['bash', str(dist / 'install.sh'), f'--dir={tmp_path / "h"}', '--yes', *args], tmp_path, fake_bin,
                   env={'HEIMDALL_BUNDLE_URL_BASE': f'file://{dist}'})

    def test_installs_verifies_and_starts(self, dist, tmp_path, fake_bin):
        r = self._install(dist, tmp_path, fake_bin, '--tier=minimal', '--no-start')
        assert r.returncode == 0, r.stderr + r.stdout
        assert (tmp_path / 'h' / '.env').is_file() and (tmp_path / 'h' / 'secrets' / 'jwt_secret.txt').is_file()
        assert 'Checksum verified' in r.stdout

    def test_router_choice_passes_through_the_bootstrap(self, dist, tmp_path, fake_bin):
        self._install(dist, tmp_path, fake_bin, '--tier=minimal', '--router=passive', '--no-start')
        assert 'INITIAL_ROUTER=passive' in (tmp_path / 'h' / '.env').read_text()

    def test_start_runs_pull_then_up(self, dist, tmp_path, fake_bin):
        # No dashboard is listening in the test, so don't wait for one.
        r = run(['bash', str(dist / 'install.sh'), f'--dir={tmp_path / "h"}', '--yes', '--tier=minimal'], tmp_path, fake_bin,
                env={'HEIMDALL_BUNDLE_URL_BASE': f'file://{dist}', 'HEIMDALL_WAIT_SECONDS': '0'}, timeout=120)
        calls = fake_bin[1].read_text().splitlines()
        assert 'compose pull' in calls and 'compose up -d' in calls
        assert calls.index('compose pull') < calls.index('compose up -d')

    def test_refuses_a_tampered_bundle(self, dist, tmp_path, fake_bin):
        bad = tmp_path / 'bad'
        bad.mkdir()
        (bad / 'heimdall-bundle.tar.gz').write_bytes((dist / 'heimdall-bundle.tar.gz').read_bytes() + b'x')
        (bad / 'heimdall-bundle.tar.gz.sha256').write_text((dist / 'heimdall-bundle.tar.gz.sha256').read_text())
        r = run(['bash', str(dist / 'install.sh'), f'--dir={tmp_path / "h"}', '--yes', '--no-start'], tmp_path, fake_bin,
                env={'HEIMDALL_BUNDLE_URL_BASE': f'file://{bad}'})
        assert r.returncode != 0 and 'Checksum mismatch' in r.stderr
        assert not (tmp_path / 'h' / 'docker-compose.yml').exists()

    def test_upgrade_keeps_secrets_and_moves_the_image_tag(self, dist, tmp_path, fake_bin):
        self._install(dist, tmp_path, fake_bin, '--tier=minimal', '--no-start')
        home = tmp_path / 'h'
        jwt = (home / 'secrets' / 'jwt_secret.txt').read_text()
        env = (home / '.env').read_text().replace('IMAGE_TAG=9.9.9', 'IMAGE_TAG=0.0.1')
        (home / '.env').write_text(env)
        self._install(dist, tmp_path, fake_bin, '--tier=minimal', '--no-start')
        assert (home / 'secrets' / 'jwt_secret.txt').read_text() == jwt
        assert 'IMAGE_TAG=9.9.9' in (home / '.env').read_text()

    def test_missing_docker_is_a_clear_error_not_an_install(self, dist, tmp_path):
        empty = tmp_path / 'empty'
        empty.mkdir()
        for tool in ('uname', 'curl', 'sha256sum', 'mktemp', 'id', 'getent', 'cut', 'tr', 'tar', 'rm', 'mkdir', 'dirname', 'seq', 'sed'):
            p = subprocess.run(['which', tool], capture_output=True, text=True).stdout.strip()
            if p:
                (empty / tool).symlink_to(p)
        r = subprocess.run(['/bin/bash', str(dist / 'install.sh'), f'--dir={tmp_path / "h"}', '--yes'], capture_output=True, text=True,
                           env={'PATH': str(empty), 'HEIMDALL_BUNDLE_URL_BASE': f'file://{dist}'}, stdin=subprocess.DEVNULL)
        assert r.returncode != 0 and 'Docker with the compose plugin is required' in r.stderr
        assert not (tmp_path / 'h').exists()

    def test_login_flags_pass_through_the_bootstrap(self, dist, tmp_path, fake_bin):
        pw = tmp_path / 'pw.txt'
        pw.write_text(PASSWORD + '\n')
        r = self._install(dist, tmp_path, fake_bin, '--tier=minimal', '--no-start', '--admin-user=alice', f'--admin-password-file={pw}')
        assert r.returncode == 0, r.stderr + r.stdout
        home = tmp_path / 'h'
        assert (home / 'secrets' / 'admin_password.txt').read_text().strip() == PASSWORD
        assert env_file(home)['ADMIN_USERNAME'] == 'alice'
        assert PASSWORD not in r.stdout + r.stderr

    def test_asks_for_the_login_on_a_terminal_and_never_puts_the_password_in_argv(self, dist, tmp_path, fake_bin):
        # A fake `docker` that records the whole process table would be overkill; instead make setup.sh's
        # argv visible: wrap it so every invocation's arguments are logged, then check the password is absent.
        code, out = run_on_tty(
            ['bash', str(dist / 'install.sh'), f'--dir={tmp_path / "h"}', '--tier=minimal', '--no-start'],
            tmp_path, fake_bin,
            [('Enter 1/2/3 [3]: ', '3'), ('User name [admin]: ', 'alice'), ('Password (', PASSWORD), ('Repeat the password: ', PASSWORD)],
            env={'HEIMDALL_BUNDLE_URL_BASE': f'file://{dist}'})
        home = tmp_path / 'h'
        assert code == 0, out
        assert (home / 'secrets' / 'admin_password.txt').read_text().strip() == PASSWORD
        assert env_file(home)['ADMIN_USERNAME'] == 'alice'
        assert PASSWORD not in out

    def test_a_terminal_upgrade_does_not_ask_for_the_login_again(self, dist, tmp_path, fake_bin):
        self._install(dist, tmp_path, fake_bin, '--tier=minimal', '--no-start', '--admin-user=alice')
        code, out = run_on_tty(
            ['bash', str(dist / 'install.sh'), f'--dir={tmp_path / "h"}', '--tier=minimal', '--no-start'], tmp_path, fake_bin, [],
            env={'HEIMDALL_BUNDLE_URL_BASE': f'file://{dist}'})
        assert code == 0 and 'Dashboard login' not in out, out
        assert env_file(tmp_path / 'h')['ADMIN_USERNAME'] == 'alice'

    def test_yes_never_prompts_even_on_a_terminal(self, dist, tmp_path, fake_bin):
        code, out = run_on_tty(
            ['bash', str(dist / 'install.sh'), f'--dir={tmp_path / "h"}', '--yes', '--tier=minimal', '--no-start'], tmp_path, fake_bin, [],
            env={'HEIMDALL_BUNDLE_URL_BASE': f'file://{dist}'})
        assert code == 0 and 'Dashboard login' not in out, out
