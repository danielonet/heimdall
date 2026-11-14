"""`setup.sh --prune-old-images`: after an upgrade, remove the Heimdall images of older versions and nothing else.

Most tests run against a fake `docker` that keeps images and containers in a JSON file and follows the real
engine's rules where they matter: an image a container uses cannot be removed, removing a tag only deletes the
image when it was its last name, and --force is refused, so a test fails if the script ever asks for it. One class
runs the same script against the real Docker engine with throwaway images and is skipped when there is none.
"""
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REG = 'ghcr.io/danielonet/heimdall'
BACKEND, FRONTEND = f'{REG}/sentinel-backend', f'{REG}/frontend'

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys

state_path = os.environ['FAKE_DOCKER_STATE']
state = json.load(open(state_path))
args = sys.argv[1:]
with open(state_path + '.log', 'a') as log:
    log.write(' '.join(args) + '\n')


def save():
    json.dump(state, open(state_path, 'w'))


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def find(ref):
    for image in state['images']:
        if ref == image['id'] or ref in image['tags']:
            return image


def used(image):
    return any(c['image'] == image['id'] for c in state['containers'])


def env(name, default):
    try:
        for line in open('.env').read().splitlines():
            if line.startswith(name + '='):
                return line.split('=', 1)[1]
    except OSError:
        pass
    return default


if args[:2] == ['compose', 'version']:
    sys.exit(0)
if args[:4] == ['compose', 'config', '--format', 'json']:
    print('{\n  "name": "heimdall",\n  "services": {}\n}')
    sys.exit(0)
if args[:3] == ['compose', 'config', '--volumes']:
    print('\n'.join(['ml-models', 'pgdata', 'zeek-logs', 'threat-feeds']))
    sys.exit(0)
if args[:2] == ['volume', 'ls']:
    for vol in state.get('volumes', []):
        if not vol.get('used'):
            print(vol['name'])
    sys.exit(0)
if args[:2] == ['volume', 'inspect']:
    key = args[3].split('"')[1]
    vol = next(v for v in state['volumes'] if v['name'] == args[4])
    print(vol.get('labels', {}).get(key, ''))
    sys.exit(0)
if args[:3] == ['system', 'df', '-v']:
    print(json.dumps({'Volumes': [{'Name': v['name'], 'Size': v.get('size', '0B')} for v in state.get('volumes', [])]}, separators=(',', ':')))
    sys.exit(0)
if args[:2] == ['volume', 'rm']:
    if len(args) != 3:
        fail('this fake refuses flags such as --force')
    vol = next((v for v in state['volumes'] if v['name'] == args[2]), None)
    if vol is None or vol.get('used'):
        fail('Error response from daemon: volume is in use')
    state['volumes'].remove(vol)
    save()
    sys.exit(0)
if args[:3] == ['compose', 'config', '--images']:
    if state.get('config_fails'):
        sys.exit(1)
    registry, tag = env('HEIMDALL_REGISTRY', 'ghcr.io/danielonet/heimdall'), env('IMAGE_TAG', 'latest')
    print(f'{registry}/sentinel-backend:{tag}')
    print(f'{registry}/frontend:{tag}')
    print('timescale/timescaledb-ha:pg16')
    print('redis:7-alpine')
    sys.exit(0)
if args[:2] == ['image', 'inspect']:
    fmt, ref = args[3], args[4]
    image = find(ref)
    if not image:
        fail(f'Error: No such image: {ref}')
    if fmt == '{{.Id}}':
        print(image['id'])
    elif 'RepoDigests' in fmt:
        for digest in image.get('digests', []):
            print(digest)
    else:
        fail('unsupported format: ' + fmt)
    sys.exit(0)
if args[:2] == ['image', 'ls']:
    if '--filter' in args:                      # dangling=true: images with no name
        for image in state['images']:
            if not image['tags']:
                print(image['id'])
        sys.exit(0)
    repo = args[-1]
    for image in state['images']:
        for name in image['tags']:
            image_repo, tag = name.rsplit(':', 1)
            if image_repo == repo:
                print(f'{tag} {image["id"]}')
        if not image['tags'] and repo in image.get('listed_under', []):     # pulled by digest: <none> tag
            print(f'<none> {image["id"]}')
    sys.exit(0)
if args[:2] == ['image', 'rm']:
    if len(args) != 3:
        fail('this fake refuses flags such as --force: the script must never force a removal')
    ref = args[2]
    image = find(ref)
    if not image:
        fail(f'Error response from daemon: No such image: {ref}')
    if ref in image['tags']:
        if used(image) and len(image['tags']) == 1:
            fail(f'Error response from daemon: conflict: unable to delete {ref} (must be forced) - container abc is using its referenced image')
        image['tags'].remove(ref)
        if not image['tags'] and not used(image):
            state['images'].remove(image)
    else:                                       # removal by id
        if image['tags']:
            fail('Error response from daemon: conflict: unable to delete (must be forced) - image is referenced in multiple repositories')
        if used(image):
            fail('Error response from daemon: conflict: unable to delete (must be forced) - container abc is using its referenced image')
        state['images'].remove(image)
    save()
    print('Deleted')
    sys.exit(0)
sys.exit(0)
'''


@pytest.fixture(scope='module')
def bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp('bundle')
    subprocess.run(['bash', str(ROOT / 'install' / 'make-bundle.sh'), 'v0.2.2'], check=True,
                   env={**os.environ, 'OUT_DIR': str(out)}, capture_output=True)
    return out / 'heimdall-bundle.tar.gz'


class Engine:
    """The fake docker, its state, and an install directory (the extracted bundle) to run setup.sh in."""

    def __init__(self, tmp_path, bundle):
        self.bin = tmp_path / 'bin'
        self.bin.mkdir()
        self.state_path = tmp_path / 'docker-state.json'
        self.home = tmp_path / 'home'
        self.home.mkdir()
        subprocess.run(['tar', '-xzf', str(bundle), '-C', str(self.home), '--strip-components=1'], check=True)
        (self.home / '.env').write_text('IMAGE_TAG=0.2.2\n')
        exe = self.bin / 'docker'
        exe.write_text(FAKE_DOCKER)
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
        self.state = {'images': [], 'containers': []}
        self.save()

    def save(self):
        self.state_path.write_text(json.dumps(self.state))

    def load(self):
        self.state = json.loads(self.state_path.read_text())

    def image(self, image_id, *tags, digests=(), listed_under=()):
        self.state['images'].append({'id': image_id, 'tags': list(tags), 'digests': list(digests), 'listed_under': list(listed_under)})
        self.save()

    def volume(self, name, project=None, label=None, used=False, size='1.5GB'):
        labels = {}
        if project:
            labels['com.docker.compose.project'] = project
        if label:
            labels['com.docker.compose.volume'] = label
        self.state.setdefault('volumes', []).append({'name': name, 'labels': labels, 'used': used, 'size': size})
        self.save()

    def volumes(self):
        self.load()
        return {v['name'] for v in self.state.get('volumes', [])}

    def container(self, image_id):
        self.state['containers'].append({'image': image_id})
        self.save()

    def env_line(self, line):
        with open(self.home / '.env', 'a') as f:
            f.write(line + '\n')

    def tags(self):
        self.load()
        return {name for image in self.state['images'] for name in image['tags']}

    def ids(self):
        self.load()
        return {image['id'] for image in self.state['images']}

    def calls(self):
        log = Path(str(self.state_path) + '.log')
        return log.read_text().splitlines() if log.exists() else []

    def run(self, *args, env=None):
        full_env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE_DOCKER_STATE': str(self.state_path), **(env or {})}
        return subprocess.run(['./setup.sh', *args], cwd=self.home, env=full_env, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL)

    def prune(self, **kw):
        return self.run('--prune-old-images', **kw)


@pytest.fixture
def engine(tmp_path, bundle):
    return Engine(tmp_path, bundle)


def three_versions(engine):
    """The state after an upgrade from 0.2.0 and 0.2.1 to 0.2.2: three backend and two frontend images."""
    engine.image('sha256:be0', f'{BACKEND}:0.2.0')
    engine.image('sha256:be1', f'{BACKEND}:0.2.1')
    engine.image('sha256:be2', f'{BACKEND}:0.2.2')
    engine.image('sha256:fe1', f'{FRONTEND}:0.2.1')
    engine.image('sha256:fe2', f'{FRONTEND}:0.2.2')


def mixed_volumes(engine):
    engine.volume('heimdall_old-service', 'heimdall', 'old-service', size='900MB')      # ours, undeclared, unused: a leftover
    engine.volume('heimdall_busy-old', 'heimdall', 'busy-old', used=True)               # undeclared but a container uses it
    engine.volume('heimdall_pgdata', 'heimdall', 'pgdata', size='4GB')                  # declared, unused (stack is down)
    engine.volume('heimdall_zeek-logs', 'heimdall', 'zeek-logs', size='2GB')            # declared, unused (tier changed)
    engine.volume('oldfolder_pgdata', 'oldfolder', 'pgdata', size='3GB')                # an install in another folder
    engine.volume('someone_else_data', 'otherapp', 'data')                              # another application's volume
    engine.volume('0123abcd')                                                           # anonymous, no labels


class TestOldVolumes:
    def test_after_an_upgrade_they_are_reported_with_sizes_and_nothing_is_removed(self, engine):
        three_versions(engine)
        mixed_volumes(engine)
        r = engine.prune()
        assert r.returncode == 0
        assert 'heimdall_old-service  900MB' in r.stdout and '--prune-old-volumes' in r.stdout
        assert 'oldfolder_pgdata  3GB' in r.stdout and 'heimdall_pgdata  4GB' in r.stdout and 'heimdall_zeek-logs  2GB' in r.stdout
        assert 'someone_else_data' not in r.stdout and '0123abcd' not in r.stdout
        assert len(engine.volumes()) == 7

    def test_prune_old_volumes_removes_only_this_installs_undeclared_unused_ones(self, engine):
        mixed_volumes(engine)
        r = engine.run('--prune-old-volumes')
        assert r.returncode == 0, r.stderr
        assert engine.volumes() == {'heimdall_busy-old', 'heimdall_pgdata', 'heimdall_zeek-logs', 'oldfolder_pgdata',
                                    'someone_else_data', '0123abcd'}
        assert 'Removed old volume heimdall_old-service (900MB)' in r.stdout

    def test_the_database_volume_is_never_removed_even_with_the_stack_down(self, engine):
        engine.volume('heimdall_pgdata', 'heimdall', 'pgdata')
        engine.volume('heimdall_ml-models', 'heimdall', 'ml-models')
        assert engine.run('--prune-old-volumes').returncode == 0
        assert engine.volumes() == {'heimdall_pgdata', 'heimdall_ml-models'}

    def test_never_forces_and_leaves_the_images_alone(self, engine):
        three_versions(engine)
        mixed_volumes(engine)
        engine.run('--prune-old-volumes')
        assert not any('volume rm' in c and (' -f' in c or '--force' in c) for c in engine.calls())
        assert len(engine.tags()) == 5

    def test_says_so_when_there_is_nothing_to_remove(self, engine):
        engine.volume('heimdall_pgdata', 'heimdall', 'pgdata')
        assert 'No old volumes to remove' in engine.run('--prune-old-volumes').stdout

    def test_does_not_combine_with_other_options(self, engine):
        mixed_volumes(engine)
        r = engine.run('--prune-old-volumes', '--tier=minimal')
        assert r.returncode != 0 and 'do not combine' in r.stderr
        assert len(engine.volumes()) == 7


class TestPruneOldImages:
    def test_removes_older_versions_of_both_images_and_keeps_the_current_one(self, engine):
        three_versions(engine)
        r = engine.prune()
        assert r.returncode == 0, r.stderr
        assert engine.tags() == {f'{BACKEND}:0.2.2', f'{FRONTEND}:0.2.2'}
        assert 'Removed 3 older Heimdall image(s)' in r.stdout
        assert f'Removed {BACKEND}:0.2.0' in r.stdout

    def test_never_touches_any_other_image(self, engine):
        three_versions(engine)
        others = {
            'timescale/timescaledb-ha:pg15', 'timescale/timescaledb-ha:pg16', 'redis:6', 'redis:7-alpine', 'thinkst/opencanary:old',
            'example.com/other/frontend:1.0',                 # same image name, someone else's repository
            f'{REG}/frontend-legacy:0.1',                     # a longer name that merely starts like ours
            f'{REG}/sentinel-backend-extra:0.1',
            f'{REG}/something-else:0.1',
        }
        for i, name in enumerate(sorted(others)):
            engine.image(f'sha256:o{i}', name)
        assert engine.prune().returncode == 0
        assert others <= engine.tags()

    def test_keeps_an_old_image_a_container_still_uses_and_says_why(self, engine):
        three_versions(engine)
        engine.container('sha256:be1')
        r = engine.prune()
        assert r.returncode == 0
        assert f'{BACKEND}:0.2.1' in engine.tags()
        assert f'{BACKEND}:0.2.0' not in engine.tags()
        assert f'Kept {BACKEND}:0.2.1' in r.stderr and 'container' in r.stderr

    def test_removes_nothing_when_the_version_in_use_is_not_on_the_machine(self, engine):
        # A failed pull: IMAGE_TAG already says 0.2.2 but only the old images are here. They are all there is.
        engine.image('sha256:be1', f'{BACKEND}:0.2.1')
        engine.image('sha256:fe1', f'{FRONTEND}:0.2.1')
        r = engine.prune()
        assert r.returncode == 0
        assert engine.tags() == {f'{BACKEND}:0.2.1', f'{FRONTEND}:0.2.1'}
        assert 'not on this machine yet' in r.stderr

    def test_removes_nothing_when_only_one_of_the_two_current_images_is_here(self, engine):
        engine.image('sha256:be1', f'{BACKEND}:0.2.1')
        engine.image('sha256:be2', f'{BACKEND}:0.2.2')
        engine.image('sha256:fe1', f'{FRONTEND}:0.2.1')              # the frontend 0.2.2 never arrived
        assert engine.prune().returncode == 0
        assert engine.tags() == {f'{BACKEND}:0.2.1', f'{BACKEND}:0.2.2', f'{FRONTEND}:0.2.1'}

    def test_a_second_name_for_the_image_in_use_is_not_old(self, engine):
        engine.image('sha256:be2', f'{BACKEND}:0.2.2', f'{BACKEND}:latest')
        engine.image('sha256:fe2', f'{FRONTEND}:0.2.2')
        r = engine.prune()
        assert r.returncode == 0
        assert engine.tags() == {f'{BACKEND}:0.2.2', f'{BACKEND}:latest', f'{FRONTEND}:0.2.2'}
        assert 'Removed' not in r.stdout

    def test_removes_untagged_leftovers_of_heimdall_images_only(self, engine):
        # Pulling a moving tag again leaves the old image with no name; its digest says whose it was.
        three_versions(engine)
        engine.image('sha256:u1', digests=[f'{BACKEND}@sha256:aaa'])                       # ours, left by :latest moving
        engine.image('sha256:u2', digests=['example.com/other/app@sha256:bbb'])            # someone else's
        engine.image('sha256:u3')                                                          # a local build, no origin at all
        engine.image('sha256:u4', digests=[f'evil.{BACKEND}@sha256:ccc'])                  # looks like ours but is not
        engine.image('sha256:u5', digests=[f'{FRONTEND}@sha256:ddd'])                      # ours, but a container uses it
        engine.container('sha256:u5')
        assert engine.prune().returncode == 0
        ids = engine.ids()
        assert 'sha256:u1' not in ids
        assert {'sha256:u2', 'sha256:u3', 'sha256:u4', 'sha256:u5'} <= ids

    def test_removes_a_copy_pulled_by_digest_that_has_no_tag(self, engine):
        three_versions(engine)
        engine.image('sha256:d1', listed_under=[BACKEND])
        assert engine.prune().returncode == 0
        assert 'sha256:d1' not in engine.ids()

    @pytest.mark.parametrize('line', ['KEEP_OLD_IMAGES=1', 'KEEP_OLD_IMAGES=true', 'KEEP_OLD_IMAGES=yes'])
    def test_keep_old_images_in_env_keeps_everything(self, engine, line):
        three_versions(engine)
        engine.env_line(line)
        r = engine.prune()
        assert r.returncode == 0
        assert len(engine.tags()) == 5
        assert 'Keeping the images of older versions' in r.stdout

    def test_keep_old_images_in_the_environment_keeps_everything(self, engine):
        three_versions(engine)
        assert engine.prune(env={'HEIMDALL_KEEP_OLD_IMAGES': '1'}).returncode == 0
        assert len(engine.tags()) == 5

    @pytest.mark.parametrize('line', ['KEEP_OLD_IMAGES=0', '# KEEP_OLD_IMAGES=1', 'KEEP_OLD_IMAGES=1 # later', 'XKEEP_OLD_IMAGES=1'])
    def test_anything_but_an_explicit_opt_in_still_prunes(self, engine, line):
        # The generated .env carries the opt-out commented out; that must not count as opting out.
        three_versions(engine)
        engine.env_line(line)
        assert engine.prune().returncode == 0
        assert engine.tags() == {f'{BACKEND}:0.2.2', f'{FRONTEND}:0.2.2'}

    def test_a_custom_registry_is_pruned_and_the_default_one_is_left_alone(self, engine):
        mirror = 'registry.example/heimdall'
        engine.env_line(f'HEIMDALL_REGISTRY={mirror}')
        engine.image('sha256:m0', f'{mirror}/sentinel-backend:0.2.0')
        engine.image('sha256:m2', f'{mirror}/sentinel-backend:0.2.2')
        engine.image('sha256:mf2', f'{mirror}/frontend:0.2.2')
        engine.image('sha256:d0', f'{BACKEND}:0.2.0')                # the public registry's copy: not the one in use
        assert engine.prune().returncode == 0
        assert engine.tags() == {f'{mirror}/sentinel-backend:0.2.2', f'{mirror}/frontend:0.2.2', f'{BACKEND}:0.2.0'}

    def test_never_forces_a_removal(self, engine):
        three_versions(engine)
        engine.container('sha256:be1')
        engine.prune()
        removals = [c for c in engine.calls() if c.startswith('image rm')]
        assert removals
        assert not any(' -f' in c or '--force' in c for c in removals)

    def test_a_second_run_changes_nothing_and_is_quiet_when_not_on_a_terminal(self, engine):
        three_versions(engine)
        engine.prune()
        before = engine.tags()
        r = engine.prune()
        assert r.returncode == 0 and engine.tags() == before
        assert r.stdout == '' and r.stderr == ''

    def test_a_docker_that_cannot_list_its_images_is_a_warning_not_a_failure(self, engine):
        three_versions(engine)
        engine.state['config_fails'] = True
        engine.save()
        r = engine.prune()
        assert r.returncode == 0
        assert len(engine.tags()) == 5
        assert 'no old images removed' in r.stderr

    def test_does_not_combine_with_other_options(self, engine):
        three_versions(engine)
        r = engine.run('--prune-old-images', '--tier=minimal')
        assert r.returncode != 0 and 'do not combine' in r.stderr
        assert len(engine.tags()) == 5

    def test_help_documents_the_option_and_prints_the_whole_header(self, engine):
        r = engine.run('--help')
        assert r.returncode == 0
        assert '--prune-old-images' in r.stdout
        assert 'KEEP_OLD_IMAGES=1' in r.stdout                  # the last sentence of the header: nothing is cut off
        assert 'set -euo pipefail' not in r.stdout


@pytest.mark.skipif(shutil.which('docker') is None or subprocess.run(['docker', 'info'], capture_output=True).returncode != 0,
                    reason='no running Docker engine')
class TestAgainstTheRealEngine:
    """The same script, the real `docker compose config --images`, `image ls`, `image inspect` and `image rm`.

    Throwaway images are built with `docker import` (no network) under a unique localhost/ registry name set as
    HEIMDALL_REGISTRY, so the prune can only ever see these. A decoy tag in a third-party repository must survive.
    """

    def test_prunes_old_versions_keeps_the_rest(self, bundle, tmp_path):
        reg = f'localhost/heimdall-prunetest-{uuid.uuid4().hex[:10]}'
        decoy = f'redis:prunetest-decoy-{uuid.uuid4().hex[:10]}'
        container = f'heimdall-prunetest-{uuid.uuid4().hex[:10]}'
        created = []

        def make(ref):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode='w') as tar:
                data = ref.encode()
                info = tarfile.TarInfo('marker')
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            subprocess.run(['docker', 'import', '-', ref], input=buf.getvalue(), check=True, capture_output=True)
            created.append(ref)

        def present():
            out = subprocess.run(['docker', 'image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'], check=True, capture_output=True, text=True)
            return {line for line in out.stdout.split() if line.startswith(reg) or line == decoy}

        home = tmp_path / 'home'
        home.mkdir()
        subprocess.run(['tar', '-xzf', str(bundle), '-C', str(home), '--strip-components=1'], check=True)
        (home / '.env').write_text(f'IMAGE_TAG=0.2.2\nHEIMDALL_REGISTRY={reg}\n')
        try:
            for ref in (f'{reg}/sentinel-backend:0.2.0', f'{reg}/sentinel-backend:0.2.1', f'{reg}/sentinel-backend:0.2.2',
                        f'{reg}/frontend:0.2.1', f'{reg}/frontend:0.2.2', f'{reg}/other:0.1', decoy):
                make(ref)
            subprocess.run(['docker', 'create', '--name', container, f'{reg}/sentinel-backend:0.2.1', '/bin/true'], check=True, capture_output=True)

            r = subprocess.run(['./setup.sh', '--prune-old-images'], cwd=home, capture_output=True, text=True, stdin=subprocess.DEVNULL)
            assert r.returncode == 0, r.stderr
            assert present() == {
                f'{reg}/sentinel-backend:0.2.1',        # old, but a container uses it: Docker refuses and the script keeps it
                f'{reg}/sentinel-backend:0.2.2', f'{reg}/frontend:0.2.2',
                f'{reg}/other:0.1', decoy,
            }
            assert f'Kept {reg}/sentinel-backend:0.2.1' in r.stderr

            subprocess.run(['docker', 'rm', container], check=True, capture_output=True)
            r = subprocess.run(['./setup.sh', '--prune-old-images'], cwd=home, capture_output=True, text=True, stdin=subprocess.DEVNULL)
            assert r.returncode == 0, r.stderr
            assert present() == {f'{reg}/sentinel-backend:0.2.2', f'{reg}/frontend:0.2.2', f'{reg}/other:0.1', decoy}
        finally:
            subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
            for ref in created:
                subprocess.run(['docker', 'image', 'rm', '-f', ref], capture_output=True)
