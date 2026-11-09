"""A fixture-driven stand-in for a web-managed switch, served through httpx.MockTransport.

It behaves like the real switch where behaviour matters to the driver: pages need a login, a logged-out request
gets the login redirect page with HTTP 200 (not a 401), the pages beyond the public ones need a Referer header,
and the login can be rejected or the session can end. Fixture folders under tests/fixtures/switches/<id>/ describe
the routes; see tests/fixtures/switches/hc-swtgw218as/fixture.json.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl

import httpx

from sentinel.switches.web import template

FIXTURES_DIR = Path(__file__).resolve().parent.parent / 'fixtures' / 'switches'


def fixture_dirs() -> list[Path]:
    """Every fixture folder (one per switch model)."""
    return sorted(p for p in FIXTURES_DIR.iterdir() if (p / 'fixture.json').is_file())


class SwitchSimulator:
    """Serves one fixture folder."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.fixture = json.loads((folder / 'fixture.json').read_text())
        self.expected = json.loads((folder / 'expected.json').read_text())
        sim = self.fixture['simulator']
        self.username: str = self.fixture['username']
        self.password: str = self.fixture['password']
        self.host: str = self.fixture['host']
        variables = {'username': self.username, 'password': self.password, 'host': self.host,
                     'base_url': f'http://{self.host}'}
        self._cookie_name: str = sim['auth_cookie']['name']
        self._cookie_value = template.render(sim['auth_cookie']['value'], variables)
        self._login_path: str = sim['login']['path']
        self._login_ok = self._read(sim['login']['ok_body'])
        self._logged_out = self._read(sim['logged_out_body'])
        self._require_referer: bool = sim.get('require_referer', False)
        self._public: set[str] = set(sim.get('public_paths', []))
        self.session_valid = False
        self.reject_login = False
        self.overrides: dict[tuple[str, str], httpx.Response | str] = {}
        self.calls: Counter[tuple[str, str]] = Counter()
        self.requests: list[httpx.Request] = []

    def _read(self, relative: str) -> str:
        return (self.folder / relative).read_text(encoding='utf-8')

    def transport(self) -> httpx.MockTransport:
        """The transport to hand to the driver."""
        return httpx.MockTransport(self.handler)

    def expire_session(self) -> None:
        """The switch forgets the login (expiry, a reboot, another login)."""
        self.session_valid = False

    def login_count(self) -> int:
        """How many times the login form was posted."""
        return self.calls[('POST', self._login_path)]

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Answer one request the way the switch would."""
        self.requests.append(request)
        path = request.url.raw_path.decode()
        bare = request.url.path
        form = dict(parse_qsl(request.content.decode())) if request.method == 'POST' else {}
        self.calls[(request.method, bare)] += 1

        if request.method == 'POST' and bare == self._login_path:
            accepted = (not self.reject_login and form.get('username') == self.username
                        and form.get('password') == self.password)
            self.session_valid = accepted
            return httpx.Response(200, text=self._login_ok)

        if bare not in self._public and self._require_referer and 'referer' not in request.headers:
            return httpx.Response(404, content=b'\r\n')
        if not self._authenticated(request):
            return httpx.Response(200, text=self._logged_out)
        if bare in self._public:
            return httpx.Response(200, text='<html></html>')

        key = (request.method, path)
        if key in self.overrides:
            override = self.overrides[key]
            return override if isinstance(override, httpx.Response) else httpx.Response(200, text=override)
        for route in self.fixture['routes']:
            if route['method'] == request.method and route['path'] == path and route.get('form', {}).items() <= form.items():
                bodies = route['bodies']
                served = self.calls_for(route)
                return httpx.Response(200, text=self._read(bodies[min(served, len(bodies) - 1)]))
        return httpx.Response(404, content=b'\r\n')

    def calls_for(self, route: dict) -> int:
        """How many times this route was served before the current request."""
        self._served = getattr(self, '_served', Counter())
        ident = (route['method'], route['path'], json.dumps(route.get('form', {}), sort_keys=True))
        count = self._served[ident]
        self._served[ident] += 1
        return count

    def _authenticated(self, request: httpx.Request) -> bool:
        cookie = request.headers.get('cookie', '')
        return self.session_valid and f'{self._cookie_name}={self._cookie_value}' in cookie
