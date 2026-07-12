import hashlib
import secrets

# Session options carried on every logIn action, reverse-engineered byte-for-byte
# from this router's own web GUI (js/gui-api.js) — the router rejects logIn
# actions missing any of these keys.
_LOGIN_SESSION_OPTIONS = {
    'nss': [{'name': 'gtw', 'uri': 'http://sagemcom.com/gateway-data'}],
    'context-flags': {'get-content-name': True, 'local-time': True},
    'capability-depth': 2,
    'capability-flags': {
        'name': True,
        'default-value': False,
        'restriction': True,
        'description': False,
    },
    'time-format': 'ISO_8601',
    'jwt-auth': 'true',
}


class XmoAuth:
    """Manages XMO session state and computes per-request auth keys.

    Reverse-engineered from the router's own `js/gui-api.js` (the XMO docs'
    description of a bare session-id=0/empty-auth-key handshake does not work
    against real F@st 5670 firmware — it always replies with
    XMO_INVALID_SESSION_ERR). The real scheme, confirmed against a live
    router:

      1. HA1 = MD5( f"{username}:{nonce}:{MD5(password)}" )
         `nonce` is '' until a session has been established.
      2. auth-key = MD5( f"{HA1}:{request_id}:{cnonce}:JSON:/cgi/json-req" )
      3. Login sends a `logIn` action (user + fixed session-options, no
         password field — the password is only ever expressed through the
         auth-key hash) with session-id=0 and the HA1 computed with nonce=''.
      4. On success the response carries a *new* session-id and *server
         nonce* in `actions[0].callbacks[0].parameters` (not `reply.uid`,
         despite what the docs say). HA1 must be recomputed with that nonce
         for every request for the rest of the session.
      5. On error 16777219 (XMO_INVALID_SESSION_ERR) → re-login and recompute.
    """

    def __init__(self, password: str, username: str = 'admin') -> None:
        self._password = password
        self._username = username
        self._pwd_hash = hashlib.md5(password.encode()).hexdigest()
        self.session_id: int = 0
        self.request_id: int = 0
        self._nonce: str = ''

    def update_nonce(self, nonce: str) -> None:
        """Store the server-issued nonce from a successful logIn.

        HA1 (and therefore every subsequent auth-key) depends on this value
        for the rest of the session.
        """
        self._nonce = nonce

    def compute_ha1(self) -> str:
        """Return MD5(username:nonce:MD5(password))."""
        return hashlib.md5(f'{self._username}:{self._nonce}:{self._pwd_hash}'.encode()).hexdigest()

    def compute_auth_key(self, request_id: int, cnonce: int) -> str:
        """Return MD5(HA1:request_id:cnonce:JSON:/cgi/json-req)."""
        return hashlib.md5(
            f'{self.compute_ha1()}:{request_id}:{cnonce}:JSON:/cgi/json-req'.encode()
        ).hexdigest()

    def build_envelope(self, actions: list) -> dict:
        """Build a signed request envelope for the given actions."""
        cnonce = secrets.randbelow(2 ** 31)
        req_id = self.request_id
        env = {
            'request': {
                'id': req_id,
                'session-id': self.session_id,
                'priority': False,
                'actions': actions,
                'cnonce': cnonce,
                'auth-key': self.compute_auth_key(req_id, cnonce),
            }
        }
        self.request_id += 1
        return env

    def build_login_envelope(self) -> dict:
        """Build the login envelope: a `logIn` action, session-id=0, and an
        auth-key computed with a blank nonce (matches a fresh, unauthenticated
        HA1). Must be called before the first authenticated request.
        """
        self._nonce = ''
        cnonce = secrets.randbelow(2 ** 31)
        req_id = self.request_id
        env = {
            'request': {
                'id': req_id,
                'session-id': 0,
                'priority': True,
                'actions': [{
                    'id': 0,
                    'method': 'logIn',
                    'parameters': {
                        'user': self._username,
                        'persistent': 'true',
                        'session-options': _LOGIN_SESSION_OPTIONS,
                    },
                }],
                'cnonce': cnonce,
                'auth-key': self.compute_auth_key(req_id, cnonce),
            }
        }
        self.request_id += 1
        return env
