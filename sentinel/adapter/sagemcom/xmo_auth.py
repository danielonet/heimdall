import hashlib
import secrets


class XmoAuth:
    """Manages XMO session state and computes per-request auth keys.

    The XMO protocol uses a challenge-response scheme:
      1. Initial request: session-id=0, auth-key="" → router returns session-id
      2. Subsequent requests: auth-key = MD5(MD5(password) + ":" + cnonce)
      3. On error 16777219 (auth failure) → re-login and recompute
    """

    def __init__(self, password: str) -> None:
        self._password = password
        self.session_id: int = 0
        self.request_id: int = 1

    def compute_auth_key(self, cnonce: int) -> str:
        """Return MD5(MD5(password):cnonce)."""
        pwd_hash = hashlib.md5(self._password.encode()).hexdigest()
        return hashlib.md5(f'{pwd_hash}:{cnonce}'.encode()).hexdigest()

    def build_envelope(self, actions: list) -> dict:
        """Build a signed request envelope for the given actions."""
        cnonce = secrets.randbelow(2 ** 31)
        env = {
            'request': {
                'id': self.request_id,
                'session-id': self.session_id,
                'priority': False,
                'actions': actions,
                'cnonce': cnonce,
                'auth-key': self.compute_auth_key(cnonce),
            }
        }
        self.request_id += 1
        return env

    def build_login_envelope(self) -> dict:
        """Build the initial handshake envelope (session-id=0, empty auth-key).

        Sends session-id=0 with an empty auth-key to obtain a fresh session-id
        from the router. Must be called before the first authenticated request.
        """
        env = {
            'request': {
                'id': self.request_id,
                'session-id': 0,
                'priority': False,
                'actions': [],
                'cnonce': secrets.randbelow(2 ** 31),
                'auth-key': '',
            }
        }
        self.request_id += 1
        return env
