"""Value templates for switch definitions: "${md5(username + password)}".

A definition is data, not code, so this is a tiny whitelist evaluator and never eval(): variables, string
literals, `+` to concatenate, and a fixed set of functions. Anything else is rejected when the definition is
loaded, so a community-contributed definition cannot run anything.

    text := (literal | "${" expr "}")*
    expr := term ("+" term)*
    term := NAME | 'string' | "string" | NAME "(" expr ")"
"""
from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable, Mapping

_TOKEN = re.compile(r"""\s*(?:(?P<name>[A-Za-z_][A-Za-z0-9_]*)|(?P<str>'[^']*'|"[^"]*")|(?P<op>[+()]))""")

FUNCTIONS: dict[str, Callable[[str], str]] = {
    'md5': lambda s: hashlib.md5(s.encode()).hexdigest(),
    'sha1': lambda s: hashlib.sha1(s.encode()).hexdigest(),
    'sha256': lambda s: hashlib.sha256(s.encode()).hexdigest(),
    'base64': lambda s: base64.b64encode(s.encode()).decode(),
    'upper': str.upper,
    'lower': str.lower,
}


class TemplateError(ValueError):
    """A template that is malformed, or uses a variable or function that does not exist."""


def _tokenize(expr: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        if not expr[pos:].strip():
            break
        match = _TOKEN.match(expr, pos)
        if not match:
            raise TemplateError(f'unexpected character in template expression {expr!r} at {pos}')
        kind = match.lastgroup or ''
        tokens.append((kind, match.group(kind)))
        pos = match.end()
    return tokens


class _Parser:
    """Recursive-descent evaluator for one ${…} expression."""

    def __init__(self, tokens: list[tuple[str, str]], variables: Mapping[str, str]) -> None:
        self._tokens = tokens
        self._pos = 0
        self._vars = variables

    def parse(self) -> str:
        """Evaluate the whole expression; trailing tokens are an error."""
        value = self._expr()
        if self._pos != len(self._tokens):
            raise TemplateError(f'unexpected {self._tokens[self._pos][1]!r} in template expression')
        return value

    def _peek(self) -> tuple[str, str] | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _expr(self) -> str:
        value = self._term()
        while self._peek() == ('op', '+'):
            self._pos += 1
            value += self._term()
        return value

    def _term(self) -> str:
        token = self._peek()
        if token is None:
            raise TemplateError('template expression ends too early')
        self._pos += 1
        kind, text = token
        if kind == 'str':
            return text[1:-1]
        if kind != 'name':
            raise TemplateError(f'unexpected {text!r} in template expression')
        if self._peek() == ('op', '('):
            func = FUNCTIONS.get(text)
            if func is None:
                raise TemplateError(f'unknown function {text!r} (allowed: {", ".join(sorted(FUNCTIONS))})')
            self._pos += 1
            inner = self._expr()
            if self._peek() != ('op', ')'):
                raise TemplateError(f'missing ")" after {text}(…')
            self._pos += 1
            return func(inner)
        if text not in self._vars:
            raise TemplateError(f'unknown variable {text!r} (allowed: {", ".join(sorted(self._vars))})')
        return self._vars[text]


def render(text: str, variables: Mapping[str, str]) -> str:
    """Fill every ${…} in `text`. Raises TemplateError for anything outside the whitelist."""
    out: list[str] = []
    pos = 0
    while True:
        start = text.find('${', pos)
        if start < 0:
            out.append(text[pos:])
            break
        end = text.find('}', start)
        if end < 0:
            raise TemplateError(f'unterminated ${{ in {text!r}')
        out.append(text[pos:start])
        out.append(_Parser(_tokenize(text[start + 2:end]), variables).parse())
        pos = end + 1
    return ''.join(out)


def check(text: str, variable_names: set[str]) -> None:
    """Validate a template at definition-load time, with dummy values."""
    render(text, {name: 'x' for name in variable_names})
