import hashlib

import pytest

from sentinel.switches.web.template import TemplateError, check, render

VARS = {'username': 'admin', 'password': 'hunter2', 'base_url': 'http://192.168.0.2'}


def test_md5_of_user_plus_password_matches_hashlib():
    assert render('${md5(username + password)}', VARS) == hashlib.md5(b'adminhunter2').hexdigest()


def test_text_around_the_expression_is_kept_and_literals_work():
    assert render('${base_url}/info.cgi', VARS) == 'http://192.168.0.2/info.cgi'
    assert render("x-${upper(username) + '-' + lower('AB')}-y", VARS) == 'x-ADMIN-ab-y'


def test_plain_text_without_an_expression_is_returned_unchanged():
    assert render('EN', VARS) == 'EN'


@pytest.mark.parametrize('bad', [
    '${__import__("os")}', '${os.system}', '${open(username)}', '${md5(', '${username +}', '${nope}',
    '${md5(username) md5(password)}', '${username', '${1 + 1}', '${username.upper()}',
])
def test_anything_outside_the_whitelist_is_rejected(bad):
    with pytest.raises(TemplateError):
        render(bad, VARS)


def test_check_validates_without_real_values():
    check('${md5(username + password)}', {'username', 'password'})
    with pytest.raises(TemplateError):
        check('${md5(username + secret)}', {'username', 'password'})
