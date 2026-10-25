from sentinel.config import secret_file_writable, write_secret_file

import pytest


class TestWriteSecretFile:
    def test_writes_the_value_stripped_with_trailing_newline(self, tmp_path):
        path = tmp_path / 'secret.txt'
        write_secret_file(str(path), '  hunter2  ')
        assert path.read_text() == 'hunter2\n'

    def test_overwrites_an_existing_file(self, tmp_path):
        path = tmp_path / 'secret.txt'
        path.write_text('old\n')
        write_secret_file(str(path), 'new')
        assert path.read_text() == 'new\n'

    def test_creates_the_file_if_it_does_not_exist(self, tmp_path):
        path = tmp_path / 'does-not-exist-yet.txt'
        assert not path.exists()
        write_secret_file(str(path), 'value')
        assert path.read_text() == 'value\n'

    def test_blank_path_raises(self):
        with pytest.raises(ValueError):
            write_secret_file('', 'value')


class TestSecretFileWritable:
    def test_blank_path_is_not_writable(self):
        assert secret_file_writable('') is False

    def test_existing_writable_file(self, tmp_path):
        f = tmp_path / 'secret.txt'
        f.write_text('x')
        assert secret_file_writable(str(f)) is True

    def test_missing_file_in_writable_directory(self, tmp_path):
        assert secret_file_writable(str(tmp_path / 'new_secret.txt')) is True

    def test_read_only_file(self, tmp_path):
        import os
        if os.geteuid() == 0:
            pytest.skip('root bypasses file permissions')
        f = tmp_path / 'secret.txt'
        f.write_text('x')
        f.chmod(0o444)
        assert secret_file_writable(str(f)) is False
