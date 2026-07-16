from sentinel.config import write_secret_file

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
