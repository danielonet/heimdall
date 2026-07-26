from sentinel.security.os_classification import os_family


class TestOsFamily:
    def test_blank_is_unknown(self):
        assert os_family('') == 'unknown'

    def test_none_is_unknown(self):
        assert os_family(None) == 'unknown'

    def test_literal_unknown_string_is_unknown(self):
        assert os_family('Unknown') == 'unknown'

    def test_passive_windows_string(self):
        assert os_family('Windows') == 'windows'

    def test_nmap_windows_osmatch_string(self):
        assert os_family('Microsoft Windows 10 1607') == 'windows'

    def test_passive_linux_android_string(self):
        assert os_family('Linux / Android') == 'linux_android'

    def test_nmap_linux_osmatch_string(self):
        assert os_family('Linux 3.10 - 4.11') == 'linux_android'

    def test_android_only_string(self):
        assert os_family('Android 12') == 'linux_android'

    def test_passive_macos_ios_string(self):
        assert os_family('macOS / iOS') == 'macos_ios'

    def test_nmap_darwin_osmatch_string(self):
        assert os_family('Apple macOS Darwin') == 'macos_ios'

    def test_unrecognized_os_string_is_other(self):
        assert os_family('FreeBSD 13') == 'other'

    def test_case_insensitive(self):
        assert os_family('WINDOWS SERVER 2019') == 'windows'
