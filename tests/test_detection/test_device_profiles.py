from sentinel.detection.device_profiles import DEFAULT_PROFILE, get_profile


class TestGetProfile:
    def test_unknown_device_type_returns_default(self):
        assert get_profile('Some Unrecognized Router String') == DEFAULT_PROFILE

    def test_blank_device_type_returns_default(self):
        assert get_profile('') == DEFAULT_PROFILE

    def test_none_device_type_returns_default(self):
        assert get_profile(None) == DEFAULT_PROFILE

    def test_nas_gets_a_more_lenient_ratio_and_streak(self):
        profile = get_profile('Network Attached Storage')
        assert profile['high_upload_ratio_threshold'] > DEFAULT_PROFILE['high_upload_ratio_threshold']
        assert profile['volume_sustained_polls'] > DEFAULT_PROFILE['volume_sustained_polls']

    def test_ip_camera_gets_a_more_lenient_ratio_and_streak(self):
        profile = get_profile('IP Camera')
        assert profile['high_upload_ratio_threshold'] > DEFAULT_PROFILE['high_upload_ratio_threshold']
        assert profile['volume_sustained_polls'] > DEFAULT_PROFILE['volume_sustained_polls']

    def test_printer_gets_a_stricter_ratio_and_streak(self):
        profile = get_profile('Printer')
        assert profile['high_upload_ratio_threshold'] < DEFAULT_PROFILE['high_upload_ratio_threshold']
        assert profile['volume_sustained_polls'] < DEFAULT_PROFILE['volume_sustained_polls']

    def test_smartphone_only_overrides_ratio_not_streak(self):
        profile = get_profile('Smartphone')
        assert profile['high_upload_ratio_threshold'] < DEFAULT_PROFILE['high_upload_ratio_threshold']
        assert profile['volume_sustained_polls'] == DEFAULT_PROFILE['volume_sustained_polls']
