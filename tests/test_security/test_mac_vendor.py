from sentinel.security.mac_vendor import is_locally_administered, lookup_vendor


class TestIsLocallyAdministered:
    def test_universally_administered_address_is_false(self):
        assert is_locally_administered('00:1a:2b:cc:dd:ee') is False

    def test_locally_administered_bit_set_is_true(self):
        # 0x02 = 00000010 — U/L bit (bit 1) set
        assert is_locally_administered('02:00:00:00:00:00') is True

    def test_randomized_phone_mac_is_true(self):
        # 0xda = 11011010 — U/L bit set; this pattern is common on modern
        # phones using WiFi MAC randomization for privacy
        assert is_locally_administered('da:d4:19:31:c0:e9') is True

    def test_case_insensitive(self):
        assert is_locally_administered('DA:D4:19:31:C0:E9') is True

    def test_malformed_mac_returns_false(self):
        assert is_locally_administered('') is False
        assert is_locally_administered('not-a-mac') is False


class TestLookupVendor:
    def test_known_oui_returns_vendor_name(self):
        vendor = lookup_vendor('00:1a:2b:cc:dd:ee')
        assert vendor != ''
        assert 'ayecom' in vendor.lower()

    def test_locally_administered_mac_returns_empty(self):
        # Randomized MACs have no real manufacturer to resolve.
        assert lookup_vendor('da:d4:19:31:c0:e9') == ''

    def test_unrecognized_oui_returns_empty(self):
        # ff:ff:fe is not an assigned IEEE OUI.
        assert lookup_vendor('ff:ff:fe:00:00:00') == ''

    def test_empty_mac_returns_empty(self):
        assert lookup_vendor('') == ''

    def test_case_insensitive(self):
        assert lookup_vendor('00:1A:2B:CC:DD:EE').lower() == lookup_vendor('00:1a:2b:cc:dd:ee').lower()
