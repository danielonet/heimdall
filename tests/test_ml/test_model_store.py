from sentinel.ml.model_store import ModelStore


class TestModelStore:
    def test_load_missing_model_returns_none(self, tmp_path):
        store = ModelStore(str(tmp_path))
        assert store.load('aa:bb:cc:dd:ee:ff') is None

    def test_save_then_load_round_trips(self, tmp_path):
        store = ModelStore(str(tmp_path))
        models = {'iso': 'fake-iso-model', 'lof': 'fake-lof-model'}
        store.save('aa:bb:cc:dd:ee:ff', models)

        loaded = store.load('aa:bb:cc:dd:ee:ff')
        assert loaded == models

    def test_mac_colons_sanitised_in_filename(self, tmp_path):
        store = ModelStore(str(tmp_path))
        store.save('aa:bb:cc:dd:ee:ff', {'iso': 1, 'lof': 2})
        assert (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    def test_creates_model_dir_if_missing(self, tmp_path):
        nested = tmp_path / 'nested' / 'models'
        store = ModelStore(str(nested))
        store.save('aa:bb:cc:dd:ee:ff', {'iso': 1, 'lof': 2})
        assert nested.exists()

    def test_devices_are_independent(self, tmp_path):
        store = ModelStore(str(tmp_path))
        store.save('aa:aa:aa:aa:aa:aa', {'iso': 'A'})
        store.save('bb:bb:bb:bb:bb:bb', {'iso': 'B'})
        assert store.load('aa:aa:aa:aa:aa:aa') == {'iso': 'A'}
        assert store.load('bb:bb:bb:bb:bb:bb') == {'iso': 'B'}
