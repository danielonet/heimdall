"""Persists per-device anomaly models to disk so they survive restarts."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import joblib


class ModelStore:
    """Loads/saves the {'iso': IsolationForest, 'lof': LOF} dict for one device."""

    def __init__(self, model_dir: str) -> None:
        self._model_dir = Path(model_dir)

    def load(self, mac: str) -> Optional[dict[str, Any]]:
        """Return the saved models for this MAC, or None if never trained."""
        path = self._path_for(mac)
        if path.exists():
            return joblib.load(path)
        return None

    def save(self, mac: str, models: dict[str, Any]) -> None:
        """Persist this MAC's models, overwriting any previous version."""
        self._model_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(models, self._path_for(mac))

    def _path_for(self, mac: str) -> Path:
        return self._model_dir / f'{mac.replace(":", "-")}.joblib'

    def delete(self, mac: str) -> None:
        """Remove one device's persisted model file, if any — used when a
        device is permanently purged (see DeviceRepository.purge_archived)
        so a deleted device doesn't leave an orphaned model file behind
        forever. Safe to call for a MAC that was never trained (no-op)."""
        path = self._path_for(mac)
        if path.exists():
            path.unlink()

    def clear_all(self) -> None:
        """Delete every persisted model file — used when purging the database
        so every device restarts its learning period from scratch instead of
        continuing to score against a model trained on data that no longer
        exists."""
        if not self._model_dir.exists():
            return
        for path in self._model_dir.glob('*.joblib'):
            path.unlink()
