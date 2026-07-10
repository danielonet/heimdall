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
