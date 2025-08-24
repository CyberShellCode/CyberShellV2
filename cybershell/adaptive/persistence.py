
from dataclasses import dataclass
from typing import Any
import os
import joblib
@dataclass
class ModelStore:
    path: str = "cybershell_mapper.joblib"
    def save(self, model: Any):
        joblib.dump(model, self.path)
    def load(self) -> Optional[T]:
        p = Path(self.path)
        if not p.exists():
            return None
        try:
            return joblib.load(p)
        except Exception:
            # TODO: optionally log here (e.g., logging.getLogger(__name__).warning(...))
            return None
