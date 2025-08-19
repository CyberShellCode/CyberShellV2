
from dataclasses import dataclass
from typing import Any
import joblib, os
@dataclass
class ModelStore:
    path: str = "cybershell_mapper.joblib"
    def save(self, model: Any):
        joblib.dump(model, self.path)
    def load(self):
        return joblib.load(self.path) if os.path.exists(self.path) else None
