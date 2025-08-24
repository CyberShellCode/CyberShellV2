from dataclasses import dataclass, field
from typing import Dict
import time
@dataclass
class RunMetrics:
    start_ts: float = field(default_factory=time.time)
    steps: int = 0
    success: int = 0
    fail: int = 0
    def log_step(self, ok: bool) -> None:
        self.steps += 1
        self.success += int(ok)
        self.fail += int(not ok)

    def summary(self) -> dict[str, float | int]:
