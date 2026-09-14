"""
utils/checkpoint.py
Tracks per-target scan progress so an interrupted run can resume with --resume
instead of starting from scratch.
"""

import json
from pathlib import Path
from utils.logger import get_logger

log = get_logger("checkpoint")


class CheckpointManager:
    def __init__(self, output_dir: str, resume: bool = False):
        self.checkpoint_file = Path(output_dir) / ".checkpoint.json"
        self.resume = resume
        self.checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._load_all()

    def _load_all(self) -> dict:
        if self.checkpoint_file.exists():
            try:
                return json.loads(self.checkpoint_file.read_text())
            except json.JSONDecodeError:
                log.warning("Checkpoint file corrupted, starting fresh")
        return {}

    def _flush(self):
        self.checkpoint_file.write_text(json.dumps(self._data, indent=2))

    def load(self, target: str) -> dict:
        """Return saved state for a target, or empty state if not resuming / not found."""
        if not self.resume:
            return {}
        state = self._data.get(target, {})
        if state.get("complete"):
            log.info(f"[{target}] Already marked complete in checkpoint, will re-run report stage only")
        return state

    def save(self, target: str, stage: int, data: dict):
        self._data[target] = {"stage": stage, "data": data, "complete": False}
        self._flush()

    def mark_complete(self, target: str):
        if target in self._data:
            self._data[target]["complete"] = True
        else:
            self._data[target] = {"complete": True}
        self._flush()