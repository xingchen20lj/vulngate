"""Checkpoint store: stage state files + artifacts for breakpoint resume."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class CheckpointStore:
    def __init__(self, workspace: Path, target: str, round_no: int):
        self.workspace = workspace.resolve()
        self.target = target
        self.round_no = round_no
        self.base = workspace / "state" / target / ("round-%02d" % round_no)
        self.base.mkdir(parents=True, exist_ok=True)

    def stage_file(self, stage: str) -> Path:
        return self.base / ("stage-%s.json" % stage)

    def load_stage(self, stage: str) -> Optional[Dict[str, Any]]:
        f = self.stage_file(stage)
        if f.exists():
            return json.loads(f.read_text(encoding="utf-8"))
        return None

    def save_stage(self, stage: str, data: Dict[str, Any]) -> Path:
        data.setdefault("stage", stage)
        data["updated_at"] = datetime.now().isoformat(timespec="seconds")
        f = self.stage_file(stage)
        self._atomic_write(f, json.dumps(data, indent=2, ensure_ascii=False))
        return f

    def completed_stages(self) -> List[str]:
        stages = []
        for f in sorted(self.base.glob("stage-S*.json")):
            stages.append(f.stem.split("-", 1)[1])
        return stages

    def artifact_path(self, stage: str, name: str) -> Path:
        d = self.base / stage
        d.mkdir(parents=True, exist_ok=True)
        return d / name

    def write_artifact(self, stage: str, name: str, data: Any) -> Path:
        f = self.artifact_path(stage, name)
        if isinstance(data, (dict, list)):
            content = json.dumps(data, indent=2, ensure_ascii=False)
        else:
            content = str(data)
        self._atomic_write(f, content)
        return f

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        """Prevent a killed/concurrent stage from leaving truncated evidence."""
        tmp = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)

    def read_artifact(self, stage: str, name: str) -> Any:
        f = self.artifact_path(stage, name)
        if not f.exists():
            return None
        if f.suffix == ".json":
            return json.loads(f.read_text(encoding="utf-8"))
        return f.read_text(encoding="utf-8")

    def approval_log(self) -> Path:
        return self.base / "approval-log.jsonl"
