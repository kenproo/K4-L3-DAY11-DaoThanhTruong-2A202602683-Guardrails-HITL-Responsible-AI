"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


import time


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None) -> str:
        """Store input + start timestamp keyed by request_id/user_id."""
        req_id = request_id or f"req-{user_id}-{len(self.logs)+len(self._open)+1}"
        self._open[req_id] = {
            "request_id": req_id,
            "user_id": user_id,
            "input": text,
            "start_time": time.time(),
            "timestamp": utc_now_iso(),
        }
        return req_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ) -> dict:
        """Store output, layer decision, latency; append to self.logs."""
        start_info = self._open.pop(request_id, None) if request_id else None
        latency_ms = None
        input_text = None
        if start_info:
            latency_ms = round((time.time() - start_info.get("start_time", time.time())) * 1000, 2)
            input_text = start_info.get("input")

        entry = {
            "request_id": request_id or (start_info.get("request_id") if start_info else f"req-{user_id}-{len(self.logs)+1}"),
            "user_id": user_id,
            "input": input_text,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
            "timestamp": utc_now_iso(),
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None) -> Path:
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        out_path = Path(filepath or default_audit_log_path())
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8")
        return out_path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
