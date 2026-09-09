"""Tamper-evident, hash-chained audit log and SHA-256 run manifest.

Each log entry is a JSON line containing the SHA-256 of the previous
entry's canonical JSON. Modifying, deleting, or reordering any entry
breaks the chain and is detected by verify_chain().
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64


def _canonical(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def _entry_hash(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only hash-chained JSONL audit log."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS_HASH
        last_line = self.path.read_text(encoding="utf-8").rstrip("\n").splitlines()[-1]
        return _entry_hash(json.loads(last_line))

    def append(self, event: str, detail: dict | None = None, timestamp: str | None = None) -> dict:
        entry = {
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "event": event,
            "detail": detail or {},
            "prev_hash": self._last_hash(),
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(_canonical(entry) + "\n")
        return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def verify_chain(self) -> tuple[bool, str]:
        """Return (ok, message). Detects edits, deletions, and reordering."""
        prev = GENESIS_HASH
        for i, entry in enumerate(self.entries()):
            if entry.get("prev_hash") != prev:
                return False, f"chain broken at entry {i}: expected prev_hash {prev}"
            prev = _entry_hash(entry)
        return True, "chain intact"


def write_manifest(run_dir: str | Path, extra: dict | None = None) -> Path:
    """Write manifest.json with the SHA-256 of every file in run_dir,
    so any post-run modification of outputs is detectable."""
    run_dir = Path(run_dir)
    files = {}
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p.name != "manifest.json":
            files[str(p.relative_to(run_dir))] = hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = {"files": files, **(extra or {})}
    body = json.dumps(manifest, indent=2, sort_keys=True)
    manifest["manifest_sha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    out = run_dir / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return out


def verify_manifest(run_dir: str | Path) -> tuple[bool, list[str]]:
    run_dir = Path(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    problems = []
    for rel, expected in manifest["files"].items():
        p = run_dir / rel
        if not p.exists():
            problems.append(f"missing file: {rel}")
        elif hashlib.sha256(p.read_bytes()).hexdigest() != expected:
            problems.append(f"hash mismatch: {rel}")
    return not problems, problems
