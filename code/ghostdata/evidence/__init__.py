"""Evidence manifest handling and the cached multiformat evidence index."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from ..data import load_manifest
from ..model import EvidenceFile, ExtractIssue, Observation, norm_iso
from .parsers import (
    parse_image_file,
    parse_json_file,
    parse_log_file,
    parse_pdf_file,
    parse_sql_file,
    parse_text_file,
)

CACHE_VERSION = 6

EXTENSION_PARSERS = {
    ".json": "json",
    ".sql": "sql",
    ".log": "log",
    ".txt": "text",
    ".tsv": "text",
    ".csv": "text",
    ".pdf": "pdf",
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".webp": "image",
}


class EvidenceIndex:
    def __init__(self) -> None:
        self.files: dict[str, EvidenceFile] = {}
        self.observations: list[Observation] = []
        self.issues: list[ExtractIssue] = []

    def add_file(self, evidence_file: EvidenceFile) -> None:
        self.files[evidence_file.file_id] = evidence_file
        self.observations.extend(evidence_file.observations)
        if evidence_file.issue:
            self.issues.append(
                ExtractIssue(
                    file_id=evidence_file.file_id,
                    path=evidence_file.path,
                    reason=evidence_file.issue,
                )
            )

    def files_at_or_before(self, cutoff: str) -> dict[str, EvidenceFile]:
        if not cutoff:
            return dict(self.files)
        return {
            file_id: item
            for file_id, item in self.files.items()
            if not item.captured_at or item.captured_at <= cutoff
        }

    def by_file(self, file_id: str) -> list[Observation]:
        item = self.files.get(file_id)
        return list(item.observations) if item else []

    def format_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.files.values():
            counts[item.fmt] = counts.get(item.fmt, 0) + 1
        return dict(sorted(counts.items()))

    def observation_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.files.values():
            counts[item.file_id] = len(item.observations)
        return counts


def _cache_key(path: Path) -> str:
    stat = path.stat()
    raw = f"{CACHE_VERSION}|{path.name}|{stat.st_size}|{int(stat.st_mtime)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _serialise(observations: list[Observation]) -> list[dict]:
    return [asdict(obs) for obs in observations]


def _deserialise(payload: list[dict]) -> list[Observation]:
    out: list[Observation] = []
    for item in payload:
        data = dict(item)
        for key in ("user_refs", "emails", "phones", "names", "hashes"):
            data[key] = tuple(data.get(key) or ())
        out.append(Observation(**data))
    return out


def build_index(dataset_dir: Path, cache_dir: Path | None = None, use_cache: bool = True) -> EvidenceIndex:
    manifest = load_manifest(dataset_dir)
    index = EvidenceIndex()
    cache_path = (cache_dir / "evidence_index.json") if cache_dir else None
    cache: dict[str, list[dict]] = {}
    if cache_path and use_cache and cache_path.is_file():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            cache = {}

    dirty = False
    for row in manifest:
        file_id = row["file_id"]
        relative = row["file_path"]
        captured_at = norm_iso(row.get("captured_at"))
        origin = (row.get("origin") or "").strip()
        path = dataset_dir / relative
        extension = path.suffix.lower()
        fmt = EXTENSION_PARSERS.get(extension, "unsupported")

        if not path.is_file():
            index.add_file(
                EvidenceFile(
                    file_id=file_id,
                    path=relative,
                    origin=origin,
                    captured_at=captured_at,
                    fmt=fmt,
                    issue="file listed in manifest but missing on disk",
                )
            )
            continue

        key = _cache_key(path)
        cached = cache.get(f"{file_id}:{key}")
        if cached is not None:
            observations = _deserialise(cached)
            issue = ""
        else:
            issue = ""
            try:
                if fmt == "json":
                    observations = parse_json_file(path, file_id, captured_at, origin)
                elif fmt == "sql":
                    observations = parse_sql_file(path, file_id, captured_at, origin)
                elif fmt == "log":
                    observations = parse_log_file(path, file_id, captured_at, origin)
                elif fmt == "text":
                    observations = parse_text_file(path, file_id, captured_at, origin)
                elif fmt == "pdf":
                    observations, issue = parse_pdf_file(path, file_id, captured_at, origin)
                elif fmt == "image":
                    observations, issue = parse_image_file(path, file_id, captured_at, origin)
                else:
                    observations, issue = [], f"unsupported evidence format: {extension or 'none'}"
            except Exception as exc:  # keep the run alive, record the failure
                observations, issue = [], f"parse error: {type(exc).__name__}: {exc}"
            if not issue:
                cache[f"{file_id}:{key}"] = _serialise(observations)
                dirty = True

        index.add_file(
            EvidenceFile(
                file_id=file_id,
                path=relative,
                origin=origin,
                captured_at=captured_at,
                fmt=fmt,
                observations=list(observations),
                issue=issue,
            )
        )

    if cache_path and use_cache and dirty:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")

    return index
