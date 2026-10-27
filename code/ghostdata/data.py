"""Loading of the participant-facing CSV inputs."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from .model import CaseRequest, norm_email, norm_iso

REQUIRED_FILES = (
    "deletion_requests.csv",
    "user_identities.csv",
    "user_audit_log.csv",
    "system_activity.csv",
    "deletion_rules.csv",
    "evidence_files.csv",
)


class DatasetError(RuntimeError):
    pass


def repo_root() -> Path:
    """Repository/package root, resolved relative to this file.

    The source checkout keeps this module at ``<repo>/code/ghostdata/data.py``.
    A submitted ``code.zip`` is extracted either flat (``<root>/ghostdata``) or
    into a ``code/`` directory at the repository root.  Prefer the nearest
    ancestor that actually contains the participant dataset; otherwise fall
    back to the nearest packaged ``main.py`` and finally the historical layout.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "dataset").is_dir():
            return parent
    for parent in here.parents:
        if (parent / "main.py").is_file() and (parent / "ghostdata").is_dir():
            return parent
    return here.parents[2]


def dataset_dir() -> Path:
    return repo_root() / "dataset"


def require_dataset(path: Path | None = None) -> Path:
    base = path or dataset_dir()
    if not base.is_dir():
        raise DatasetError(
            f"Dataset directory not found: {base}\n"
            "Place the participant-facing dataset under 'dataset/' at the repository root."
        )
    missing = [name for name in REQUIRED_FILES if not (base / name).is_file()]
    if missing:
        raise DatasetError(
            "Missing required participant-facing input file(s):\n  "
            + "\n  ".join(str(base / name) for name in missing)
        )
    return base


def _read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def load_cases(path: Path) -> list[CaseRequest]:
    cases: list[CaseRequest] = []
    for row in _read_csv(path):
        cases.append(
            CaseRequest(
                case_id=(row.get("case_id") or "").strip(),
                email=(row.get("email") or "").strip(),
                requested_at=norm_iso(row.get("requested_at")),
                reported_status=(row.get("reported_status") or "").strip(),
                reported_at=norm_iso(row.get("reported_at")),
                audit_at=norm_iso(row.get("audit_at")),
                request_text=(row.get("request_text") or "").strip(),
            )
        )
    return cases


def load_identities(base: Path) -> list[dict[str, str]]:
    return _read_csv(base / "user_identities.csv")


def load_audit_log(base: Path) -> list[dict[str, str]]:
    return _read_csv(base / "user_audit_log.csv")


def load_activity(base: Path) -> list[dict[str, str]]:
    return _read_csv(base / "system_activity.csv")


def load_rules(base: Path) -> list[dict[str, str]]:
    return _read_csv(base / "deletion_rules.csv")


def load_manifest(base: Path) -> list[dict[str, str]]:
    rows = _read_csv(base / "evidence_files.csv")
    for row in rows:
        row["file_path"] = (row.get("file_path") or "").strip().replace("\\", "/")
        row["captured_at"] = norm_iso(row.get("captured_at"))
        row["file_id"] = (row.get("file_id") or "").strip()
    return rows


def write_output(path: Path, rows: list[tuple[str, str, str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for row in rows:
            writer.writerow(row)


def load_sample_cases(base: Path) -> list[CaseRequest]:
    return load_cases(base / "sample_deletion_requests.csv")


def load_sample_output(base: Path) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for row in _read_csv(base / "sample_output.csv"):
        out[row["case_id"]] = (row["deletion_status"], row["steps_json"])
    return out


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)
