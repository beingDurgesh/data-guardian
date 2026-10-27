"""Structural and semantic validators for ``output.csv``.

The validator is deliberately strict and fails the run when a structural
requirement is violated: a defective file must never be written silently.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .data import load_cases, load_manifest
from .model import OPERATIONS, PHASE_ORDER, STEP_FIELDS

VALID_STATUS = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}


def _evidence_cutoffs(dataset_dir: Path) -> dict[str, str]:
    cutoffs: dict[str, str] = {}
    try:
        for row in load_manifest(dataset_dir):
            cutoffs[row["file_id"]] = row.get("captured_at", "")
    except Exception:
        return cutoffs
    return cutoffs


def validate_output(path: Path, cases_path: Path) -> dict:
    problems: list[str] = []
    dataset = cases_path.parent
    requests = {case.case_id: case for case in load_cases(cases_path)}
    cutoffs = _evidence_cutoffs(dataset)

    if not path.is_file():
        return {"ok": False, "problems": [f"output file not found: {path}"], "rows": 0}

    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        rows = list(reader)

    if not rows:
        return {"ok": False, "problems": ["output file is empty"], "rows": 0}

    header = rows[0]
    if header != ["case_id", "deletion_status", "steps_json"]:
        problems.append(f"header must be case_id,deletion_status,steps_json (got {header})")

    data_rows = rows[1:]
    seen: list[str] = []
    for index, row in enumerate(data_rows, start=2):
        if len(row) != 3:
            problems.append(f"line {index}: expected 3 columns, got {len(row)}")
            continue
        case_id, status, payload = row
        seen.append(case_id)
        case = requests.get(case_id)
        if case is None:
            problems.append(f"line {index}: unknown case_id {case_id!r}")
            continue
        if status not in VALID_STATUS:
            problems.append(f"line {index}: invalid deletion_status {status!r}")
            continue
        try:
            steps = json.loads(payload)
        except ValueError as exc:
            problems.append(f"line {index}: steps_json is not valid JSON ({exc})")
            continue
        if not isinstance(steps, list):
            problems.append(f"line {index}: steps_json must be a JSON array")
            continue

        problems.extend(
            _validate_steps(case_id, status, steps, case.audit_at, cutoffs)
        )

    if len(seen) != len(set(seen)):
        duplicates = sorted({cid for cid in seen if seen.count(cid) > 1})
        problems.append(f"duplicate case_id values: {duplicates[:10]}")
    if seen != sorted(seen):
        problems.append("rows are not sorted by case_id")
    missing = set(requests) - set(seen)
    extra = set(seen) - set(requests)
    if missing:
        problems.append(f"{len(missing)} case(s) missing from output, e.g. {sorted(missing)[:5]}")
    if extra:
        problems.append(f"{len(extra)} unexpected case(s) in output, e.g. {sorted(extra)[:5]}")

    statuses = {}
    for row in data_rows:
        if len(row) == 3:
            statuses[row[1]] = statuses.get(row[1], 0) + 1

    return {
        "ok": not problems,
        "problems": problems,
        "rows": len(data_rows),
        "unique_case_ids": len(set(seen)),
        "status_counts": statuses,
    }


def _validate_steps(
    case_id: str, status: str, steps: list, audit_at: str, cutoffs: dict[str, str]
) -> list[str]:
    problems: list[str] = []

    if status == "NOT_APPLICABLE":
        if steps:
            problems.append(f"{case_id}: NOT_APPLICABLE must have an empty steps array")
        return problems
    if not steps:
        problems.append(f"{case_id}: {status} case has no steps")
        return problems

    previous_rank: tuple | None = None
    for position, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            problems.append(f"{case_id}: step {position} is not an object")
            continue
        keys = set(step.keys())
        if keys != set(STEP_FIELDS):
            problems.append(f"{case_id}: step {position} fields are {sorted(keys)}")
            continue
        if step["step_no"] != position:
            problems.append(f"{case_id}: step numbers must start at 1 and be consecutive")
        operation = step["operation"]
        if operation not in OPERATIONS:
            problems.append(f"{case_id}: step {position} has unknown operation {operation!r}")
            continue
        phase, state, rank = OPERATIONS[operation]
        if step["phase"] != phase:
            problems.append(f"{case_id}: step {position} phase {step['phase']!r} != {phase!r}")
        if step["state"] != state:
            problems.append(f"{case_id}: step {position} state {step['state']!r} != {state!r}")
        if not str(step["system_id"]).strip():
            problems.append(f"{case_id}: step {position} has empty system_id")
        if not str(step["resource_id"]).strip():
            problems.append(f"{case_id}: step {position} has empty resource_id")

        current_rank = (PHASE_ORDER[phase], rank, str(step["system_id"]), str(step["resource_id"]))
        if previous_rank is not None and current_rank < previous_rank:
            problems.append(
                f"{case_id}: step {position} breaks phase/operation/system ordering "
                f"({current_rank} < {previous_rank})"
            )
        previous_rank = current_rank

        evidence = str(step["evidence_id"])
        if phase == "FINDING":
            if not evidence:
                problems.append(f"{case_id}: step {position} finding has no evidence_id")
            elif evidence in cutoffs and cutoffs[evidence] and cutoffs[evidence] > audit_at:
                problems.append(
                    f"{case_id}: step {position} cites {evidence} captured after audit_at"
                )
        if status == "COMPLETE":
            if phase != "VERIFICATION":
                problems.append(f"{case_id}: COMPLETE cases may only contain verification steps")
            if not evidence:
                problems.append(f"{case_id}: step {position} verification has no evidence_id")
            elif evidence in cutoffs and cutoffs[evidence] and cutoffs[evidence] > audit_at:
                problems.append(
                    f"{case_id}: step {position} cites {evidence} captured after audit_at"
                )
        else:  # INCOMPLETE
            if phase in {"REMEDIATION", "VERIFICATION"} and evidence:
                problems.append(
                    f"{case_id}: step {position} {phase.lower()} step must use an empty evidence_id"
                )

    phases = [step.get("phase") for step in steps if isinstance(step, dict)]
    order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    ranks = [order.get(phase, -1) for phase in phases]
    if ranks != sorted(ranks):
        problems.append(f"{case_id}: phases are not ordered FINDING -> REMEDIATION -> VERIFICATION")

    return problems
