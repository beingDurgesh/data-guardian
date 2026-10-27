#!/usr/bin/env python3
"""Reproducible evaluation of the deletion-audit agent.

Scores a prediction file against ``dataset/sample_output.csv`` and reports the
metrics required by the challenge:

* case-level deletion-status accuracy
* exact-output match rate
* step-level precision / recall / F1
* operation accuracy
* field-level accuracy (position-aligned and semantic-step-aligned)
* evidence-reference accuracy
* ordered-sequence accuracy
* false-COMPLETE count

Run directly::

    python3 code/evaluation/main.py
"""

from __future__ import annotations

import difflib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghostdata.data import load_sample_output, repo_root  # noqa: E402

STEP_KEY = ("phase", "system_id", "resource_id", "operation", "state")


def _steps(payload: str) -> list[dict]:
    try:
        data = json.loads(payload)
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def _key(step: dict, with_evidence: bool = False) -> tuple:
    base = tuple(str(step.get(field, "")) for field in STEP_KEY)
    if with_evidence:
        return base + (str(step.get("evidence_id", "")),)
    return base


def evaluate(predictions: dict[str, tuple[str, str]], expected: dict[str, tuple[str, str]]) -> dict:
    cases = sorted(set(expected) & set(predictions))
    status_correct = 0
    exact_match = 0
    sequence_match = 0
    false_complete = 0
    false_incomplete = 0
    missed_na = 0

    tp = fp = fn = 0
    evidence_tp = evidence_total = 0
    operation_correct = operation_total = 0
    field_correct = field_total = 0
    findings_tp = findings_fp = findings_fn = 0
    remediation_tp = remediation_fp = remediation_fn = 0
    semantic_steps = 0
    semantic_fields = Counter()
    semantic_correct = Counter()
    semantic_fields_seen = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
    semantic_signature = ("phase", "system_id", "resource_id", "operation")

    per_case: list[dict] = []

    for case_id in cases:
        pred_status, pred_payload = predictions[case_id]
        exp_status, exp_payload = expected[case_id]
        pred_steps = _steps(pred_payload)
        exp_steps = _steps(exp_payload)

        if pred_status == exp_status:
            status_correct += 1
        if pred_status == "COMPLETE" and exp_status != "COMPLETE":
            false_complete += 1
        if pred_status == "INCOMPLETE" and exp_status == "COMPLETE":
            false_incomplete += 1
        if pred_status == "NOT_APPLICABLE" and exp_status != "NOT_APPLICABLE":
            missed_na += 1

        if [s.get("operation") for s in pred_steps] == [s.get("operation") for s in exp_steps]:
            sequence_match += 1
        if (
            pred_status == exp_status
            and [_key(s, True) for s in pred_steps] == [_key(s, True) for s in exp_steps]
        ):
            exact_match += 1

        pred_keys = Counter(_key(s) for s in pred_steps)
        exp_keys = Counter(_key(s) for s in exp_steps)
        common = pred_keys & exp_keys
        tp += sum(common.values())
        fp += sum((pred_keys - common).values())
        fn += sum((exp_keys - common).values())

        pred_findings = Counter(_key(s) for s in pred_steps if s.get("phase") == "FINDING")
        exp_findings = Counter(_key(s) for s in exp_steps if s.get("phase") == "FINDING")
        findings_tp += sum((pred_findings & exp_findings).values())
        findings_fp += sum((pred_findings - exp_findings).values())
        findings_fn += sum((exp_findings - pred_findings).values())

        pred_rem = Counter(_key(s) for s in pred_steps if s.get("phase") == "REMEDIATION")
        exp_rem = Counter(_key(s) for s in exp_steps if s.get("phase") == "REMEDIATION")
        remediation_tp += sum((pred_rem & exp_rem).values())
        remediation_fp += sum((pred_rem - exp_rem).values())
        remediation_fn += sum((exp_rem - pred_rem).values())

        # field-level: for aligned steps by position where operation matches
        for pred_step, exp_step in zip(pred_steps, exp_steps):
            for field in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += 1
                if str(pred_step.get(field, "")) == str(exp_step.get(field, "")):
                    field_correct += 1
            operation_total += 1
            if pred_step.get("operation") == exp_step.get("operation"):
                operation_correct += 1
            evidence_total += 1
            if str(pred_step.get("evidence_id", "")) == str(exp_step.get("evidence_id", "")):
                evidence_tp += 1

        # Supplementary diagnostic: align by semantic step identity rather than
        # position, so one missing step does not shift every later step_no.
        exp_sig = [tuple(str(step.get(field, "")) for field in semantic_signature) for step in exp_steps]
        pred_sig = [tuple(str(step.get(field, "")) for field in semantic_signature) for step in pred_steps]
        matcher = difflib.SequenceMatcher(a=exp_sig, b=pred_sig, autojunk=False)
        for tag, exp_start, exp_end, pred_start, pred_end in matcher.get_opcodes():
            if tag not in {"equal", "replace"} or (exp_end - exp_start) != (pred_end - pred_start):
                continue
            for exp_index, pred_index in zip(range(exp_start, exp_end), range(pred_start, pred_end)):
                semantic_steps += 1
                for field in semantic_fields_seen:
                    semantic_fields[field] += 1
                    if str(exp_steps[exp_index].get(field, "")) == str(pred_steps[pred_index].get(field, "")):
                        semantic_correct[field] += 1

        per_case.append(
            {
                "case_id": case_id,
                "expected_status": exp_status,
                "predicted_status": pred_status,
                "status_match": pred_status == exp_status,
                "expected_steps": len(exp_steps),
                "predicted_steps": len(pred_steps),
                "exact_match": pred_status == exp_status
                and [_key(s, True) for s in pred_steps] == [_key(s, True) for s in exp_steps],
            }
        )

    total = max(1, len(cases))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "cases": len(cases),
        "status_accuracy": status_correct / total,
        "exact_match_rate": exact_match / total,
        "sequence_accuracy": sequence_match / total,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "step_true_positives": tp,
        "step_false_positives": fp,
        "step_false_negatives": fn,
        "finding_precision": findings_tp / (findings_tp + findings_fp) if (findings_tp + findings_fp) else 0.0,
        "finding_recall": findings_tp / (findings_tp + findings_fn) if (findings_tp + findings_fn) else 0.0,
        "remediation_precision": remediation_tp / (remediation_tp + remediation_fp)
        if (remediation_tp + remediation_fp)
        else 0.0,
        "remediation_recall": remediation_tp / (remediation_tp + remediation_fn)
        if (remediation_tp + remediation_fn)
        else 0.0,
        "operation_accuracy": operation_correct / operation_total if operation_total else 0.0,
        "field_accuracy": field_correct / field_total if field_total else 0.0,
        "evidence_accuracy": evidence_tp / evidence_total if evidence_total else 0.0,
        "semantic_step_matches": semantic_steps,
        "semantic_field_accuracy": sum(semantic_correct.values()) / max(1, sum(semantic_fields.values())),
        "semantic_field_accuracy_by_field": {
            field: semantic_correct[field] / semantic_fields[field] if semantic_fields[field] else 0.0
            for field in semantic_fields_seen
        },
        "false_complete": false_complete,
        "false_incomplete": false_incomplete,
        "missed_not_applicable": missed_na,
        "per_case": per_case,
    }


def evaluate_sample_run(outcomes) -> int:
    predictions = {
        outcome.case_id: (
            outcome.status,
            json.dumps(outcome.steps, ensure_ascii=False, separators=(",", ":")),
        )
        for outcome in outcomes
    }
    expected = load_sample_output(repo_root() / "dataset")
    metrics = evaluate(predictions, expected)
    print(json.dumps({k: v for k, v in metrics.items() if k != "per_case"}, indent=2))
    failures = [row for row in metrics["per_case"] if not row["exact_match"]]
    if failures:
        print("\nMismatched cases:")
        for row in failures:
            print(
                f"  {row['case_id']}: expected {row['expected_status']} "
                f"({row['expected_steps']} steps), got {row['predicted_status']} "
                f"({row['predicted_steps']} steps)"
            )
    return 0 if metrics["exact_match_rate"] == 1.0 else 1


if __name__ == "__main__":
    from main import run

    dataset = repo_root() / "dataset"
    result = run(dataset / "sample_deletion_requests.csv", repo_root() / "sample_output_check.csv")
    raise SystemExit(evaluate_sample_run(result["outcomes"]))
