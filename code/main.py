#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion-audit agent (entry point).

Usage
-----
    python3 code/main.py                 # full 518-case run -> ./output.csv
    python3 code/main.py --sample        # 32 public sample cases -> ./sample_output_check.csv
    python3 code/main.py --evaluate      # run + score against dataset/sample_output.csv
    python3 code/main.py --no-cache      # rebuild the evidence index from scratch

The pipeline is deterministic.  See ``code/README.md`` for the architecture.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghostdata.data import (  # noqa: E402
    DatasetError,
    dataset_dir,
    eprint,
    load_activity,
    load_audit_log,
    load_cases,
    load_identities,
    load_rules,
    load_sample_cases,
    repo_root,
    require_dataset,
    write_output,
)
from ghostdata.engine import AuditEngine  # noqa: E402
from ghostdata.evidence import build_index  # noqa: E402
from ghostdata.identity import IdentityIndex, activity_identity_hints  # noqa: E402
from ghostdata.intent import authorises_deletion  # noqa: E402
from ghostdata.llm import LLMIntentAdjudicator  # noqa: E402
from ghostdata.policy import PolicyTable  # noqa: E402
from ghostdata.validate import validate_output  # noqa: E402

CACHE_DIR = ROOT / ".cache"
USAGE_PATH = ROOT / "evaluation" / "usage_data.json"


def build_engine(base: Path, use_cache: bool = True) -> tuple[AuditEngine, dict]:
    rules = load_rules(base)
    policy = PolicyTable(rules)
    identities = load_identities(base)
    audit_log = load_audit_log(base)
    activity = load_activity(base)
    identity_index = IdentityIndex.build(identities, audit_log)
    hints = activity_identity_hints(activity)
    index = build_index(base, CACHE_DIR, use_cache=use_cache)
    engine = AuditEngine(index, policy, identities, activity, hints)
    meta = {
        "identity_index": identity_index,
        "activity": activity,
        "index": index,
        "rules": len(policy.rules),
        "policy": policy,
        "identities": identities,
        "hints": hints,
    }
    return engine, meta


def rebuild_engine(meta: dict, identity_index, requester_users: set[str]) -> AuditEngine:
    return AuditEngine(
        meta["index"],
        meta["policy"],
        meta["identities"],
        meta["activity"],
        meta["hints"],
        identity_index=identity_index,
        requester_users=requester_users,
    )


def run(
    cases_path: Path,
    out_path: Path,
    use_cache: bool = True,
    use_model: bool = True,
    verbose: bool = True,
) -> dict:
    started = time.time()
    base = require_dataset()
    engine, meta = build_engine(base, use_cache=use_cache)
    identity_index: IdentityIndex = meta["identity_index"]

    adjudicator = None
    if use_model:
        candidate = LLMIntentAdjudicator(CACHE_DIR / "intent_cache.json")
        if candidate.available:
            adjudicator = candidate

    cases = load_cases(cases_path)
    if not cases:
        raise DatasetError(f"No requests found in {cases_path}")

    # ---- intent + subject resolution ---------------------------------
    prepared = []
    for case in cases:
        authorised, intent, source = authorises_deletion(case.request_text, adjudicator)
        subject = identity_index.resolve_request(case.email, engine.hints) if authorised else None
        prepared.append((case, authorised, intent, source, subject))

    requester_users = {
        subject.user_id for _case, authorised, _i, _s, subject in prepared if authorised and subject
    }
    engine = rebuild_engine(meta, identity_index, requester_users)

    # ---- account-id assignment for cases without an evidence account --
    engine.register_account_assignments(
        [
            (
                case,
                engine.needs_account_record(subject, case.audit_at),
                engine.evidence_account_id(subject, case.audit_at),
            )
            for case, authorised, _intent, _source, subject in prepared
            if authorised
        ]
    )

    # ---- audit --------------------------------------------------------
    outcomes = []
    status_counts: dict[str, int] = {}
    for case, authorised, intent, source, subject in prepared:
        outcome = engine.analyse(case, subject, authorised, intent, source)
        outcomes.append(outcome)
        status_counts[outcome.status] = status_counts.get(outcome.status, 0) + 1

    outcomes.sort(key=lambda item: item.case_id)
    rows = [
        (item.case_id, item.status, json.dumps(item.steps, ensure_ascii=False, separators=(",", ":")))
        for item in outcomes
    ]
    write_output(out_path, rows)

    report = validate_output(out_path, cases_path)
    elapsed = time.time() - started

    usage = {
        "elapsed_seconds": round(elapsed, 2),
        "cases": len(cases),
        "status_counts": status_counts,
        "evidence_files": len(meta["index"].files),
        "evidence_formats": meta["index"].format_counts(),
        "evidence_observations": len(meta["index"].observations),
        "parse_issues": [
            {"file_id": issue.file_id, "path": issue.path, "reason": issue.reason}
            for issue in meta["index"].issues
        ],
        "model": adjudicator.ledger.as_dict() if adjudicator else {
            "provider": "",
            "model": "",
            "calls": 0,
            "cached_calls": 0,
            "failed_calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "records": [],
        },
        "model_available": bool(adjudicator),
        "rules_loaded": meta["rules"],
        "validation": report,
    }
    try:
        USAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
        USAGE_PATH.write_text(json.dumps(usage, indent=2), encoding="utf-8")
    except OSError:
        pass

    if verbose:
        eprint(f"Wrote {out_path} ({len(rows)} rows) in {elapsed:.1f}s")
        eprint(f"Status counts: {status_counts}")
        eprint(f"Validator: {'PASS' if report['ok'] else 'FAIL'}")
        if not report["ok"]:
            for problem in report["problems"][:20]:
                eprint(f"  - {problem}")

    return {"outcomes": outcomes, "usage": usage, "report": report}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - deletion audit agent")
    parser.add_argument("--sample", action="store_true", help="run the 32 public sample requests")
    parser.add_argument("--evaluate", action="store_true", help="run the sample set and score it")
    parser.add_argument("--no-cache", action="store_true", help="ignore the evidence extraction cache")
    parser.add_argument("--no-model", action="store_true", help="never call a remote model")
    parser.add_argument("--cases", type=Path, default=None, help="alternative requests CSV")
    parser.add_argument("--out", type=Path, default=None, help="alternative output path")
    args = parser.parse_args(argv)

    base = dataset_dir()
    if args.cases is not None:
        cases_path = args.cases
    elif args.sample or args.evaluate:
        cases_path = base / "sample_deletion_requests.csv"
    else:
        cases_path = base / "deletion_requests.csv"

    if args.out is not None:
        out_path = args.out
    elif args.sample or args.evaluate:
        out_path = repo_root() / "sample_output_check.csv"
    else:
        out_path = repo_root() / "output.csv"

    try:
        result = run(
            cases_path,
            out_path,
            use_cache=not args.no_cache,
            use_model=not args.no_model,
        )
    except DatasetError as exc:
        eprint(f"ERROR: {exc}")
        return 2
    except FileNotFoundError as exc:
        eprint(f"ERROR: required input not found: {exc.filename or exc}")
        return 2

    if args.evaluate:
        from evaluation.main import evaluate_sample_run

        code = evaluate_sample_run(result["outcomes"])
        return 0 if code == 0 else 1
    return 0 if result["report"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
