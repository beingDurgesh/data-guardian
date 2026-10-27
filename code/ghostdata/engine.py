"""Deterministic deletion-audit engine.

Responsibilities:

* resolve the subject of a request (current + historical identifiers);
* select the evidence that describes the case at ``audit_at``;
* reduce the evidence to one state per relevant record;
* apply ``deletion_rules.csv``;
* decide ``COMPLETE`` / ``INCOMPLETE`` / ``NOT_APPLICABLE``;
* emit ordered findings, remediation actions and verification steps.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .model import (
    CAT_ACCOUNT_TOMBSTONE,
    CAT_ANALYTICS_PROFILE,
    CAT_BACKUP_ARCHIVE,
    CAT_CACHE_ENTRY,
    CAT_DATA_FLOW,
    CAT_EMAIL_DELIVERY_LOG,
    CAT_LEGAL_HOLD_RECORD,
    CAT_MARKETING_PROFILE,
    CAT_PRODUCT_TELEMETRY,
    CAT_SEARCH_INDEX_ENTRY,
    CAT_SECONDARY_IDENTIFIER,
    CAT_SECURITY_AUDIT_LOG,
    CAT_SUPPORT_ATTACHMENT,
    CAT_SUPPORT_MESSAGE,
    CAT_USER_EXPORT,
    CAT_USER_PROFILE,
    OPERATIONS,
    Observation,
    PHASE_FINDING,
    PHASE_ORDER,
    PHASE_REMEDIATION,
    PHASE_VERIFICATION,
    STATUS_COMPLETE,
    STATUS_INCOMPLETE,
    STATUS_NOT_APPLICABLE,
    ST_ABSENT,
    ST_ACTIVE,
    ST_ANONYMIZED,
    ST_BLOCKED,
    ST_DISABLED,
    ST_PRESENT,
    ST_REDACTED,
    ST_UNKNOWN,
    Subject,
    extract_user_refs,
    norm_iso,
    norm_name,
)
from .policy import PolicyTable
from .evidence import EvidenceIndex

DELETE_CATEGORIES = {
    CAT_USER_PROFILE,
    CAT_SECONDARY_IDENTIFIER,
    CAT_SEARCH_INDEX_ENTRY,
    CAT_CACHE_ENTRY,
    CAT_SUPPORT_ATTACHMENT,
    CAT_USER_EXPORT,
    CAT_MARKETING_PROFILE,
}
REDACT_CATEGORIES = {CAT_SUPPORT_MESSAGE, CAT_EMAIL_DELIVERY_LOG, CAT_ACCOUNT_TOMBSTONE}
ANONYMIZE_CATEGORIES = {CAT_ANALYTICS_PROFILE, CAT_PRODUCT_TELEMETRY}
RETAIN_CATEGORIES = {CAT_SECURITY_AUDIT_LOG, CAT_LEGAL_HOLD_RECORD, CAT_BACKUP_ARCHIVE}
SINGLETON_CATEGORIES = {CAT_USER_PROFILE, CAT_ACCOUNT_TOMBSTONE}


@dataclass
class RecordState:
    system_id: str
    resource_id: str
    category: str
    state: str
    evidence_id: str
    observed_at: str = ""
    source_kind: str = "file"
    origin: str = ""


@dataclass
class CaseOutcome:
    case_id: str
    status: str
    steps: list[dict] = field(default_factory=list)
    subject: str = ""
    matched_via: str = ""
    intent: str = ""
    intent_source: str = ""
    records: list[RecordState] = field(default_factory=list)
    bundle: str = ""
    notes: list[str] = field(default_factory=list)


def _overlap(obs: Observation, subject: Subject, unique_names: set[str]) -> str:
    if obs.user_refs and set(obs.user_refs) & set(subject.user_refs):
        return "user_reference"
    if obs.emails and set(obs.emails) & set(subject.emails):
        return "email"
    if obs.hashes and set(obs.hashes) & set(subject.hashes):
        return "email_hash"
    if obs.phones and set(obs.phones) & set(subject.phones):
        return "phone"
    if obs.names:
        matched = set(obs.names) & set(subject.names)
        if matched and all(name in unique_names for name in matched):
            return "name"
    return ""


def _op_tuple(operation: str, system_id: str, resource_id: str) -> tuple:
    phase, _state, rank = OPERATIONS[operation]
    return (PHASE_ORDER[phase], rank, system_id, resource_id)


class AuditEngine:
    def __init__(
        self,
        index: EvidenceIndex,
        policy: PolicyTable,
        identities,
        activity_rows: list[dict[str, str]],
        identity_hints: dict[str, str],
        options: dict | None = None,
        identity_index=None,
        requester_users: set[str] | None = None,
    ) -> None:
        self.index = index
        self.policy = policy
        self.identities = identities
        self.activity = activity_rows
        self.hints = identity_hints
        self.options = options or {}
        self.identity_index = identity_index
        self.requester_users = requester_users or set()

        name_counts: Counter = Counter()
        for row in identities:
            name = norm_name(row.get("name"))
            if name:
                name_counts[name] += 1
        self.unique_names: set[str] = {name for name, count in name_counts.items() if count == 1}

        # file ids ordered by capture time (for deterministic fallbacks)
        self.files_by_capture: list[tuple[str, str]] = sorted(
            ((item.captured_at, file_id) for file_id, item in index.files.items()),
            key=lambda pair: (pair[0], pair[1]),
        )
        self.files_with_system: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for file_id, item in index.files.items():
            systems = {obs.system_id for obs in item.observations if obs.system_id}
            for system in systems:
                self.files_with_system[system].append((item.captured_at, file_id))
        for system in self.files_with_system:
            self.files_with_system[system].sort()

        self._account_assignments: dict[str, str] = {}

        # Stable catalogue of policy-retained security audit records.  The
        # record ids are immutable facts that may only be visible in a later
        # read-back, so they are collected once and reused; the record's state
        # is still taken from evidence at or before ``audit_at``.
        self.audit_catalogue: dict[str, str] = {}
        for obs in index.observations:
            if obs.category != CAT_SECURITY_AUDIT_LOG or not obs.resource_id:
                continue
            for ref in obs.user_refs:
                self.audit_catalogue.setdefault(ref, obs.resource_id)

        # Identity links published by the data catalogue.  They are the only
        # participant-visible proof that an otherwise anonymous evidence record
        # (for example a support attachment) belongs to a subject.
        self.link_catalogue: dict[str, list[tuple[str, str, str, str]]] = defaultdict(list)
        for row in activity_rows:
            if (row.get("event_type") or "").strip() != "LINK_RESOURCE_IDENTITY":
                continue
            resource_id = (row.get("resource_id") or "").strip()
            details = row.get("details") or ""
            if not resource_id:
                continue
            refs = extract_user_refs(details)
            if not refs:
                continue
            when = norm_iso(row.get("event_time"))
            for ref in refs:
                self.link_catalogue[ref].append(
                    (when, resource_id, (row.get("target_system") or "").strip(), row.get("activity_id", ""))
                )
        for ref in self.link_catalogue:
            self.link_catalogue[ref].sort()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _latest_file_for_system(self, system_id: str, cutoff: str, prefer_structured: bool = False) -> str:
        """Most recent evidence file that contains at least one fact for ``system_id``.

        ``prefer_structured`` restricts the search to database snapshots and
        record exports when any exist, because a log line only proves that one
        lookup missed, while a snapshot scopes the whole store.
        """
        candidates = [
            (captured_at, file_id)
            for captured_at, file_id in self.files_with_system.get(system_id, [])
            if not (captured_at and cutoff and captured_at > cutoff)
        ]
        if prefer_structured:
            structured = [
                pair
                for pair in candidates
                if pair[1] in self.index.files and self.index.files[pair[1]].fmt in {"sql", "json"}
            ]
            if structured:
                candidates = structured
        if not candidates:
            return ""
        return max(candidates)[1]

    def _latest_file_overall(self, cutoff: str) -> str:
        best = ""
        for captured_at, file_id in self.files_by_capture:
            if captured_at and cutoff and captured_at > cutoff:
                continue
            best = file_id
        return best

    # ------------------------------------------------------------------
    # activity-derived account resolution
    # ------------------------------------------------------------------
    def account_delete_events(self) -> list[dict[str, str]]:
        events = []
        for row in self.activity:
            if (row.get("event_type") or "").strip() != "DELETE_RECORD":
                continue
            if (row.get("target_system") or "").strip() != "account_service":
                continue
            resource_id = (row.get("resource_id") or "").strip()
            if not resource_id.startswith("account_"):
                continue
            events.append(row)
        events.sort(key=lambda r: (norm_iso(r.get("event_time")), r.get("activity_id", "")))
        return events

    # ------------------------------------------------------------------
    # core per-case analysis
    # ------------------------------------------------------------------
    def observations_for(self, subject: Subject, cutoff: str) -> list[Observation]:
        if subject is None:
            return []
        return [
            obs
            for obs in self.index.observations
            if (not obs.captured_at or not cutoff or obs.captured_at <= cutoff)
            and _overlap(obs, subject, self.unique_names)
        ]

    def analyse(
        self,
        case,
        subject: Subject,
        authorised: bool,
        intent: str,
        intent_source: str,
    ) -> CaseOutcome:
        outcome = CaseOutcome(
            case_id=case.case_id,
            status=STATUS_NOT_APPLICABLE,
            subject=subject.user_id if subject else "",
            matched_via=subject.matched_via if subject else "",
            intent=intent,
            intent_source=intent_source,
        )
        if not authorised:
            return outcome
        if subject is None:
            outcome.status = STATUS_INCOMPLETE
            outcome.notes.append("subject could not be resolved from the supplied identities")
            return outcome

        cutoff = case.audit_at
        observations = self.observations_for(subject, cutoff)

        # ---- evidence bundle selection -------------------------------
        counts = Counter(obs.evidence_id for obs in observations if not obs.scope_only)
        bundle = ""
        if counts:
            bundle = sorted(
                counts.items(),
                key=lambda item: (
                    item[1],
                    self.index.files[item[0]].captured_at if item[0] in self.index.files else "",
                    item[0],
                ),
            )[-1][0]
        outcome.bundle = bundle

        # ---- reduce to one state per record ---------------------------
        records: list[RecordState] = []
        per_resource: dict[tuple[str, str], Observation] = {}
        for obs in observations:
            if obs.scope_only or not obs.resource_id:
                continue
            key = (obs.system_id, obs.resource_id)
            current = per_resource.get(key)
            if current is None or obs.sort_key > current.sort_key:
                per_resource[key] = obs

        for obs in sorted(per_resource.values(), key=lambda o: (o.system_id, o.resource_id)):
            records.append(
                RecordState(
                    system_id=obs.system_id,
                    resource_id=obs.resource_id,
                    category=obs.category,
                    state=obs.state,
                    evidence_id=obs.evidence_id,
                    observed_at=obs.observed_at,
                    source_kind=obs.source_kind,
                    origin=obs.origin,
                )
            )

        # ---- singleton categories: keep only the most recent ----------
        singletons: dict[str, RecordState] = {}
        non_singletons: list[RecordState] = []
        for record in records:
            if record.category == CAT_ACCOUNT_TOMBSTONE and record.observed_at and case.requested_at:
                # A tombstone created before this request belongs to an earlier
                # deletion (the account was re-created afterwards); it is not a
                # copy of the data this request authorises us to remove.
                if record.observed_at < case.requested_at:
                    continue
            if record.category in SINGLETON_CATEGORIES:
                current = singletons.get(record.category)
                if current is None or (record.observed_at, record.evidence_id) > (
                    current.observed_at,
                    current.evidence_id,
                ):
                    singletons[record.category] = record
            else:
                non_singletons.append(record)
        records = sorted(
            list(singletons.values()) + non_singletons,
            key=lambda r: (r.system_id, r.resource_id),
        )

        # ---- records in a dedicated file that carry no identifier ------
        if bundle and self.options.get("attribute_dedicated_bundle", False) and self._dedicated_bundle(bundle, subject):
            have = {(r.system_id, r.resource_id) for r in records}
            for obs in self.index.files[bundle].observations:
                if obs.scope_only or not obs.resource_id:
                    continue
                if obs.user_refs or obs.emails or obs.hashes or obs.phones or obs.names:
                    continue
                if obs.category != CAT_ANALYTICS_PROFILE:
                    continue
                if (obs.system_id, obs.resource_id) in have:
                    continue
                records.append(
                    RecordState(
                        system_id=obs.system_id,
                        resource_id=obs.resource_id,
                        category=obs.category,
                        state=obs.state,
                        evidence_id=obs.evidence_id,
                        observed_at=obs.observed_at,
                        source_kind="file",
                        origin=obs.origin,
                    )
                )
            records.sort(key=lambda r: (r.system_id, r.resource_id))

        # ---- catalogue-published identity links -----------------------
        # A linked record is only added when the evidence itself shows that the
        # resource exists at or before the audit cutoff; the link never invents
        # a record or a state.
        linked = {(r.system_id, r.resource_id) for r in records}
        for when, resource_id, target_system, _activity_id in self.link_catalogue.get(
            subject.user_id, []
        ):
            if when and cutoff and when > cutoff:
                continue
            candidates = [
                obs
                for obs in self.index.observations
                if obs.resource_id == resource_id
                and obs.category not in SINGLETON_CATEGORIES
                and (not obs.captured_at or not cutoff or obs.captured_at <= cutoff)
                and (not target_system or obs.system_id == target_system)
            ]
            if not candidates:
                continue
            best = max(candidates, key=lambda o: o.sort_key)
            # Screenshots and exports are point-in-time; an old capture is not
            # proof that the linked resource still exists at this audit time.
            if best.captured_at and cutoff and abs(
                _seconds_between(best.captured_at, cutoff)
            ) > 60 * 86400:
                continue
            key = (best.system_id, best.resource_id)
            if key in linked:
                continue
            linked.add(key)
            records.append(
                RecordState(
                    system_id=best.system_id,
                    resource_id=best.resource_id,
                    category=best.category,
                    state=best.state,
                    evidence_id=best.evidence_id,
                    observed_at=best.observed_at,
                    source_kind="catalogue_link",
                    origin=best.origin,
                )
            )
        records.sort(key=lambda r: (r.system_id, r.resource_id))

        # ---- policy-retained security audit record ---------------------
        # The audit trail must survive deletion.  When the record id is not in
        # the cutoff evidence it is still a stable, policy-required record; the
        # catalogue only supplies its id, never a state or a finding.
        if subject.user_id in self.audit_catalogue and not any(
            r.category == CAT_SECURITY_AUDIT_LOG for r in records
        ):
            audit_id = self.audit_catalogue[subject.user_id]
            matches = [
                obs
                for obs in observations
                if obs.resource_id == audit_id and obs.category == CAT_SECURITY_AUDIT_LOG
            ]
            evidence = max(matches, key=lambda o: o.sort_key).evidence_id if matches else ""
            records.append(
                RecordState(
                    system_id="security_service",
                    resource_id=audit_id,
                    category=CAT_SECURITY_AUDIT_LOG,
                    state=ST_PRESENT,
                    evidence_id=evidence,
                    observed_at="",
                    source_kind="catalogue",
                )
            )
            records.sort(key=lambda r: (r.system_id, r.resource_id))

        # ---- account record (always relevant) -------------------------
        if CAT_USER_PROFILE not in singletons:
            account = self._resolve_account_from_activity(case, cutoff)
            if account:
                evidence = bundle or self._latest_file_for_system("account_service", cutoff)
                if not evidence:
                    evidence = self._latest_file_overall(cutoff)
                records.append(
                    RecordState(
                        system_id="account_service",
                        resource_id=account,
                        category=CAT_USER_PROFILE,
                        state=ST_ABSENT,
                        evidence_id=evidence,
                        observed_at="",
                        source_kind="derived",
                    )
                )
                records.sort(key=lambda r: (r.system_id, r.resource_id))

        # ---- scope-only absence markers -------------------------------
        scope_absent = {
            obs.category
            for obs in observations
            if obs.scope_only and obs.state == ST_ABSENT
        }
        for category in scope_absent:
            if category in SINGLETON_CATEGORIES and category not in singletons:
                records.append(
                    RecordState(
                        system_id="account_service" if category == CAT_USER_PROFILE else "",
                        resource_id="",
                        category=category,
                        state=ST_ABSENT,
                        evidence_id=bundle,
                    )
                )

        outcome.records = [r for r in records if r.resource_id]
        self._emit_steps(outcome, case, cutoff)
        return outcome

    # ------------------------------------------------------------------
    def evidence_account_id(self, subject: Subject, cutoff: str) -> str:
        best: Observation | None = None
        for obs in self.observations_for(subject, cutoff):
            if obs.category == CAT_USER_PROFILE and obs.resource_id and not obs.scope_only:
                if best is None or obs.sort_key > best.sort_key:
                    best = obs
        return best.resource_id if best else ""

    def _dedicated_bundle(self, bundle: str, subject: Subject) -> bool:
        """True when ``bundle`` mentions no other requester but ``subject``.

        Such a file is dedicated to the subject, so records in it that carry no
        identifier of their own (for example an already anonymised analytics
        profile) can be attributed without guessing.
        """
        if not bundle or bundle not in self.index.files:
            return False
        requesters = set()
        for obs in self.index.files[bundle].observations:
            for ref in obs.user_refs:
                if ref in self.requester_users:
                    requesters.add(ref)
            for email in obs.emails:
                if self.identity_index is not None:
                    user_id = self.identity_index.resolve_by_email(email)
                    if user_id in self.requester_users:
                        requesters.add(user_id)
        return requesters <= {subject.user_id}


    # ------------------------------------------------------------------
    def _resolve_account_from_activity(self, case, cutoff: str) -> str:
        if case.case_id in self._account_assignments:
            return self._account_assignments[case.case_id]
        return ""

    def needs_account_record(self, subject: Subject, cutoff: str) -> bool:
        """True when the case has no evidence-linked account and needs an activity id."""
        if subject is None:
            return False
        for obs in self.observations_for(subject, cutoff):
            if obs.category == CAT_USER_PROFILE and obs.resource_id and not obs.scope_only:
                return False
        return True

    def register_account_assignments(self, cases: list[tuple]) -> None:
        """Assign account-deletion activity rows to cases that lack an account record.

        ``cases`` is a list of ``(case, needs_account, evidence_account_id)``
        tuples.  Candidates are restricted to the case's own deletion window and
        ranked so that the deletion result that matches the workflow's
        ``reported_status`` wins first, then the event closest to
        ``reported_at``.  The assignment is deterministic and one-to-one.
        """
        events = self.account_delete_events()
        if not events:
            return
        status_to_result = {
            "COMPLETE": "SUCCESS",
            "PARTIALLY_COMPLETE": "",
            "NOT_STARTED": "FAILED",
        }
        reserved = {account for _case, _needs, account in cases if account}
        pending = []
        for case, needs, _known in cases:
            if not needs:
                continue
            start = _shift(case.requested_at, -24 * 3600)
            end = _shift(case.reported_at or case.audit_at, 24 * 3600)
            cap = min(end, case.audit_at) if case.audit_at else end
            wanted = status_to_result.get((case.reported_status or "").strip().upper(), "")
            for row in events:
                resource_id = (row.get("resource_id") or "").strip()
                if resource_id in reserved:
                    continue
                when = norm_iso(row.get("event_time"))
                if start and when < start:
                    continue
                if cap and when > cap:
                    continue
                mismatch = 0 if (wanted and (row.get("reported_result") or "").strip() == wanted) else 1
                distance = abs(_seconds_between(when, case.reported_at or when))
                pending.append(
                    (mismatch, distance, case.case_id, row.get("activity_id", ""), resource_id)
                )
        pending.sort()
        used_cases: set[str] = set()
        used_resources: set[str] = set()
        for _mismatch, _distance, case_id, _activity_id, resource_id in pending:
            if case_id in used_cases or resource_id in used_resources:
                continue
            used_cases.add(case_id)
            used_resources.add(resource_id)
            self._account_assignments[case_id] = resource_id

    # ------------------------------------------------------------------
    def _emit_steps(self, outcome: CaseOutcome, case, cutoff: str) -> None:
        findings: list[tuple] = []
        remediations: list[tuple] = []
        verifications: list[tuple] = []

        seen: set[tuple[str, str, str]] = set()
        for record in outcome.records:
            if not record.resource_id:
                continue
            key = (record.system_id, record.resource_id)
            if key in seen:
                continue
            seen.add(key)
            category = record.category
            state = record.state
            action = self.policy.action_for(category, self._policy_context(record))
            evidence = record.evidence_id or self._fallback_evidence(record, cutoff, outcome.bundle)

            if category in DELETE_CATEGORIES or action == "DELETE":
                if state in {ST_ABSENT}:
                    verifications.append(
                        ("VERIFY_RECORD_ABSENT", record, evidence)
                    )
                else:
                    findings.append(("REPORT_REMAINING_RECORD", record, evidence))
                    remediations.append(("DELETE_RECORD", record))
                    verifications.append(("VERIFY_RECORD_ABSENT", record, ""))
            elif category in ANONYMIZE_CATEGORIES or action == "ANONYMIZE":
                if state in {ST_ANONYMIZED}:
                    verifications.append(("VERIFY_RECORD_ANONYMIZED", record, evidence))
                else:
                    findings.append(("REPORT_EXPOSED_PII", record, evidence))
                    remediations.append(("ANONYMIZE_RECORD", record))
                    verifications.append(("VERIFY_RECORD_ANONYMIZED", record, ""))
            elif category in REDACT_CATEGORIES or action == "REDACT":
                if state in {ST_REDACTED}:
                    verifications.append(("VERIFY_RECORD_REDACTED", record, evidence))
                else:
                    findings.append(("REPORT_EXPOSED_PII", record, evidence))
                    remediations.append(("REDACT_RECORD", record))
                    verifications.append(("VERIFY_RECORD_REDACTED", record, ""))
            elif category == CAT_DATA_FLOW or action == "RETAIN" and category == CAT_DATA_FLOW:
                if state in {ST_DISABLED}:
                    verifications.append(("VERIFY_DATA_FLOW_DISABLED", record, evidence))
                else:
                    findings.append(("REPORT_ACTIVE_DATA_FLOW", record, evidence))
                    remediations.append(("DISABLE_DATA_FLOW", record))
                    verifications.append(("VERIFY_DATA_FLOW_DISABLED", record, ""))
            elif category == CAT_BACKUP_ARCHIVE:
                if state in {ST_ABSENT}:
                    continue
                if state in {ST_BLOCKED}:
                    verifications.append(("VERIFY_RESTORE_BLOCKED", record, evidence))
                else:
                    findings.append(("REPORT_RESTORE_RISK", record, evidence))
                    remediations.append(("BLOCK_RESTORE", record))
                    verifications.append(("VERIFY_RESTORE_BLOCKED", record, ""))
            elif category in RETAIN_CATEGORIES or action == "RETAIN":
                if state not in {ST_ABSENT, ST_UNKNOWN}:
                    verifications.append(("VERIFY_RECORD_PRESENT", record, evidence))
            else:
                # Unknown category: never fabricate a finding.
                continue

        status = STATUS_INCOMPLETE if findings else STATUS_COMPLETE
        ordered_findings = sorted(
            findings, key=lambda item: _op_tuple(item[0], item[1].system_id, item[1].resource_id)
        )
        ordered_remediations = sorted(
            remediations, key=lambda item: _op_tuple(item[0], item[1].system_id, item[1].resource_id)
        )
        ordered_verifications = sorted(
            verifications, key=lambda item: _op_tuple(item[0], item[1].system_id, item[1].resource_id)
        )

        steps: list[dict] = []
        if status == STATUS_COMPLETE:
            for operation, record, evidence in ordered_verifications:
                steps.append(_step(len(steps) + 1, operation, record, evidence))
        else:
            for operation, record, evidence in ordered_findings:
                steps.append(_step(len(steps) + 1, operation, record, evidence))
            for operation, record in ordered_remediations:
                steps.append(_step(len(steps) + 1, operation, record, ""))
            for operation, record, _evidence in ordered_verifications:
                steps.append(_step(len(steps) + 1, operation, record, ""))

        outcome.status = status
        outcome.steps = steps

    @staticmethod
    def _policy_context(record: RecordState) -> dict:
        return {
            "still_attributable": record.state in {ST_PRESENT, ST_REDACTED, ST_ACTIVE},
            "contains_user_email": record.state == ST_PRESENT,
        }

    def _fallback_evidence(self, record: RecordState, cutoff: str, bundle: str) -> str:
        candidate = self._latest_file_for_system(
            record.system_id, cutoff, prefer_structured=record.category == CAT_USER_PROFILE
        )
        if candidate:
            return candidate
        if bundle:
            return bundle
        return self._latest_file_overall(cutoff)


def _step(step_no: int, operation: str, record: RecordState, evidence_id: str) -> dict:
    phase, state, _rank = OPERATIONS[operation]
    return {
        "step_no": step_no,
        "phase": phase,
        "system_id": record.system_id,
        "resource_id": record.resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id or "",
    }


def _shift(timestamp: str, seconds: int) -> str:
    from datetime import datetime, timedelta, timezone

    text = norm_iso(timestamp)
    if not text:
        return ""
    try:
        moment = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return ""
    return (moment + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seconds_between(left: str, right: str) -> int:
    from datetime import datetime, timezone

    try:
        a = datetime.strptime(norm_iso(left), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        b = datetime.strptime(norm_iso(right), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return 10**9
    return int((a - b).total_seconds())
