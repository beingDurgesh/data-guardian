#!/usr/bin/env python3
"""Participant-created edge cases for the Ghost Data deletion auditor.

The public sample set covers 32 happy-path and policy-mix scenarios.  These
cases isolate the decisions that are easiest to get wrong and that the sample
does not exercise directly:

1.  Korean deletion language is recognised after Unicode normalisation.
2.  A correction request is NOT_APPLICABLE and has no steps.
3.  A historical (pre-change) email resolves to the current subject.
4.  An active connector is disabled before dependent records are deleted, and
    the remediation/verification ordering is enforced.
5.  A restorable backup is reported, blocked and verified.
6.  A tombstone that still carries direct identifiers is redacted.
7.  An already-redacted tombstone yields a verification-only case.
8.  An attributable analytics profile is anonymised; an anonymous one passes.
9.  A policy-required security audit record is verified even when its id is only
    visible in a later read-back.
10. Replica drift is resolved in favour of the latest state at the cutoff.
11. Evidence captured after ``audit_at`` cannot create a finding.
12. A clean deletion is COMPLETE with evidence-backed verifications only.
13. Negated deletion language in eight non-English languages is NOT_APPLICABLE,
    while positive controls in the same languages still authorise deletion.
14. A JSON analytics record retaining only a stable user reference is still
    attributable; an anonymous one is ANONYMIZED; a tombstone with only its
    stable reference is REDACTED.
15. Real log fixtures: downloadable export -> PRESENT, denied restore ->
    BLOCKED, absent backup archive -> ABSENT, active connector -> ACTIVE,
    with exact ordering.

Run with::

    python code/evaluation/custom_cases.py

The cases build their own fixtures; no dataset file is required except the
published policy actions, which are mirrored here so the tests also run from
the submitted ``code.zip`` (which excludes ``dataset/``).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghostdata.engine import AuditEngine  # noqa: E402
from ghostdata.evidence import EvidenceIndex  # noqa: E402
from ghostdata.evidence.parsers import _state_from_generic, parse_log_file  # noqa: E402
from ghostdata.identity import IdentityIndex  # noqa: E402
from ghostdata.intent import authorises_deletion, classify  # noqa: E402
from ghostdata.model import (  # noqa: E402
    CAT_ACCOUNT_TOMBSTONE,
    CAT_ANALYTICS_PROFILE,
    CAT_BACKUP_ARCHIVE,
    CAT_DATA_FLOW,
    CAT_SEARCH_INDEX_ENTRY,
    CAT_SECURITY_AUDIT_LOG,
    CAT_SUPPORT_ATTACHMENT,
    CAT_SUPPORT_MESSAGE,
    CAT_USER_EXPORT,
    CAT_USER_PROFILE,
    CaseRequest,
    EvidenceFile,
    Observation,
    ST_ABSENT,
    ST_ACTIVE,
    ST_ANONYMIZED,
    ST_BLOCKED,
    ST_DISABLED,
    ST_PRESENT,
    ST_REDACTED,
    Subject,
)
from ghostdata.policy import PolicyTable  # noqa: E402

# Mirrors dataset/deletion_rules.csv (participant-facing policy data).
RULE_ROWS = [
    ("USER_PROFILE", "Always", "DELETE"),
    ("SECONDARY_IDENTIFIER", "Always", "DELETE"),
    ("SEARCH_INDEX_ENTRY", "Always", "DELETE"),
    ("CACHE_ENTRY", "Always", "DELETE"),
    ("SUPPORT_MESSAGE", "Conversation contains shared context", "REDACT"),
    ("SUPPORT_ATTACHMENT", "Attachment belongs only to the deletion subject", "DELETE"),
    ("ANALYTICS_PROFILE", "Record is still attributable to a user", "ANONYMIZE"),
    ("PRODUCT_TELEMETRY", "Record is still attributable to a user", "ANONYMIZE"),
    ("USER_EXPORT", "Always", "DELETE"),
    ("MARKETING_PROFILE", "Always", "DELETE"),
    ("EMAIL_DELIVERY_LOG", "Log contains a user email address", "REDACT"),
    ("SECURITY_AUDIT_LOG", "Record is within the retained period", "RETAIN"),
    ("LEGAL_HOLD_RECORD", "A supplied legal hold is active", "RETAIN"),
    ("BACKUP_ARCHIVE", "Restore access can be blocked", "RETAIN"),
    ("ACCOUNT_TOMBSTONE", "Only a stable internal user_id is needed", "REDACT"),
]

POLICY = PolicyTable(
    [
        {"rule_id": f"rule_{i:02d}", "data_category": category, "condition": condition, "required_action": action}
        for i, (category, condition, action) in enumerate(RULE_ROWS, start=1)
    ]
)

SUBJECT = Subject(
    user_id="user_900",
    names=frozenset({"test subject"}),
    emails=frozenset({"subject@example.com"}),
    phones=frozenset({"15550001111"}),
    hashes=frozenset({"a" * 64}),
    user_refs=frozenset({"user_900"}),
    matched_via="current_identity",
    request_email="subject@example.com",
)


def obs(
    file_id: str,
    captured_at: str,
    system: str,
    resource: str,
    category: str,
    state: str,
    *,
    emails: tuple[str, ...] = (),
    user_refs: tuple[str, ...] = ("user_900",),
    observed_at: str = "",
    scope_only: bool = False,
) -> Observation:
    return Observation(
        evidence_id=file_id,
        source_kind="file",
        system_id=system,
        resource_id=resource,
        category=category,
        state=state,
        observed_at=observed_at or captured_at,
        captured_at=captured_at,
        user_refs=user_refs,
        emails=emails,
        scope_only=scope_only,
    )


def index_of(files: list[tuple[str, str, list[Observation]]]) -> EvidenceIndex:
    index = EvidenceIndex()
    for file_id, captured_at, observations in files:
        index.add_file(
            EvidenceFile(
                file_id=file_id,
                path=f"evidence/{file_id}.json",
                origin="custom_test",
                captured_at=captured_at,
                fmt="json",
                observations=observations,
            )
        )
    return index


def make_case(case_id: str = "custom_01", audit_at: str = "2026-10-01T12:00:00Z") -> CaseRequest:
    return CaseRequest(
        case_id=case_id,
        email="subject@example.com",
        requested_at="2026-09-20T12:00:00Z",
        reported_status="COMPLETE",
        reported_at="2026-09-25T12:00:00Z",
        audit_at=audit_at,
        request_text="Please delete my account.",
    )


def analyse(index: EvidenceIndex, case: CaseRequest | None = None, authorised: bool = True, activity=None):
    engine = AuditEngine(index, POLICY, [], activity or [], {}, requester_users={"user_900"})
    outcome = engine.analyse(case or make_case(), SUBJECT, authorised, "deletion", "deterministic")
    return outcome, engine


def operations(outcome):
    return [step["operation"] for step in outcome.steps]


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def case_korean_intent():
    text = "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다. 개인정보 처리 절차에 따라 검토해 주세요."
    assert classify(text)[0] == "deletion", classify(text)
    assert authorises_deletion(text)[0] is True
    assert authorises_deletion("Please change the email address on my account.")[0] is False


def case_multilingual_non_deletion():
    """Negated deletion verbs must never be treated as authorisation.

    These are correction/access requests that mention deletion only to rule it
    out.  The classifier previously saw the deletion verb and authorised the
    case, which would have deleted a person's data against their wish.
    """
    non_deletion = [
        "Não quero excluir minha conta. Gostaria apenas de atualizar meu e-mail.",
        "Não solicito a exclusão da conta; peço uma cópia dos meus dados.",
        "Ich möchte mein Konto nicht löschen, bitte korrigieren Sie nur meine Adresse.",
        "Nie chcę usuwać konta, proszę tylko o kopię moich danych.",
        "Hesabımı silmek istemiyorum, sadece e-posta adresimi güncellemek istiyorum.",
        "我不想删除账户，只想更正我的电话号码。",
        "Verwijder mijn account niet, ik wil alleen mijn e-mailadres wijzigen.",
        "لا أطلب حذف حسابي، أريد فقط تصحيح بريدي الإلكتروني.",
        "アカウントを削除しないでください。住所だけ訂正したいです。",
        "계정을 삭제하지 마세요. 이메일 주소만 수정하고 싶습니다.",
    ]
    for text in non_deletion:
        intent, confidence, reason = classify(text)
        assert intent != "deletion", (text, intent, confidence, reason)
        assert authorises_deletion(text)[0] is False, (text, intent, reason)

    # The same languages must still recognise an actual deletion request.
    positive = [
        "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
        "アカウントを削除してください。",
        "Por favor, exclua minha conta.",
        "Bitte löschen Sie mein Konto.",
        "请删除我的账户。",
        "Lütfen hesabımı silin.",
    ]
    for text in positive:
        assert authorises_deletion(text)[0] is True, (text, classify(text))


def case_parser_states():
    """JSON records with only a stable user reference are still attributable."""
    attributable = {
        "resource_id": "analytics_1",
        "user_id": "user_900",
        "email": None,
        "phone": None,
        "name": None,
    }
    anonymous = {
        "resource_id": "analytics_2",
        "user_id": None,
        "email": None,
        "phone": None,
        "name": None,
    }
    tombstone = {
        "resource_id": "tombstone_1",
        "subject_reference": "user_900",
        "email": None,
        "phone": None,
        "name": None,
    }
    assert _state_from_generic(CAT_ANALYTICS_PROFILE, attributable) == ST_PRESENT
    assert _state_from_generic(CAT_ANALYTICS_PROFILE, anonymous) == ST_ANONYMIZED
    assert _state_from_generic(CAT_ACCOUNT_TOMBSTONE, tombstone) == ST_REDACTED


def case_log_export_and_restore_states():
    """Download availability and restore decisions are evidence, not statuses."""
    log = (
        "2026-09-30T10:00:00Z level=INFO service=export_service trace_id=tr-1 "
        "event=export_download_check_completed resource_id=export_1 "
        "file=customer_export_1.zip available=true correlation_key=subject@example.com\n"
        "2026-09-30T10:01:00Z level=INFO service=backup_service trace_id=tr-2 "
        "event=restore_authorization_completed resource_id=backup_1 decision=deny "
        "policy=privacy_deletion correlation_key=subject@example.com\n"
        "2026-09-30T10:02:00Z level=INFO service=backup_service trace_id=tr-3 "
        "event=restore_policy_read_completed resource_id=backup_2 archive_present=false "
        "restore_allowed=true correlation_key=subject@example.com\n"
        "2026-09-30T10:03:00Z level=INFO service=integration_service trace_id=tr-4 "
        "event=connector_heartbeat resource_id=data_flow_1 enabled=true "
        "scheduler_registered=true last_run=success correlation_key=subject@example.com\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "events.log"
        path.write_text(log, encoding="utf-8")
        observations = parse_log_file(path, "evidence_log", "2026-10-01T11:00:00Z", "custom_test")
    states = {(item.resource_id, item.category): item.state for item in observations}
    assert states[("export_1", CAT_USER_EXPORT)] == ST_PRESENT, states
    assert states[("backup_1", CAT_BACKUP_ARCHIVE)] == ST_BLOCKED, states
    assert states[("backup_2", CAT_BACKUP_ARCHIVE)] == ST_ABSENT, states
    assert states[("data_flow_1", CAT_DATA_FLOW)] == ST_ACTIVE, states

    with_account = observations + [
        obs("evidence_log", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT)
    ]
    outcome, _ = analyse(index_of([("evidence_log", "2026-10-01T11:00:00Z", with_account)]))
    assert outcome.status == "INCOMPLETE", outcome.status
    ops = operations(outcome)
    assert "REPORT_REMAINING_RECORD" in ops, ops
    assert "REPORT_ACTIVE_DATA_FLOW" in ops, ops
    assert ops.index("DISABLE_DATA_FLOW") < ops.index("DELETE_RECORD"), ops
    assert ops.index("VERIFY_RECORD_ABSENT") < ops.index("VERIFY_DATA_FLOW_DISABLED"), ops
    assert "VERIFY_RESTORE_BLOCKED" in ops, ops
    assert all(step["resource_id"] != "backup_2" for step in outcome.steps), outcome.steps


def case_correction_not_applicable():
    outcome, _ = analyse(index_of([]), authorised=False)
    assert outcome.status == "NOT_APPLICABLE", outcome.status
    assert outcome.steps == [], outcome.steps


def case_historical_email():
    identities = [
        {
            "user_id": "user_900",
            "name": "Test Subject",
            "email": "new@example.com",
            "phone": "+1 555 000 1111",
            "email_hash": "a" * 64,
            "updated_at": "2026-09-01T00:00:00Z",
        }
    ]
    audit = [
        {
            "audit_id": "audit_900",
            "user_id": "user_900",
            "event_time": "2026-08-01T00:00:00Z",
            "field_name": "email",
            "old_value": "old@example.com",
            "new_value": "new@example.com",
        }
    ]
    index = IdentityIndex.build(identities, audit)
    subject = index.resolve_request("old@example.com")
    assert subject is not None and subject.user_id == "user_900"
    assert subject.matched_via == "historical_audit_email", subject.matched_via


def case_active_flow_ordering():
    index = index_of(
        [
            (
                "evidence_flow",
                "2026-10-01T11:00:00Z",
                [
                    obs("evidence_flow", "2026-10-01T11:00:00Z", "integration_service", "data_flow_1", CAT_DATA_FLOW, ST_ACTIVE),
                    obs("evidence_flow", "2026-10-01T11:00:00Z", "search_service", "search_1", CAT_SEARCH_INDEX_ENTRY, ST_PRESENT, emails=("subject@example.com",)),
                    obs("evidence_flow", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT),
                ],
            )
        ]
    )
    outcome, _ = analyse(index)
    ops = operations(outcome)
    assert outcome.status == "INCOMPLETE", outcome.status
    assert "REPORT_ACTIVE_DATA_FLOW" in ops, ops
    assert ops.index("DISABLE_DATA_FLOW") < ops.index("DELETE_RECORD"), ops
    assert ops.index("VERIFY_RECORD_ABSENT") < ops.index("VERIFY_DATA_FLOW_DISABLED"), ops
    for step in outcome.steps:
        if step["phase"] != "FINDING":
            assert step["evidence_id"] == "", step


def case_backup_restore():
    index = index_of(
        [
            (
                "evidence_backup",
                "2026-10-01T11:00:00Z",
                [
                    obs("evidence_backup", "2026-10-01T11:00:00Z", "backup_service", "backup_1", CAT_BACKUP_ARCHIVE, ST_ACTIVE),
                    obs("evidence_backup", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT),
                ],
            )
        ]
    )
    outcome, _ = analyse(index)
    assert outcome.status == "INCOMPLETE", outcome.status
    assert operations(outcome) == [
        "REPORT_RESTORE_RISK",
        "BLOCK_RESTORE",
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RESTORE_BLOCKED",
    ], operations(outcome)


def case_tombstone_exposed():
    index = index_of(
        [
            (
                "evidence_tomb",
                "2026-10-01T11:00:00Z",
                [
                    obs("evidence_tomb", "2026-10-01T11:00:00Z", "identity_service", "tombstone_1", CAT_ACCOUNT_TOMBSTONE, ST_PRESENT, emails=("subject@example.com",)),
                    obs("evidence_tomb", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT),
                ],
            )
        ]
    )
    outcome, _ = analyse(index)
    assert outcome.status == "INCOMPLETE", outcome.status
    ops = operations(outcome)
    assert "REPORT_EXPOSED_PII" in ops and "REDACT_RECORD" in ops and "VERIFY_RECORD_REDACTED" in ops, ops


def case_tombstone_redacted():
    index = index_of(
        [
            (
                "evidence_tomb2",
                "2026-10-01T11:00:00Z",
                [
                    obs("evidence_tomb2", "2026-10-01T11:00:00Z", "identity_service", "tombstone_2", CAT_ACCOUNT_TOMBSTONE, ST_REDACTED, emails=(), user_refs=("user_900",)),
                    obs("evidence_tomb2", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT),
                ],
            )
        ]
    )
    outcome, _ = analyse(index)
    assert outcome.status == "COMPLETE", outcome.status
    assert operations(outcome) == ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_REDACTED"], operations(outcome)
    assert outcome.steps[1]["evidence_id"] == "evidence_tomb2"


def case_analytics():
    exposed = index_of(
        [
            (
                "evidence_analytics",
                "2026-10-01T11:00:00Z",
                [
                    obs("evidence_analytics", "2026-10-01T11:00:00Z", "analytics_platform", "analytics_1", CAT_ANALYTICS_PROFILE, ST_PRESENT, emails=("subject@example.com",)),
                    obs("evidence_analytics", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT),
                ],
            )
        ]
    )
    outcome, _ = analyse(exposed)
    assert outcome.status == "INCOMPLETE", outcome.status
    assert operations(outcome) == [
        "REPORT_EXPOSED_PII",
        "ANONYMIZE_RECORD",
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_ANONYMIZED",
    ], operations(outcome)

    anonymous = index_of(
        [
            (
                "evidence_analytics2",
                "2026-10-01T11:00:00Z",
                [
                    obs("evidence_analytics2", "2026-10-01T11:00:00Z", "analytics_platform", "analytics_1", CAT_ANALYTICS_PROFILE, ST_ANONYMIZED, emails=(), user_refs=("user_900",)),
                    obs("evidence_analytics2", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT),
                ],
            )
        ]
    )
    outcome, _ = analyse(anonymous)
    assert outcome.status == "COMPLETE", outcome.status
    assert "VERIFY_RECORD_ANONYMIZED" in operations(outcome), operations(outcome)


def case_retained_audit_catalogue():
    index = index_of(
        [
            (
                "evidence_early",
                "2026-10-01T11:00:00Z",
                [obs("evidence_early", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT)],
            ),
            (
                "evidence_late",
                "2026-11-01T11:00:00Z",
                [obs("evidence_late", "2026-11-01T11:00:00Z", "security_service", "audit_record_1", CAT_SECURITY_AUDIT_LOG, ST_PRESENT)],
            ),
        ]
    )
    outcome, _ = analyse(index)
    assert outcome.status == "COMPLETE", outcome.status
    assert operations(outcome) == ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT"], operations(outcome)
    assert outcome.steps[1]["resource_id"] == "audit_record_1"


def case_replica_drift():
    index = index_of(
        [
            (
                "evidence_primary",
                "2026-09-25T11:00:00Z",
                [obs("evidence_primary", "2026-09-25T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT)],
            ),
            (
                "evidence_replica",
                "2026-09-30T11:00:00Z",
                [obs("evidence_replica", "2026-09-30T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_PRESENT, emails=("subject@example.com",))],
            ),
        ]
    )
    outcome, _ = analyse(index)
    assert outcome.status == "INCOMPLETE", outcome.status
    assert "REPORT_REMAINING_RECORD" in operations(outcome), operations(outcome)
    assert outcome.steps[0]["evidence_id"] == "evidence_replica", outcome.steps[0]


def case_post_cutoff_ignored():
    index = index_of(
        [
            (
                "evidence_before",
                "2026-10-01T11:00:00Z",
                [obs("evidence_before", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT)],
            ),
            (
                "evidence_after",
                "2026-11-01T11:00:00Z",
                [obs("evidence_after", "2026-11-01T11:00:00Z", "search_service", "search_1", CAT_SEARCH_INDEX_ENTRY, ST_PRESENT, emails=("subject@example.com",))],
            ),
        ]
    )
    outcome, _ = analyse(index)
    assert outcome.status == "COMPLETE", outcome.status
    assert all(step["resource_id"] != "search_1" for step in outcome.steps), outcome.steps


def case_clean_complete():
    index = index_of(
        [
            (
                "evidence_clean",
                "2026-10-01T11:00:00Z",
                [
                    obs("evidence_clean", "2026-10-01T11:00:00Z", "account_service", "account_1", CAT_USER_PROFILE, ST_ABSENT),
                    obs("evidence_clean", "2026-10-01T11:00:00Z", "support_platform", "support_1", CAT_SUPPORT_MESSAGE, ST_REDACTED, emails=(), user_refs=("user_900",)),
                    obs("evidence_clean", "2026-10-01T11:00:00Z", "integration_service", "data_flow_1", CAT_DATA_FLOW, ST_DISABLED),
                    obs("evidence_clean", "2026-10-01T11:00:00Z", "backup_service", "backup_1", CAT_BACKUP_ARCHIVE, ST_BLOCKED),
                ],
            )
        ]
    )
    outcome, _ = analyse(index)
    assert outcome.status == "COMPLETE", outcome.status
    assert operations(outcome) == [
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_REDACTED",
        "VERIFY_DATA_FLOW_DISABLED",
        "VERIFY_RESTORE_BLOCKED",
    ], operations(outcome)
    assert all(step["evidence_id"] == "evidence_clean" for step in outcome.steps), outcome.steps


def case_attachment_catalogue_link():
    links = [
        {
            "activity_id": "activity_900",
            "event_time": "2026-09-28T10:00:00Z",
            "event_type": "LINK_RESOURCE_IDENTITY",
            "source_system": "data_catalog",
            "target_system": "object_storage",
            "resource_id": "object_1",
            "reported_result": "SUCCESS",
            "details": "Attachment catalog confirmed object_1 belongs only to subject@example.com and user_900.",
        }
    ]
    index = index_of(
        [
            (
                "evidence_object",
                "2026-09-29T10:00:00Z",
                [obs("evidence_object", "2026-09-29T10:00:00Z", "object_storage", "object_1", CAT_SUPPORT_ATTACHMENT, ST_PRESENT, emails=(), user_refs=())],
            )
        ]
    )
    outcome, _ = analyse(index, activity=links)
    assert outcome.status == "INCOMPLETE", outcome.status
    assert operations(outcome) == [
        "REPORT_REMAINING_RECORD",
        "DELETE_RECORD",
        "VERIFY_RECORD_ABSENT",
    ], operations(outcome)
    assert outcome.steps[0]["evidence_id"] == "evidence_object"


CASES = [
    ("korean_intent", case_korean_intent),
    ("multilingual_non_deletion", case_multilingual_non_deletion),
    ("parser_states", case_parser_states),
    ("log_export_and_restore_states", case_log_export_and_restore_states),
    ("correction_not_applicable", case_correction_not_applicable),
    ("historical_email", case_historical_email),
    ("active_flow_ordering", case_active_flow_ordering),
    ("backup_restore", case_backup_restore),
    ("tombstone_exposed", case_tombstone_exposed),
    ("tombstone_redacted", case_tombstone_redacted),
    ("analytics", case_analytics),
    ("retained_audit_catalogue", case_retained_audit_catalogue),
    ("replica_drift", case_replica_drift),
    ("post_cutoff_ignored", case_post_cutoff_ignored),
    ("clean_complete", case_clean_complete),
    ("attachment_catalogue_link", case_attachment_catalogue_link),
]


def main() -> int:
    failures = 0
    for name, function in CASES:
        try:
            function()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
        else:
            print(f"PASS {name}")
    print(f"\n{len(CASES) - failures}/{len(CASES)} custom cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
