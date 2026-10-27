"""Core data model, normalisation helpers and the allowed output vocabulary."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------------------
# Output vocabulary (frozen by the problem statement)
# ---------------------------------------------------------------------------

PHASE_FINDING = "FINDING"
PHASE_REMEDIATION = "REMEDIATION"
PHASE_VERIFICATION = "VERIFICATION"

STATUS_COMPLETE = "COMPLETE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

# operation -> (phase, state, rank).  The rank implements the ordering rule from
# the problem statement: order by phase, then by the operation order in the
# published table, then by system_id and resource_id.
OPERATIONS: dict[str, tuple[str, str, int]] = {
    "REPORT_REMAINING_RECORD": (PHASE_FINDING, "PRESENT", 0),
    "REPORT_EXPOSED_PII": (PHASE_FINDING, "PRESENT", 1),
    "REPORT_ACTIVE_DATA_FLOW": (PHASE_FINDING, "ACTIVE", 2),
    "REPORT_RESTORE_RISK": (PHASE_FINDING, "ACTIVE", 3),
    "DISABLE_DATA_FLOW": (PHASE_REMEDIATION, "DISABLED", 0),
    "BLOCK_RESTORE": (PHASE_REMEDIATION, "BLOCKED", 1),
    "DELETE_RECORD": (PHASE_REMEDIATION, "ABSENT", 2),
    "REDACT_RECORD": (PHASE_REMEDIATION, "REDACTED", 3),
    "ANONYMIZE_RECORD": (PHASE_REMEDIATION, "ANONYMIZED", 4),
    "VERIFY_RECORD_ABSENT": (PHASE_VERIFICATION, "ABSENT", 0),
    "VERIFY_RECORD_PRESENT": (PHASE_VERIFICATION, "PRESENT", 1),
    "VERIFY_RECORD_REDACTED": (PHASE_VERIFICATION, "REDACTED", 2),
    "VERIFY_RECORD_ANONYMIZED": (PHASE_VERIFICATION, "ANONYMIZED", 3),
    "VERIFY_DATA_FLOW_DISABLED": (PHASE_VERIFICATION, "DISABLED", 4),
    "VERIFY_RESTORE_BLOCKED": (PHASE_VERIFICATION, "BLOCKED", 5),
}

PHASE_ORDER = {PHASE_FINDING: 0, PHASE_REMEDIATION: 1, PHASE_VERIFICATION: 2}

STEP_FIELDS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)

# ---------------------------------------------------------------------------
# Canonical data categories (the vocabulary used by deletion_rules.csv)
# ---------------------------------------------------------------------------

CAT_USER_PROFILE = "USER_PROFILE"
CAT_SECONDARY_IDENTIFIER = "SECONDARY_IDENTIFIER"
CAT_SEARCH_INDEX_ENTRY = "SEARCH_INDEX_ENTRY"
CAT_CACHE_ENTRY = "CACHE_ENTRY"
CAT_SUPPORT_MESSAGE = "SUPPORT_MESSAGE"
CAT_SUPPORT_ATTACHMENT = "SUPPORT_ATTACHMENT"
CAT_ANALYTICS_PROFILE = "ANALYTICS_PROFILE"
CAT_PRODUCT_TELEMETRY = "PRODUCT_TELEMETRY"
CAT_USER_EXPORT = "USER_EXPORT"
CAT_MARKETING_PROFILE = "MARKETING_PROFILE"
CAT_EMAIL_DELIVERY_LOG = "EMAIL_DELIVERY_LOG"
CAT_SECURITY_AUDIT_LOG = "SECURITY_AUDIT_LOG"
CAT_LEGAL_HOLD_RECORD = "LEGAL_HOLD_RECORD"
CAT_BACKUP_ARCHIVE = "BACKUP_ARCHIVE"
CAT_ACCOUNT_TOMBSTONE = "ACCOUNT_TOMBSTONE"
CAT_DATA_FLOW = "DATA_FLOW"

# ---------------------------------------------------------------------------
# Observation states
# ---------------------------------------------------------------------------

ST_ABSENT = "ABSENT"
ST_PRESENT = "PRESENT"
ST_REDACTED = "REDACTED"
ST_ANONYMIZED = "ANONYMIZED"
ST_ACTIVE = "ACTIVE"
ST_DISABLED = "DISABLED"
ST_BLOCKED = "BLOCKED"
ST_UNKNOWN = "UNKNOWN"

# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

_WS = re.compile(r"\s+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"\+?\d[\d\s\-().]{5,}\d")
_USER_REF = re.compile(r"\buser_\d+\b")
_TICKET_REF = re.compile(r"\bCS-\d+\b")
_HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def norm_email(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def norm_phone(value: object) -> str:
    if value is None:
        return ""
    digits = re.sub(r"\D", "", str(value))
    return digits


def norm_hash(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def norm_name(value: object) -> str:
    if value is None:
        return ""
    return _WS.sub(" ", str(value)).strip().casefold()


def norm_user_ref(value: object) -> str:
    if value is None:
        return ""
    m = _USER_REF.search(str(value))
    return m.group(0) if m else ""


def norm_iso(value: object) -> str:
    """Normalise an ISO-8601 UTC timestamp to a lexicographically sortable form."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    m = _ISO.search(text)
    if m:
        return m.group(0)
    return text


def extract_emails(text: object) -> tuple[str, ...]:
    if text is None:
        return ()
    found = {norm_email(m) for m in _EMAIL.findall(str(text))}
    found.discard("")
    return tuple(sorted(found))


def extract_phones(text: object) -> tuple[str, ...]:
    if text is None:
        return ()
    out = set()
    for m in _PHONE.findall(str(text)):
        digits = norm_phone(m)
        if 7 <= len(digits) <= 15:
            out.add(digits)
    return tuple(sorted(out))


def extract_user_refs(text: object) -> tuple[str, ...]:
    if text is None:
        return ()
    return tuple(sorted(set(_USER_REF.findall(str(text)))))


def extract_hashes(text: object) -> tuple[str, ...]:
    if text is None:
        return ()
    return tuple(sorted({m.lower() for m in _HEX64.findall(str(text))}))


def is_blank(value: object) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    return text == "" or text.lower() in {"null", "none", "nil", "n/a", "-"}


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    """A single policy-relevant fact extracted from evidence.

    ``evidence_id`` is always a genuine participant-visible identifier:
    a ``file_id`` from ``evidence_files.csv``, an ``activity_id`` or an
    ``audit_id``.  It is never synthesised.
    """

    evidence_id: str
    source_kind: str  # "file" | "activity" | "audit"
    system_id: str
    resource_id: str
    category: str
    state: str
    observed_at: str
    captured_at: str
    user_refs: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()
    phones: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()
    detail: str = ""
    origin: str = ""
    # Set when the observation only proves a *scope* (e.g. an empty collection
    # snapshot) rather than a record-level fact.
    scope_only: bool = False

    @property
    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.observed_at, self.captured_at, self.evidence_id, self.resource_id)

    def identifiers(self) -> Iterable[str]:
        yield from self.emails
        yield from self.hashes


@dataclass
class ExtractIssue:
    file_id: str
    path: str
    reason: str


@dataclass
class EvidenceFile:
    file_id: str
    path: str
    origin: str
    captured_at: str
    fmt: str
    observations: list[Observation] = field(default_factory=list)
    issue: str = ""


@dataclass
class Subject:
    user_id: str
    names: frozenset[str]
    emails: frozenset[str]
    phones: frozenset[str]
    hashes: frozenset[str]
    user_refs: frozenset[str]
    matched_via: str
    request_email: str = ""


@dataclass
class CaseRequest:
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str
    authorised: bool = True
    intent: str = ""
    intent_source: str = "deterministic"
