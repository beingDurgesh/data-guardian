"""Normalised vocabulary shared by every evidence parser."""

from __future__ import annotations

from ..model import (
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
    Observation,
    ST_ABSENT,
    ST_ACTIVE,
    ST_ANONYMIZED,
    ST_BLOCKED,
    ST_DISABLED,
    ST_PRESENT,
    ST_REDACTED,
    ST_UNKNOWN,
    extract_emails,
    extract_hashes,
    extract_phones,
    extract_user_refs,
    is_blank,
    norm_email,
    norm_hash,
    norm_iso,
    norm_name,
    norm_phone,
    norm_user_ref,
)

# ---------------------------------------------------------------------------
# resource prefix -> (system_id, default category)
# ---------------------------------------------------------------------------

RESOURCE_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("account_", "account_service", CAT_USER_PROFILE),
    ("search_", "search_service", CAT_SEARCH_INDEX_ENTRY),
    ("analytics_", "analytics_platform", CAT_ANALYTICS_PROFILE),
    ("support_", "support_platform", CAT_SUPPORT_MESSAGE),
    ("export_", "export_service", CAT_USER_EXPORT),
    ("data_flow_", "integration_service", CAT_DATA_FLOW),
    ("backup_", "backup_service", CAT_BACKUP_ARCHIVE),
    ("audit_record_", "security_service", CAT_SECURITY_AUDIT_LOG),
    ("tombstone_", "identity_service", CAT_ACCOUNT_TOMBSTONE),
    ("cache_", "cache_service", CAT_CACHE_ENTRY),
    ("email_delivery_", "email_delivery_service", CAT_EMAIL_DELIVERY_LOG),
    ("marketing_", "marketing_platform", CAT_MARKETING_PROFILE),
    ("legal_", "legal_service", CAT_LEGAL_HOLD_RECORD),
    ("object_", "object_storage", CAT_SUPPORT_ATTACHMENT),
    ("telemetry_", "analytics_platform", CAT_PRODUCT_TELEMETRY),
)

RECORD_TYPE_CATEGORY = {
    "USER_PROFILE": CAT_USER_PROFILE,
    "SECONDARY_IDENTIFIER": CAT_SECONDARY_IDENTIFIER,
    "SEARCH_INDEX_ENTRY": CAT_SEARCH_INDEX_ENTRY,
    "CACHE_ENTRY": CAT_CACHE_ENTRY,
    "SUPPORT_MESSAGE": CAT_SUPPORT_MESSAGE,
    "SUPPORT_ATTACHMENT": CAT_SUPPORT_ATTACHMENT,
    "ANALYTICS_PROFILE": CAT_ANALYTICS_PROFILE,
    "PRODUCT_TELEMETRY": CAT_PRODUCT_TELEMETRY,
    "USER_EXPORT": CAT_USER_EXPORT,
    "MARKETING_PROFILE": CAT_MARKETING_PROFILE,
    "EMAIL_DELIVERY_LOG": CAT_EMAIL_DELIVERY_LOG,
    "SECURITY_AUDIT_LOG": CAT_SECURITY_AUDIT_LOG,
    "LEGAL_HOLD_RECORD": CAT_LEGAL_HOLD_RECORD,
    "BACKUP_ARCHIVE": CAT_BACKUP_ARCHIVE,
    "ACCOUNT_TOMBSTONE": CAT_ACCOUNT_TOMBSTONE,
    "DATA_FLOW": CAT_DATA_FLOW,
}

TABLE_CATEGORY = {
    "customer_profiles": CAT_USER_PROFILE,
    "customer_profiles_primary": CAT_USER_PROFILE,
    "customer_profiles_failover_replica": CAT_USER_PROFILE,
    "customer_search_documents": CAT_SEARCH_INDEX_ENTRY,
    "search_documents_primary": CAT_SEARCH_INDEX_ENTRY,
    "customer_analytics_profiles": CAT_ANALYTICS_PROFILE,
    "customer_analytics_reports": CAT_ANALYTICS_PROFILE,
    "support_records": CAT_SUPPORT_MESSAGE,
    "support_conversations": CAT_SUPPORT_MESSAGE,
    "customer_exports": CAT_USER_EXPORT,
    "customer_export_jobs": CAT_USER_EXPORT,
    "connector_subscriptions": CAT_DATA_FLOW,
    "connector_configurations": CAT_DATA_FLOW,
    "backup_restore_entries": CAT_BACKUP_ARCHIVE,
    "backup_catalog": CAT_BACKUP_ARCHIVE,
    "security_audit_records": CAT_SECURITY_AUDIT_LOG,
    "security_audit_events": CAT_SECURITY_AUDIT_LOG,
    "deleted_customer_references": CAT_ACCOUNT_TOMBSTONE,
}

COLLECTION_CATEGORY = {
    "customer_profiles": CAT_USER_PROFILE,
    "customer_search_documents": CAT_SEARCH_INDEX_ENTRY,
    "customer_analytics_profiles": CAT_ANALYTICS_PROFILE,
    "customer_analytics_reports": CAT_ANALYTICS_PROFILE,
    "support_records": CAT_SUPPORT_MESSAGE,
    "support_conversations": CAT_SUPPORT_MESSAGE,
    "customer_exports": CAT_USER_EXPORT,
    "customer_export_jobs": CAT_USER_EXPORT,
    "connector_subscriptions": CAT_DATA_FLOW,
    "connector_configurations": CAT_DATA_FLOW,
    "backup_restore_entries": CAT_BACKUP_ARCHIVE,
    "backup_catalog": CAT_BACKUP_ARCHIVE,
    "security_audit_records": CAT_SECURITY_AUDIT_LOG,
    "security_audit_events": CAT_SECURITY_AUDIT_LOG,
    "deleted_customer_references": CAT_ACCOUNT_TOMBSTONE,
}

STORE_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "customer_search_documents": "search_service",
    "search_documents_primary": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "customer_analytics_reports": "analytics_platform",
    "support_records": "support_platform",
    "support_conversations": "support_platform",
    "customer_exports": "export_service",
    "customer_export_jobs": "export_service",
    "connector_subscriptions": "integration_service",
    "connector_configurations": "integration_service",
    "backup_restore_entries": "backup_service",
    "backup_catalog": "backup_service",
    "security_audit_records": "security_service",
    "security_audit_events": "security_service",
    "deleted_customer_references": "identity_service",
}

RESULT_STATE = {
    "NOT_FOUND": ST_ABSENT,
    "DELETED": ST_ABSENT,
    "FOUND": ST_PRESENT,
    "PRESENT": ST_PRESENT,
    "IDENTIFIABLE": ST_PRESENT,
    "ATTRIBUTABLE": ST_PRESENT,
    "ACTIVE": ST_ACTIVE,
    "ENABLED": ST_ACTIVE,
    "RESTORABLE": ST_ACTIVE,
    "REDACTED": ST_REDACTED,
    "ANONYMIZED": ST_ANONYMIZED,
    "DISABLED": ST_DISABLED,
    "BLOCKED": ST_BLOCKED,
    "RETENTION_BLOCKED": ST_BLOCKED,
    "RETAINED": ST_PRESENT,
    "WITHHELD": ST_PRESENT,
}


def default_system_for(resource_id: str) -> tuple[str, str]:
    for prefix, system, category in RESOURCE_PREFIXES:
        if resource_id.startswith(prefix):
            return system, category
    return "", ""


def category_for_record_type(record_type: str) -> str:
    return RECORD_TYPE_CATEGORY.get((record_type or "").strip().upper(), "")


def state_for_result(result: str) -> str:
    return RESULT_STATE.get((result or "").strip().upper(), ST_UNKNOWN)


# ---------------------------------------------------------------------------
# Identifier extraction helpers for free-form evidence
# ---------------------------------------------------------------------------


def identity_fields(record: dict) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Pull ``(user_refs, emails, phones, names, hashes)`` from a record dict."""
    emails: set[str] = set()
    phones: set[str] = set()
    names: set[str] = set()
    hashes: set[str] = set()
    user_refs: set[str] = set()

    for key, value in record.items():
        if value is None:
            continue
        lowered = key.lower()
        if isinstance(value, (dict, list)):
            continue
        if "email" in lowered and "hash" not in lowered:
            if not is_blank(value):
                emails.add(norm_email(value))
        elif "hash" in lowered:
            if not is_blank(value):
                hashes.add(norm_hash(value))
        elif "phone" in lowered or "mobile" in lowered:
            if not is_blank(value):
                digits = norm_phone(value)
                if digits:
                    phones.add(digits)
        elif "name" in lowered and "file" not in lowered and "index" not in lowered:
            if not is_blank(value):
                names.add(norm_name(value))
        elif lowered in {"user_id", "customer_reference", "subject_reference", "subject_selector", "owner"}:
            ref = norm_user_ref(value)
            if ref:
                user_refs.add(ref)
        elif "reference" in lowered or "selector" in lowered:
            ref = norm_user_ref(value)
            if ref:
                user_refs.add(ref)
            for email in extract_emails(value):
                emails.add(email)

    # Nested documents (search hits, profile objects).
    for key, value in record.items():
        if isinstance(value, dict):
            sub = identity_fields(value)
            user_refs.update(sub[0])
            emails.update(sub[1])
            phones.update(sub[2])
            names.update(sub[3])
            hashes.update(sub[4])

    emails.discard("")
    hashes.discard("")
    phones.discard("")
    return (
        tuple(sorted(user_refs)),
        tuple(sorted(emails)),
        tuple(sorted(phones)),
        tuple(sorted(names)),
        tuple(sorted(hashes)),
    )


def make_observation(
    *,
    evidence_id: str,
    source_kind: str,
    system_id: str,
    resource_id: str,
    category: str,
    state: str,
    observed_at: str,
    captured_at: str,
    user_refs: tuple[str, ...] = (),
    emails: tuple[str, ...] = (),
    phones: tuple[str, ...] = (),
    names: tuple[str, ...] = (),
    hashes: tuple[str, ...] = (),
    detail: str = "",
    origin: str = "",
    scope_only: bool = False,
) -> Observation:
    if not system_id or not category:
        guess_system, guess_category = default_system_for(resource_id)
        system_id = system_id or guess_system
        category = category or guess_category
    return Observation(
        evidence_id=evidence_id,
        source_kind=source_kind,
        system_id=system_id,
        resource_id=resource_id,
        category=category,
        state=state,
        observed_at=norm_iso(observed_at) or captured_at,
        captured_at=captured_at,
        user_refs=tuple(sorted(set(user_refs))),
        emails=tuple(sorted(set(emails))),
        phones=tuple(sorted(set(phones))),
        names=tuple(sorted(set(names))),
        hashes=tuple(sorted(set(hashes))),
        detail=detail[:400],
        origin=origin,
        scope_only=scope_only,
    )
