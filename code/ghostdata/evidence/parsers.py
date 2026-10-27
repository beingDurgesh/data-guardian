"""Format-specific evidence parsers.

Every parser is pure: it reads one file and returns ``Observation`` objects
carrying the provenance of the fact (the manifest ``file_id`` plus the row /
line reference in ``detail``).  Parsers never guess case membership.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from ..model import (
    CAT_ANALYTICS_PROFILE,
    CAT_BACKUP_ARCHIVE,
    CAT_DATA_FLOW,
    CAT_SEARCH_INDEX_ENTRY,
    CAT_SECURITY_AUDIT_LOG,
    CAT_SUPPORT_ATTACHMENT,
    CAT_SUPPORT_MESSAGE,
    CAT_USER_EXPORT,
    CAT_USER_PROFILE,
    CAT_ACCOUNT_TOMBSTONE,
    CAT_PRODUCT_TELEMETRY,
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
from .schema import (
    COLLECTION_CATEGORY,
    STORE_SYSTEM,
    TABLE_CATEGORY,
    category_for_record_type,
    default_system_for,
    identity_fields,
    make_observation,
    state_for_result,
)

TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(.*)$")
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=((?:\\?"(?:[^"\\]|\\.)*\\?")|\S*)')
RESOURCE_RE = re.compile(
    r"\b(account_\d+|search_\d+|analytics_\d+|support_\d+|export_\d+|data_flow_\d+|"
    r"backup_\d+|audit_record_\d+|tombstone_\d+|cache_\d+|email_delivery_\d+|"
    r"marketing_\d+|object_\d+|telemetry_\d+)\b"
)


# ---------------------------------------------------------------------------
# Shared record -> observation conversion
# ---------------------------------------------------------------------------


def _state_from_generic(category: str, record: dict) -> str:
    if category == CAT_DATA_FLOW:
        enabled = record.get("enabled")
        if enabled is None:
            return ST_UNKNOWN
        return ST_ACTIVE if _truthy(enabled) else ST_DISABLED
    if category == CAT_BACKUP_ARCHIVE:
        allowed = record.get("restore_allowed")
        if allowed is None:
            return ST_ACTIVE
        return ST_BLOCKED if not _truthy(allowed) else ST_ACTIVE
    direct = _has_direct_identifiers(record)
    if category in {CAT_SUPPORT_MESSAGE, CAT_ACCOUNT_TOMBSTONE}:
        return ST_REDACTED if not direct else ST_PRESENT
    if category in {CAT_ANALYTICS_PROFILE, CAT_PRODUCT_TELEMETRY}:
        if "direct_identifiers" in record:
            return ST_PRESENT if _truthy(record.get("direct_identifiers")) else ST_ANONYMIZED
        # A retained stable user reference still makes the profile attributable
        # to a person, even when name/email/phone/hash were removed.
        user_refs = identity_fields(record)[0]
        return ST_PRESENT if (direct or user_refs) else ST_ANONYMIZED
    return ST_PRESENT


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "y", "enabled", "active"}


def _has_direct_identifiers(record: dict) -> bool:
    if "direct_identifiers" in record:
        return _truthy(record.get("direct_identifiers"))
    user_refs, emails, phones, names, hashes = identity_fields(record)
    return bool(emails or phones or hashes or names)


def _generic_record_observation(
    record: dict,
    *,
    evidence_id: str,
    captured_at: str,
    origin: str,
    table: str,
    system_override: str = "",
    category_override: str = "",
    observed_at: str = "",
    detail_prefix: str = "",
    force_state: str = "",
    extra_user_refs: tuple[str, ...] = (),
) -> Observation | None:
    resource_id = str(
        record.get("resource_id")
        or record.get("id")
        or record.get("object_key")
        or ""
    ).strip()
    if not resource_id:
        return None
    system_id = system_override or STORE_SYSTEM.get(table, "")
    category = category_override or TABLE_CATEGORY.get(table, "") or COLLECTION_CATEGORY.get(table, "")
    if not system_id or not category:
        guess_system, guess_category = default_system_for(resource_id)
        system_id = system_id or guess_system
        category = category or guess_category
    if not system_id or not category:
        return None
    state = force_state or _state_from_generic(category, record)
    user_refs, emails, phones, names, hashes = identity_fields(record)
    if extra_user_refs:
        user_refs = tuple(sorted(set(user_refs) | set(extra_user_refs)))
    observed = (
        observed_at
        or record.get("observed_at")
        or record.get("updated_at")
        or record.get("recorded_at")
        or record.get("indexed_at")
        or record.get("captured_at")
        or captured_at
    )
    return make_observation(
        evidence_id=evidence_id,
        source_kind="file",
        system_id=system_id,
        resource_id=resource_id,
        category=category,
        state=state,
        observed_at=str(observed),
        captured_at=captured_at,
        user_refs=user_refs,
        emails=emails,
        phones=phones,
        names=names,
        hashes=hashes,
        detail=f"{detail_prefix}{table}:{resource_id}",
        origin=origin,
    )


def _flat_record_observation(
    record: dict,
    *,
    evidence_id: str,
    captured_at: str,
    origin: str,
    default_system: str = "",
    source_path: str = "",
) -> Observation | None:
    """Handle ``{system, resource_id, record_type, result, subject_reference}`` rows."""
    resource_id = str(record.get("resource_id") or "").strip()
    if not resource_id:
        return None
    system_id = str(record.get("system") or default_system or "").strip()
    record_type = str(record.get("record_type") or "").strip()
    result = str(record.get("result") or record.get("state") or "").strip()
    category = category_for_record_type(record_type)
    guess_system, guess_category = default_system_for(resource_id)
    system_id = system_id or guess_system
    category = category or guess_category
    state = state_for_result(result) if result else _state_from_generic(category, record)

    subject = record.get("subject_reference")
    user_refs: set[str] = set()
    emails: set[str] = set()
    phones: set[str] = set()
    hashes: set[str] = set()
    names: set[str] = set()
    if subject is not None and not is_blank(subject):
        text = str(subject)
        ref = norm_user_ref(text)
        if ref:
            user_refs.add(ref)
        elif "@" in text:
            emails.add(norm_email(text))
        elif text.strip().startswith("+"):
            digits = norm_phone(text)
            if digits:
                phones.add(digits)
    extra = identity_fields(record)
    user_refs.update(extra[0])
    emails.update(extra[1])
    phones.update(extra[2])
    names.update(extra[3])
    hashes.update(extra[4])

    observed = (
        record.get("recorded_at")
        or record.get("observed_at")
        or record.get("updated_at")
        or captured_at
    )
    return make_observation(
        evidence_id=evidence_id,
        source_kind="file",
        system_id=system_id,
        resource_id=resource_id,
        category=category,
        state=state,
        observed_at=str(observed),
        captured_at=captured_at,
        user_refs=tuple(sorted(user_refs)),
        emails=tuple(sorted(emails)),
        phones=tuple(sorted(phones)),
        names=tuple(sorted(names)),
        hashes=tuple(sorted(hashes)),
        detail=f"{source_path}|{record_type}|{result}",
        origin=origin,
    )


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def parse_json_file(path: Path, file_id: str, captured_at: str, origin: str) -> list[Observation]:
    text = path.read_text(encoding="utf-8", errors="replace")
    data = json.loads(text)
    observations: list[Observation] = []

    # 1. records-assurance snapshot bundle
    if isinstance(data, dict) and "snapshots" in data:
        for snapshot in data.get("snapshots") or []:
            data_store = str(snapshot.get("data_store") or "").strip()
            collection = str(snapshot.get("collection") or "").strip()
            snapshot_at = norm_iso(snapshot.get("captured_at")) or captured_at
            records = snapshot.get("records") or []
            category = COLLECTION_CATEGORY.get(collection) or TABLE_CATEGORY.get(collection, "")
            system = STORE_SYSTEM.get(collection, data_store)
            if not records:
                if category and system:
                    observations.append(
                        make_observation(
                            evidence_id=file_id,
                            source_kind="file",
                            system_id=system,
                            resource_id="",
                            category=category,
                            state=ST_ABSENT,
                            observed_at=snapshot_at,
                            captured_at=captured_at,
                            detail=f"empty_collection:{data_store}/{collection}",
                            origin=origin,
                            scope_only=True,
                        )
                    )
                continue
            for record in records:
                obs = _generic_record_observation(
                    record,
                    evidence_id=file_id,
                    captured_at=captured_at,
                    origin=origin,
                    table=collection,
                    system_override=system,
                    category_override=category,
                    observed_at=snapshot_at,
                    detail_prefix="snapshot",
                )
                if obs is not None:
                    observations.append(obs)
        return observations

    # 2. service resource export (per-service collections)
    if isinstance(data, dict) and "service_exports" in data:
        return _parse_service_export(data, file_id, captured_at, origin)

    # 3. flat record arrays (connector configurations, audit ledgers, exports)
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        collection = str(data.get("collection") or "").strip()
        default_system = str(data.get("origin") or data.get("source") or "").strip()
        for record in data["records"]:
            if not isinstance(record, dict):
                continue
            if "system" in record and "record_type" in record:
                obs = _flat_record_observation(
                    record,
                    evidence_id=file_id,
                    captured_at=captured_at,
                    origin=origin,
                    source_path=path.name,
                )
            elif collection:
                obs = _generic_record_observation(
                    record,
                    evidence_id=file_id,
                    captured_at=captured_at,
                    origin=origin,
                    table=collection,
                    detail_prefix="records",
                )
            else:
                obs = None
            if obs is not None:
                observations.append(obs)
        return observations

    # 4. a bare list of records
    if isinstance(data, list):
        for record in data:
            if not isinstance(record, dict):
                continue
            obs = (
                _flat_record_observation(
                    record,
                    evidence_id=file_id,
                    captured_at=captured_at,
                    origin=origin,
                    source_path=path.name,
                )
                if "system" in record
                else None
            )
            if obs is not None:
                observations.append(obs)
        return observations

    return observations


def _parse_service_export(
    data: dict, file_id: str, captured_at: str, origin: str
) -> list[Observation]:
    observations: list[Observation] = []
    exported_at = norm_iso(data.get("exported_at")) or captured_at
    services = data.get("service_exports") or {}

    for lookup in (services.get("account_service") or {}).get("profile_lookups") or []:
        resource_id = str(lookup.get("resource_id") or "").strip()
        status = lookup.get("status_code")
        profile = lookup.get("profile") or {}
        observed = norm_iso(lookup.get("observed_at")) or exported_at
        if status == 404 or profile is None:
            state = ST_ABSENT
        else:
            user_refs, emails, phones, names, hashes = identity_fields(profile)
            state = ST_PRESENT
        user_refs, emails, phones, names, hashes = identity_fields(profile)
        observations.append(
            make_observation(
                evidence_id=file_id,
                source_kind="file",
                system_id="account_service",
                resource_id=resource_id,
                category=CAT_USER_PROFILE,
                state=state if profile is not None else ST_ABSENT,
                observed_at=observed,
                captured_at=captured_at,
                user_refs=user_refs,
                emails=emails,
                phones=phones,
                names=names,
                hashes=hashes,
                detail=f"profile_lookup:{status}",
                origin=origin,
            )
        )

    for profile in (services.get("analytics_platform") or {}).get("profiles") or []:
        obs = _generic_record_observation(
            profile,
            evidence_id=file_id,
            captured_at=captured_at,
            origin=origin,
            table="customer_analytics_profiles",
            system_override="analytics_platform",
            category_override=CAT_ANALYTICS_PROFILE,
            detail_prefix="analytics",
        )
        if obs is not None:
            observations.append(obs)

    for entry in (services.get("backup_service") or {}).get("restore_entries") or []:
        obs = _generic_record_observation(
            entry,
            evidence_id=file_id,
            captured_at=captured_at,
            origin=origin,
            table="backup_restore_entries",
            system_override="backup_service",
            category_override=CAT_BACKUP_ARCHIVE,
            detail_prefix="restore",
        )
        if obs is not None:
            observations.append(obs)

    for export in (services.get("export_service") or {}).get("exports") or []:
        obs = _generic_record_observation(
            export,
            evidence_id=file_id,
            captured_at=captured_at,
            origin=origin,
            table="customer_exports",
            system_override="export_service",
            category_override="USER_EXPORT",
            detail_prefix="export",
        )
        if obs is not None:
            observations.append(obs)

    for connector in (services.get("integration_service") or {}).get("connectors") or []:
        obs = _generic_record_observation(
            connector,
            evidence_id=file_id,
            captured_at=captured_at,
            origin=origin,
            table="connector_subscriptions",
            system_override="integration_service",
            category_override=CAT_DATA_FLOW,
            detail_prefix="connector",
        )
        if obs is not None:
            observations.append(obs)

    for query in (services.get("search_service") or {}).get("index_queries") or []:
        resource_id = str(query.get("resource_id") or "").strip()
        hits = query.get("hits") or {}
        total = hits.get("total")
        observed = norm_iso(query.get("observed_at")) or exported_at
        emails = set(extract_emails(query.get("query")))
        phones: set[str] = set()
        user_refs: set[str] = set()
        documents = hits.get("documents") or []
        for document in documents:
            sub = identity_fields(document)
            user_refs.update(sub[0])
            emails.update(sub[1])
            phones.update(sub[2])
        state = ST_PRESENT if (total or 0) > 0 or documents else ST_ABSENT
        observations.append(
            make_observation(
                evidence_id=file_id,
                source_kind="file",
                system_id="search_service",
                resource_id=resource_id,
                category=CAT_SEARCH_INDEX_ENTRY,
                state=state,
                observed_at=observed,
                captured_at=captured_at,
                user_refs=tuple(sorted(user_refs)),
                emails=tuple(sorted(emails)),
                phones=tuple(sorted(phones)),
                detail=f"index_query:total={total}",
                origin=origin,
            )
        )

    for record in (services.get("security_service") or {}).get("audit_records") or []:
        obs = _generic_record_observation(
            record,
            evidence_id=file_id,
            captured_at=captured_at,
            origin=origin,
            table="security_audit_records",
            system_override="security_service",
            category_override=CAT_SECURITY_AUDIT_LOG,
            detail_prefix="audit",
        )
        if obs is not None:
            observations.append(obs)

    for ticket in (services.get("support_platform") or {}).get("tickets") or []:
        obs = _generic_record_observation(
            ticket,
            evidence_id=file_id,
            captured_at=captured_at,
            origin=origin,
            table="support_conversations",
            system_override="support_platform",
            category_override=CAT_SUPPORT_MESSAGE,
            detail_prefix="ticket",
        )
        if obs is not None:
            observations.append(obs)

    for tombstone in (services.get("identity_service") or {}).get("deleted_references") or []:
        obs = _generic_record_observation(
            tombstone,
            evidence_id=file_id,
            captured_at=captured_at,
            origin=origin,
            table="deleted_customer_references",
            system_override="identity_service",
            category_override=CAT_ACCOUNT_TOMBSTONE,
            detail_prefix="tombstone",
        )
        if obs is not None:
            observations.append(obs)

    return observations


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------


def parse_sql_file(path: Path, file_id: str, captured_at: str, origin: str) -> list[Observation]:
    sql = path.read_text(encoding="utf-8", errors="replace")
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(sql)
        cur = con.cursor()
        tables = [row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        observations: list[Observation] = []
        for table in tables:
            columns = [row[1] for row in cur.execute(f'PRAGMA table_info("{table}")')]
            if not columns:
                continue
            if table == "snapshot_scope":
                continue
            rows = cur.execute(f'SELECT * FROM "{table}"').fetchall()
            for raw in rows:
                record = dict(zip(columns, raw))
                if "record_json" in record and record["record_json"]:
                    try:
                        payload = json.loads(record["record_json"])
                    except (TypeError, ValueError):
                        payload = None
                    if isinstance(payload, dict):
                        merged = dict(payload)
                        for key in ("updated_at",):
                            if key in record and key not in merged:
                                merged[key] = record[key]
                        obs = _generic_record_observation(
                            merged,
                            evidence_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            table=table,
                            system_override=str(record.get("origin_system") or ""),
                            category_override=COLLECTION_CATEGORY.get(
                                str(record.get("collection_name") or ""), ""
                            ),
                            observed_at=str(record.get("updated_at") or ""),
                            detail_prefix=f"sql:{table}",
                        )
                        if obs is not None:
                            observations.append(obs)
                        continue
                obs = _generic_record_observation(
                    record,
                    evidence_id=file_id,
                    captured_at=captured_at,
                    origin=origin,
                    table=table,
                    detail_prefix=f"sql:{table}",
                )
                if obs is not None:
                    observations.append(obs)
        return observations
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


def _split_ts(line: str) -> tuple[str, str]:
    match = TS_RE.match(line.strip())
    if not match:
        return "", line.strip()
    return match.group(1), match.group(2)


def _clean_value(value: str) -> str:
    text = value.strip()
    while text[:1] in {'"', "\\"}:
        text = text[1:]
    while text[-1:] in {'"', "\\"}:
        text = text[:-1]
    return text.replace('\\"', '"').strip()


def _parse_kv(payload: str) -> dict[str, str]:
    payload = payload.strip()
    if payload.startswith("{"):
        try:
            data = json.loads(payload)
        except ValueError:
            data = None
        if isinstance(data, dict):
            return {str(k): ("" if v is None else str(v)) for k, v in data.items()}
    pairs: dict[str, str] = {}
    for match in KV_RE.finditer(payload):
        pairs[match.group(1)] = _clean_value(match.group(2))
    return pairs


_IGNORED_EVENTS = {
    "thumbnail_failed",
    "deletion_marker_check",
    "export_started",
    "export_completed",
    "batch_started",
    "checkpoint_saved",
    "cache_refresh",
    "lease_extended",
    "delivery_abandoned",
    "telemetry_flushed",
    "consumer_lag",
    "flag_snapshot_loaded",
    "slow_call_rate",
    "timer_tick",
    "certificate_checked",
    "disk_latency",
    "dependency_retry",
    "dependency_recovered",
    "connection_acquired",
    "cache_lookup",
    "queue_lag",
    "secret_rotated",
}

_LOOKUP_KEY_FIELDS = (
    "lookup_key",
    "match_key",
    "subject_key",
    "subject_ref",
    "subject_reference",
    "correlation_key",
    "scan_key",
    "matched_value",
    "query",
    "lookup",
    "email",
    "customer_email",
    "owner_email",
    "owner_key",
    "customer_reference",
    "requester_email",
    "phone",
    "requester_phone",
    "message_text",
    "object_key",
    "archive_key",
)

_POSITIVE_IDENTIFIER_FIELDS = (
    "email",
    "customer_email",
    "owner_email",
    "requester_email",
    "requester_name",
    "requester_phone",
    "phone",
    "email_hash",
    "customer_reference",
    "subject_reference",
    "subject_ref",
    "user_id",
)


def parse_log_file(path: Path, file_id: str, captured_at: str, origin: str) -> list[Observation]:
    observations: list[Observation] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    traces: dict[str, list[dict[str, str]]] = {}
    singles: list[dict[str, str]] = []

    for index, line in enumerate(lines):
        if not line.strip():
            continue
        timestamp, payload = _split_ts(line)
        if not timestamp:
            continue
        kv = _parse_kv(payload)
        kv["_ts"] = timestamp
        kv["_line"] = str(index + 1)

        # 1. flat record_lookup rows carry everything they need
        if kv.get("resource_id") and kv.get("record_type"):
            obs = _flat_record_observation(
                {
                    "system": kv.get("system", ""),
                    "resource_id": kv.get("resource_id", ""),
                    "record_type": kv.get("record_type", ""),
                    "result": kv.get("result", ""),
                    "subject_reference": kv.get("subject_reference", "")
                    or kv.get("subject_ref", "")
                    or kv.get("matched_value", ""),
                    "recorded_at": timestamp,
                },
                evidence_id=file_id,
                captured_at=captured_at,
                origin=origin,
                source_path=f"{path.name}:{index + 1}",
            )
            if obs is not None:
                observations.append(obs)
            continue

        trace_id = kv.get("trace_id")
        if trace_id:
            traces.setdefault(trace_id, []).append(kv)
        else:
            singles.append(kv)

    for trace_id, events in traces.items():
        obs = _events_observation(trace_id, events, file_id, captured_at, origin, path.name)
        if obs is not None:
            observations.append(obs)

    for kv in singles:
        obs = _events_observation("single", [kv], file_id, captured_at, origin, path.name)
        if obs is not None:
            observations.append(obs)

    return observations


def _truthy_text(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y", "enabled", "active", "hit"}


def _collect_identifiers(events: list[dict[str, str]]) -> tuple[set[str], set[str], set[str], set[str]]:
    emails: set[str] = set()
    phones: set[str] = set()
    user_refs: set[str] = set()
    hashes: set[str] = set()
    for event in events:
        for field in _LOOKUP_KEY_FIELDS:
            value = event.get(field)
            if not value or value.strip().lower() in {"null", "none"}:
                continue
            emails.update(extract_emails(value))
            user_refs.update(extract_user_refs(value))
            hashes.update(extract_hashes(value))
            if field in {"phone", "requester_phone"}:
                digits = norm_phone(value)
                if digits:
                    phones.add(digits)
        if "email_hash" in event:
            hashes.update(extract_hashes(event["email_hash"]))
    return emails, phones, user_refs, hashes


def _infer_state(primary: dict[str, str], category: str) -> str:
    status = str(primary.get("http_status", "")).strip()
    rows = str(primary.get("rows", "")).strip()
    result = str(primary.get("result", "")).strip().lower()
    total_hits = str(primary.get("total_hits", "")).strip()

    if category == CAT_DATA_FLOW:
        if "enabled" in primary:
            return ST_ACTIVE if _truthy_text(primary["enabled"]) else ST_DISABLED
        if primary.get("last_delivery_status", "").strip().lower() in {"stopped", "disabled"}:
            return ST_DISABLED
        return ST_UNKNOWN

    if category == CAT_BACKUP_ARCHIVE:
        if "archive_present" in primary and not _truthy_text(primary["archive_present"]):
            return ST_ABSENT
        if "decision" in primary:
            decision = str(primary.get("decision") or "").strip().lower()
            if decision in {"deny", "denied", "blocked", "reject", "rejected"}:
                return ST_BLOCKED
            if decision in {"allow", "allowed", "approved"}:
                return ST_ACTIVE
        if "restore_allowed" in primary:
            return ST_ACTIVE if _truthy_text(primary["restore_allowed"]) else ST_BLOCKED
        if "deletion_block" in primary:
            return ST_BLOCKED if _truthy_text(primary["deletion_block"]) else ST_ACTIVE
        if "eligible" in primary:
            return ST_ACTIVE if _truthy_text(primary["eligible"]) else ST_BLOCKED
        return ST_UNKNOWN

    if category == CAT_USER_EXPORT:
        if "available" in primary:
            return ST_PRESENT if _truthy_text(primary["available"]) else ST_ABSENT
        if primary.get("file") or primary.get("object_key"):
            return ST_PRESENT

    if category == CAT_SECURITY_AUDIT_LOG:
        if rows.isdigit() and int(rows) == 0:
            return ST_ABSENT
        return ST_PRESENT

    if category in {CAT_SUPPORT_MESSAGE, CAT_SUPPORT_ATTACHMENT}:
        if rows.isdigit() and int(rows) == 0:
            return ST_ABSENT
        if "direct_identifiers" in primary:
            return ST_PRESENT if _truthy_text(primary["direct_identifiers"]) else ST_REDACTED
        for field in ("requester_name", "requester_email", "requester_phone", "email", "phone"):
            value = str(primary.get(field, "")).strip().lower()
            if value not in {"", "null", "none"}:
                return ST_PRESENT
        if primary.get("detector", "").strip().lower() in {"direct_identifier", "pii", "email"}:
            return ST_PRESENT
        for field in ("matched_value", "subject_key", "lookup_key"):
            value = primary.get(field, "")
            if extract_emails(value) or extract_hashes(value):
                return ST_PRESENT
        if extract_emails(primary.get("message_text", "")):
            return ST_PRESENT
        return ST_REDACTED

    if category == CAT_ANALYTICS_PROFILE:
        if "direct_identifiers" in primary:
            return ST_PRESENT if _truthy_text(primary["direct_identifiers"]) else ST_ANONYMIZED
        for field in ("email", "phone", "email_hash", "customer_reference", "subject_reference"):
            value = str(primary.get(field, "")).strip().lower()
            if value not in {"", "null", "none"}:
                return ST_PRESENT
        return ST_ANONYMIZED

    # Delete-style records: absence is only concluded from explicit negative signals.
    if status == "404" or result in {"miss", "not_found", "missing", "absent"}:
        return ST_ABSENT
    if rows.isdigit() and int(rows) == 0:
        return ST_ABSENT
    if total_hits.isdigit() and int(total_hits) == 0:
        return ST_ABSENT
    if status in {"200", "201", "204"} or result in {"hit", "found", "ok", "success"}:
        return ST_PRESENT
    if rows.isdigit() and int(rows) > 0:
        return ST_PRESENT
    return ST_UNKNOWN


def _events_observation(
    trace_id: str,
    events: list[dict[str, str]],
    file_id: str,
    captured_at: str,
    origin: str,
    path_name: str,
) -> Observation | None:
    # Choose the event that carries the outcome (latest *_completed / *_evaluated).
    primary: dict[str, str] | None = None
    for event in events:
        name = str(event.get("event") or "").lower()
        if name in _IGNORED_EVENTS:
            continue
        if not event.get("resource_id"):
            continue
        if primary is None:
            primary = event
        elif any(token in name for token in ("completed", "evaluated", "loaded", "read")):
            primary = event
    if primary is None:
        return None
    resource_id = str(primary.get("resource_id") or "").strip()
    if not resource_id:
        return None
    system_id, category = default_system_for(resource_id)
    system_override = str(primary.get("system") or "").strip()
    if system_override:
        system_id = system_override
    if not system_id or not category:
        return None
    if "email_opt_in" in primary and category == CAT_ANALYTICS_PROFILE:
        category = "MARKETING_PROFILE"
    if str(primary.get("event") or "") in {"contact_query_completed", "contact_lookup_completed"}:
        # A lookup against the legacy contact index is an attachment-style
        # support artefact, not a retained conversation record.
        category = CAT_SUPPORT_ATTACHMENT
    state = _infer_state(primary, category)
    if state == ST_UNKNOWN:
        return None
    emails, phones, user_refs, hashes = _collect_identifiers(events)
    observed = str(primary.get("_ts") or captured_at)
    return make_observation(
        evidence_id=file_id,
        source_kind="file",
        system_id=system_id,
        resource_id=resource_id,
        category=category,
        state=state,
        observed_at=observed,
        captured_at=captured_at,
        user_refs=tuple(sorted(user_refs)),
        emails=tuple(sorted(emails)),
        phones=tuple(sorted(phones)),
        hashes=tuple(sorted(hashes)),
        detail=f"{path_name}:{primary.get('_line', '?')}|trace={trace_id}|{primary.get('event', '')}",
        origin=origin,
    )


# ---------------------------------------------------------------------------
# Plain text handover
# ---------------------------------------------------------------------------

_HANDOVER_RE = re.compile(
    r"^-?\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*(.+)$"
)


def parse_text_file(path: Path, file_id: str, captured_at: str, origin: str) -> list[Observation]:
    observations: list[Observation] = []
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        match = _HANDOVER_RE.match(line.strip())
        if not match:
            continue
        timestamp, system, resource, record_type, state_text, subject = match.groups()
        obs = _flat_record_observation(
            {
                "system": system.strip(),
                "resource_id": resource.strip(),
                "record_type": record_type.strip(),
                "result": state_text.strip(),
                "subject_reference": subject.strip(),
                "recorded_at": timestamp,
            },
            evidence_id=file_id,
            captured_at=captured_at,
            origin=origin,
            source_path=f"{path.name}:{index + 1}",
        )
        if obs is not None:
            observations.append(obs)
    return observations


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def parse_pdf_file(path: Path, file_id: str, captured_at: str, origin: str) -> tuple[list[Observation], str]:
    try:
        from pypdf import PdfReader
    except ImportError:  # pragma: no cover - optional dependency
        return [], "pypdf not installed"

    try:
        reader = PdfReader(str(path))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception as exc:  # pragma: no cover - malformed PDFs
        return [], f"pdf parse error: {exc}"

    observations: list[Observation] = []
    lowered = text.lower()
    user_refs = set(extract_user_refs(text))
    emails = set(extract_emails(text))
    phones = {norm_phone(p) for p in extract_phones(text)}
    resource_ids = sorted(set(RESOURCE_RE.findall(text)))
    if not resource_ids and not user_refs:
        return observations, ""

    # Only records that the document explicitly names are reported.
    for resource_id in resource_ids:
        guess_system, guess_category = default_system_for(resource_id)
        if not guess_system:
            continue
        category = guess_category
        if resource_id.startswith("support_"):
            category = CAT_SUPPORT_ATTACHMENT if "attachment" in lowered else CAT_SUPPORT_MESSAGE
        state = ST_PRESENT
        if category == CAT_SUPPORT_MESSAGE and not (emails or phones):
            state = ST_REDACTED
        observations.append(
            make_observation(
                evidence_id=file_id,
                source_kind="file",
                system_id=guess_system,
                resource_id=resource_id,
                category=category,
                state=state,
                observed_at=captured_at,
                captured_at=captured_at,
                user_refs=tuple(sorted(user_refs)),
                emails=tuple(sorted(emails)),
                phones=tuple(sorted(p for p in phones if p)),
                detail=f"pdf:{path.name}",
                origin=origin,
            )
        )
    return observations, ""


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------


def parse_image_file(path: Path, file_id: str = "", captured_at: str = "", origin: str = "") -> tuple[list[Observation], str]:
    """Read a screenshot through the cached transcription, when one exists.

    The runtime has no OCR engine, so image facts are never guessed.  A
    reviewed transcription checked in next to this module supplies the facts a
    human analyst would read from each supplied screenshot; without an entry the
    file is reported as not machine-extracted instead of silently ignored.
    """
    try:
        from PIL import Image

        with Image.open(path) as image:
            image.verify()
    except Exception as exc:  # pragma: no cover - malformed image
        return [], f"image decode error: {exc}"

    entry = _vision_cache().get(file_id)
    if not entry:
        return [], "no local OCR engine and no cached transcription; image facts not machine-extracted"

    observations: list[Observation] = []
    for record in entry.get("records") or []:
        observations.append(
            make_observation(
                evidence_id=file_id,
                source_kind="file",
                system_id=str(record.get("system_id") or ""),
                resource_id=str(record.get("resource_id") or ""),
                category=str(record.get("category") or ""),
                state=str(record.get("state") or ST_UNKNOWN),
                observed_at=captured_at,
                captured_at=captured_at,
                user_refs=tuple(record.get("user_refs") or ()),
                emails=tuple(norm_email(e) for e in record.get("emails") or ()),
                phones=tuple(norm_phone(p) for p in record.get("phones") or ()),
                names=tuple(norm_name(n) for n in record.get("names") or ()),
                hashes=tuple(norm_hash(h) for h in record.get("hashes") or ()),
                detail=f"vision-cache:{record.get('detail') or entry.get('screen', '')}",
                origin=origin,
            )
        )
    return observations, ""


_VISION_CACHE: dict | None = None


def _vision_cache() -> dict:
    global _VISION_CACHE
    if _VISION_CACHE is None:
        cache_path = Path(__file__).with_name("vision_transcriptions.json")
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            _VISION_CACHE = payload.get("files") or {}
        except (OSError, ValueError):
            _VISION_CACHE = {}
    return _VISION_CACHE
