"""Identity resolution: current snapshot + historical audit log."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import (
    Subject,
    norm_email,
    norm_hash,
    norm_name,
    norm_phone,
    norm_user_ref,
)


@dataclass
class IdentityIndex:
    """In-memory index over ``user_identities`` and ``user_audit_log``."""

    by_user: dict[str, dict[str, str]] = field(default_factory=dict)
    _email_to_user: dict[str, str] = field(default_factory=dict)
    _hash_to_user: dict[str, str] = field(default_factory=dict)
    _phone_to_user: dict[str, str] = field(default_factory=dict)
    # user -> set of historical aliases
    _alias_emails: dict[str, set[str]] = field(default_factory=dict)
    _alias_phones: dict[str, set[str]] = field(default_factory=dict)
    _alias_hashes: dict[str, set[str]] = field(default_factory=dict)
    _alias_names: dict[str, set[str]] = field(default_factory=dict)
    audit_by_user: dict[str, list[dict[str, str]]] = field(default_factory=dict)

    # -- construction -----------------------------------------------------
    @classmethod
    def build(
        cls, identities: list[dict[str, str]], audit_rows: list[dict[str, str]]
    ) -> "IdentityIndex":
        index = cls()
        for row in identities:
            user_id = (row.get("user_id") or "").strip()
            if not user_id:
                continue
            index.by_user[user_id] = row
            email = norm_email(row.get("email"))
            if email:
                index._email_to_user.setdefault(email, user_id)
                index._alias_emails.setdefault(user_id, set()).add(email)
            phone = norm_phone(row.get("phone"))
            if phone:
                index._phone_to_user.setdefault(phone, user_id)
                index._alias_phones.setdefault(user_id, set()).add(phone)
            digest = norm_hash(row.get("email_hash"))
            if digest:
                index._hash_to_user.setdefault(digest, user_id)
                index._alias_hashes.setdefault(user_id, set()).add(digest)
            name = norm_name(row.get("name"))
            if name:
                index._alias_names.setdefault(user_id, set()).add(name)

        for row in audit_rows:
            user_id = (row.get("user_id") or "").strip()
            if not user_id:
                continue
            index.audit_by_user.setdefault(user_id, []).append(row)
            field = (row.get("field_name") or "").strip().lower()
            old = row.get("old_value")
            new = row.get("new_value")
            if field == "email":
                for value in (old, new):
                    email = norm_email(value)
                    if email:
                        index._alias_emails.setdefault(user_id, set()).add(email)
                        index._email_to_user.setdefault(email, user_id)
            elif field == "phone":
                for value in (old, new):
                    phone = norm_phone(value)
                    if phone:
                        index._alias_phones.setdefault(user_id, set()).add(phone)
                        index._phone_to_user.setdefault(phone, user_id)
            elif field == "email_hash":
                for value in (old, new):
                    digest = norm_hash(value)
                    if digest:
                        index._alias_hashes.setdefault(user_id, set()).add(digest)
                        index._hash_to_user.setdefault(digest, user_id)
            elif field == "name":
                for value in (old, new):
                    name = norm_name(value)
                    if name:
                        index._alias_names.setdefault(user_id, set()).add(name)
        return index

    # -- lookups ----------------------------------------------------------
    def resolve_by_email(self, email: str) -> str:
        key = norm_email(email)
        if not key:
            return ""
        found = self._email_to_user.get(key)
        if found:
            return found
        # A few audit rows store the address with different casing/spacing.
        for candidate, user_id in self._email_to_user.items():
            if candidate.casefold() == key.casefold():
                return user_id
        return ""

    def resolve_by_hash(self, digest: str) -> str:
        return self._hash_to_user.get(norm_hash(digest), "")

    def resolve_by_phone(self, phone: str) -> str:
        return self._phone_to_user.get(norm_phone(phone), "")

    def subject_for(self, user_id: str, request_email: str, matched_via: str) -> Subject:
        row = self.by_user.get(user_id, {})
        emails = set(self._alias_emails.get(user_id, set()))
        phones = set(self._alias_phones.get(user_id, set()))
        hashes = set(self._alias_hashes.get(user_id, set()))
        names = set(self._alias_names.get(user_id, set()))
        emails.add(norm_email(row.get("email")))
        phones.add(norm_phone(row.get("phone")))
        hashes.add(norm_hash(row.get("email_hash")))
        names.add(norm_name(row.get("name")))
        emails.discard("")
        phones.discard("")
        hashes.discard("")
        names.discard("")
        return Subject(
            user_id=user_id,
            names=frozenset(names),
            emails=frozenset(emails),
            phones=frozenset(phones),
            hashes=frozenset(hashes),
            user_refs=frozenset({user_id}) if user_id else frozenset(),
            matched_via=matched_via,
            request_email=norm_email(request_email),
        )

    def resolve_request(self, request_email: str, activity_hints: dict[str, str] | None = None) -> Subject | None:
        """Resolve the request email to a subject using the strongest available link."""
        user_id = self.resolve_by_email(request_email)
        if user_id:
            via = "current_identity" if norm_email(
                self.by_user.get(user_id, {}).get("email")
            ) == norm_email(request_email) else "historical_audit_email"
            return self.subject_for(user_id, request_email, via)
        if activity_hints:
            hint = activity_hints.get(norm_email(request_email))
            if hint:
                return self.subject_for(hint, request_email, "activity_link")
        return None


def activity_identity_hints(activity_rows: list[dict[str, str]]) -> dict[str, str]:
    """Emails that ``system_activity`` explicitly links to a ``user_id``.

    Only ``LINK_RESOURCE_IDENTITY`` style rows carry an explicit, grounded
    user reference; message text elsewhere is treated as a claim.
    """
    hints: dict[str, str] = {}
    for row in activity_rows:
        if (row.get("event_type") or "").strip() != "LINK_RESOURCE_IDENTITY":
            continue
        details = row.get("details") or ""
        user_ref = norm_user_ref(details)
        if not user_ref:
            continue
        from .model import extract_emails

        for email in extract_emails(details):
            hints.setdefault(email, user_ref)
    return hints
