"""Policy-rule loading and application.

The rules file is data, not code: every row describes a data category, the
condition under which the rule fires and the required action.  The engine in
:mod:`ghostdata.engine` only ever consults :class:`PolicyTable`.
"""

from __future__ import annotations

from dataclasses import dataclass

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
)

ACTION_DELETE = "DELETE"
ACTION_REDACT = "REDACT"
ACTION_ANONYMIZE = "ANONYMIZE"
ACTION_RETAIN = "RETAIN"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


class PolicyTable:
    """Parsed ``deletion_rules.csv`` with condition evaluation."""

    def __init__(self, rows: list[dict[str, str]]) -> None:
        self.rules: list[Rule] = []
        for row in rows:
            rule = Rule(
                rule_id=(row.get("rule_id") or "").strip(),
                data_category=(row.get("data_category") or "").strip(),
                condition=(row.get("condition") or "").strip(),
                required_action=(row.get("required_action") or "").strip().upper(),
            )
            if rule.data_category and rule.required_action:
                self.rules.append(rule)
        self._by_category: dict[str, list[Rule]] = {}
        for rule in self.rules:
            self._by_category.setdefault(rule.data_category, []).append(rule)

    # -- selection --------------------------------------------------------
    def rule_for(self, category: str, context: dict[str, object] | None = None) -> Rule | None:
        """Return the applicable rule for ``category`` under ``context``.

        The dataset ships one rule per category, but the evaluator is written
        so additional conditional rows can be added without touching engine
        code: rules are tried in file order and the first satisfied condition
        wins, with ``Always`` always satisfied.
        """
        candidates = self._by_category.get(category)
        if not candidates:
            return None
        context = context or {}
        for rule in candidates:
            if self._condition_holds(rule, context):
                return rule
        return None

    @staticmethod
    def _condition_holds(rule: Rule, context: dict[str, object]) -> bool:
        condition = rule.condition.strip()
        lowered = condition.lower()
        if lowered in {"always", ""}:
            return True
        flag = lowered.replace(" ", "_")
        for key in (
            "conversation_shared_context",
            "attachment_exclusive",
            "still_attributable",
            "contains_user_email",
            "within_retention",
            "legal_hold_active",
            "restore_blockable",
            "stable_user_reference_only",
        ):
            if key in flag:
                return bool(context.get(key, False))
        # Unknown condition wording: fall back to "satisfied" so that the
        # published action is still applied rather than silently dropped.
        return True

    def action_for(self, category: str, context: dict[str, object] | None = None) -> str:
        rule = self.rule_for(category, context)
        return rule.required_action if rule else ""

    def describe(self) -> list[dict[str, str]]:
        return [
            {
                "rule_id": rule.rule_id,
                "data_category": rule.data_category,
                "condition": rule.condition,
                "required_action": rule.required_action,
            }
            for rule in self.rules
        ]


# Categories whose records must disappear completely.
DELETE_CATEGORIES = {
    CAT_USER_PROFILE,
    CAT_SECONDARY_IDENTIFIER,
    CAT_SEARCH_INDEX_ENTRY,
    CAT_CACHE_ENTRY,
    CAT_SUPPORT_ATTACHMENT,
    CAT_USER_EXPORT,
    CAT_MARKETING_PROFILE,
}
# Categories that stay but lose direct identifiers.
REDACT_CATEGORIES = {CAT_SUPPORT_MESSAGE, CAT_EMAIL_DELIVERY_LOG, CAT_ACCOUNT_TOMBSTONE}
# Categories that stay but must be irreversibly unlinked.
ANONYMIZE_CATEGORIES = {CAT_ANALYTICS_PROFILE, CAT_PRODUCT_TELEMETRY}
# Categories that must remain available.
RETAIN_CATEGORIES = {CAT_SECURITY_AUDIT_LOG, CAT_LEGAL_HOLD_RECORD, CAT_BACKUP_ARCHIVE}
# Process categories.
FLOW_CATEGORIES = {CAT_DATA_FLOW}
