"""Request-intent classification.

The classifier decides whether ``request_text`` actually authorises deletion.
It is deterministic and multilingual: the dataset contains deletion requests in
English, Spanish, French, Portuguese, German, Italian, Dutch, Polish, Turkish,
Arabic, Japanese, Korean and Chinese, plus non-deletion requests that only look
like deletion cases.

An optional LLM adjudicator (``ghostdata.llm``) is consulted only for requests
that the deterministic rules cannot classify, and only when credentials exist.
"""

from __future__ import annotations

import re
import unicodedata

INTENT_DELETION = "deletion"
INTENT_ACCESS = "access_or_copy"
INTENT_CORRECTION = "correction"
INTENT_MARKETING = "marketing_opt_out"
INTENT_SUPPORT = "account_support"
INTENT_UNKNOWN = "unknown"

# Verbs that authorise destruction of the account / personal data.
_DELETION_PATTERNS = (
    r"\bdelet(?:e|ed|ing|ion)\b",
    r"\beras(?:e|ed|ing|ure)\b",
    r"\bremov(?:e|ed|ing|al)\b",
    r"\bclose\b",
    r"\bclosing\b",
    r"\bpurge\b",
    r"\bdestroy\b",
    r"\bsupprim",
    r"\bsuppression\b",
    r"\bl[oö]sch",
    r"\belimin",
    r"\bexcluir\b",
    r"\bexclu(?:a|am|ir)\b",
    r"\bexclus",
    r"\bapag",
    r"\bborrar\b",
    r"\bborrado\b",
    r"\bcancel(?:ar|aci[oó]n)\b",
    r"\bverwijder",
    r"\busun\b",
    r"\busuw",
    r"\bудал",
    r"\bδιαγραφ",
    r"\bt[oö]rl",
    r"\bsil(?:me|in|insin)\b",
    r"\bortadan kald",
    r"\bkaldes\b",
    # Scripts without word boundaries
    r"删除",
    r"삭제",
    r"削除",
    r"حذف",
    r"抹除",
    r"消去",
)

# Phrases that explicitly disclaim deletion or scope the request elsewhere.
_NEGATION_PATTERNS = (
    r"not asking for deletion",
    r"not a request to erase",
    r"not requesting (?:deletion|erasure)",
    r"(?:do not|don'?t|please don'?t) (?:delete|close|erase|remove)",
    r"do not (?:close|delete) the account",
    r"leave the account",
    r"keep the account",
    r"leave my profile",
    r"still (?:need|want|use) (?:the|my|this)? ?account",
    r"still (?:want|need) (?:receipts|service messages)",
    r"continue using (?:the|this) service",
    r"without removing any",
    r"leave (?:the )?account (?:active|as it is)",
    r"keep (?:it|the account) as it is",
    r"(?:je )?ne souhaite pas (?:la )?suppression",
    r"keine l[oö]schung",
    r"nicht l[oö]schen",
    r"nicht l[oö]sch",
    r"no solicito (?:la )?(?:eliminaci[oó]n|supresi[oó]n)",
    r"non chiedo (?:la )?(?:cancellazione|eliminazione)",
    r"niet verwijderen",
    r"verwijder[^\n]{0,40}niet",
    r"geen verwijdering",
    r"nao (?:quero|solicito|desejo|pretendo|peco|pedi) (?:a )?(?:exclusao|eliminacao|apagar|excluir)",
    r"nao (?:excluir|apagar|eliminar)",
    r"sem excluir",
    r"nie (?:chce|prosze|zycze)[^\n]{0,40}(?:usun|usuw|skasow)",
    r"nie usuwaj",
    r"silmek istemiyorum",
    r"silinmesini istemiyorum",
    r"silmeyin",
    r"不要删除",
    r"不想删除",
    r"不要求删除",
    r"请勿删除",
    r"无需删除",
    r"لا (?:أ|ا)?(?:طلب|رغب|ريد)[^\n]{0,20}حذف",
    r"لا تحذف",
    r"عدم حذف",
    r"削除しない",
    r"削除を希望しません",
    r"削除は不要",
    r"削除不要",
    r"삭제하지",
    r"삭제를 원하지",
    r"삭제 불필요",
    r"لا أطلب الحذف",
)

_ACCESS_PATTERNS = (
    r"\bcopy of\b",
    r"\bdownload\b",
    r"\bportable format\b",
    r"\bwhat personal information you hold\b",
    r"\binformation (?:you )?hold(?: on| about)? me\b",
    r"\baccess my (?:data|profile|account information)\b",
    r"\bright of access\b",
    r"\bsend me a copy\b",
)

_CORRECTION_PATTERNS = (
    r"\bmisspell",
    r"\bcorrect (?:it|my|the record|the account)\b",
    r"\bchange the email address\b",
    r"\breplace it\b",
    r"\bout of date\b",
    r"\bupdate my\b",
)

_MARKETING_PATTERNS = (
    r"\bopt out\b",
    r"\bunsubscribe\b",
    r"\bstop the promotional\b",
    r"\bmarketing lists only\b",
    r"\bremove me from marketing\b",
)

_SUPPORT_PATTERNS = (
    r"\breset(?:ting)? the login\b",
    r"\bcan'?t access my profile\b",
    r"\bhelp resetting\b",
    r"\blocked out of my account\b",
)

# Follow-up language that confirms an existing deletion request.
_FOLLOWUP_PATTERNS = (
    r"\bprofile is gone\b",
    r"\bconfirm (?:that )?(?:the )?(?:profile|account) (?:is|was) (?:gone|deleted|removed)\b",
    r"\bcheck (?:whether|if) (?:any )?(?:data|records?) (?:still )?(?:remain|exists?)\b",
    r"\bcomplete the deletion\b",
    r"\bcheck the latest state\b",
    r"\bremaining records cannot identify me\b",
    r"\bstill existed\b",
    r"\bany data (?:is )?left\b",
)


def _normalise(text: str) -> str:
    # NFKD folds Latin accents (``lösch`` -> ``losch``) but also decomposes Hangul
    # syllables into conjoining jamo, which would defeat the Korean patterns.
    # Dropping combining marks and recomposing with NFC restores Hangul while
    # keeping the accent folding.
    folded = unicodedata.normalize("NFKD", text)
    # Kana voicing marks are semantic, not decorative: keep them so that NFC
    # can recompose で/だ/ど instead of turning them into て/た/と.
    stripped = "".join(
        ch
        for ch in folded
        if not unicodedata.combining(ch) or ch in {"\u3099", "\u309a"}
    )
    return unicodedata.normalize("NFC", stripped).casefold()


def _any(patterns: tuple[str, ...], text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def classify(text: str) -> tuple[str, float, str]:
    """Return ``(intent, confidence, rationale)`` for a request body."""
    raw = text or ""
    lowered = _normalise(raw)

    if _any(_NEGATION_PATTERNS, lowered):
        intent = INTENT_UNKNOWN
        for candidate, patterns in (
            (INTENT_MARKETING, _MARKETING_PATTERNS),
            (INTENT_ACCESS, _ACCESS_PATTERNS),
            (INTENT_CORRECTION, _CORRECTION_PATTERNS),
            (INTENT_SUPPORT, _SUPPORT_PATTERNS),
        ):
            if _any(patterns, lowered):
                intent = candidate
                break
        if intent == INTENT_UNKNOWN:
            intent = INTENT_ACCESS if "information" in lowered else INTENT_CORRECTION
        return intent, 0.97, "explicit non-deletion language"

    has_deletion = _any(_DELETION_PATTERNS, lowered)
    has_access = _any(_ACCESS_PATTERNS, lowered)
    has_correction = _any(_CORRECTION_PATTERNS, lowered)
    has_marketing = _any(_MARKETING_PATTERNS, lowered)
    has_support = _any(_SUPPORT_PATTERNS, lowered)
    has_followup = _any(_FOLLOWUP_PATTERNS, lowered)

    if has_deletion:
        return INTENT_DELETION, 0.95, "deletion verb present"

    if has_followup:
        return INTENT_DELETION, 0.8, "deletion follow-up language"

    if has_marketing and not has_deletion:
        return INTENT_MARKETING, 0.9, "marketing preference request"
    if has_access and not has_deletion:
        return INTENT_ACCESS, 0.9, "access / copy request"
    if has_correction and not has_deletion:
        return INTENT_CORRECTION, 0.9, "correction request"
    if has_support:
        return INTENT_SUPPORT, 0.85, "account support request"

    return INTENT_UNKNOWN, 0.4, "no deletion language detected"


def authorises_deletion(text: str, adjudicator=None) -> tuple[bool, str, str]:
    """Classify and, when allowed, escalate ambiguous requests to a model.

    Returns ``(authorised, intent, source)``.  ``source`` records whether the
    decision came from the deterministic rules or from the optional model.
    """
    intent, confidence, rationale = classify(text)
    if intent == INTENT_DELETION:
        return True, intent, "deterministic"
    if confidence >= 0.85:
        return False, intent, "deterministic"
    if adjudicator is not None:
        result = adjudicator(text)
        if result is not None:
            return result.authorised, result.intent, "model"
    return False, intent, "deterministic"
