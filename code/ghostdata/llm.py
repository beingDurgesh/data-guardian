"""Optional, tightly-scoped model assistance.

The production pipeline is deterministic.  A model is only consulted for
request-intent classification when the deterministic rules report low
confidence, and only when the environment provides credentials.  Every call is
cached by prompt hash and accounted for in ``usage.json``.

Configuration (all optional, read from the environment):

``GHOSTDATA_LLM_BASE_URL``  OpenAI-compatible base URL (default: api.openai.com/v1)
``GHOSTDATA_LLM_API_KEY``   bearer token (falls back to ``OPENAI_API_KEY``)
``GHOSTDATA_LLM_MODEL``     model name (default: gpt-4o-mini)
``GHOSTDATA_LLM_TIMEOUT``   per-request timeout in seconds (default: 20)
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

INTENT_SCHEMA_HINT = (
    '{"authorised": true|false, "intent": "deletion|access_or_copy|correction|'
    'marketing_opt_out|account_support|other", "reason": "<=20 words"}'
)

SYSTEM_PROMPT = (
    "You classify privacy request texts for a deletion-audit system. "
    "Decide whether the message authorises deletion or erasure of the account "
    "and its personal data. Requests for access, copies, correction, marketing "
    "opt-out, login help, or anything that explicitly says deletion is not "
    "wanted do NOT authorise deletion. Reply with strict JSON only, matching: "
    + INTENT_SCHEMA_HINT
)


@dataclass
class IntentVerdict:
    authorised: bool
    intent: str
    reason: str = ""


@dataclass
class UsageLedger:
    provider: str = ""
    model: str = ""
    calls: int = 0
    cached_calls: int = 0
    failed_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    records: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "calls": self.calls,
            "cached_calls": self.cached_calls,
            "failed_calls": self.failed_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "records": self.records,
        }


class LLMIntentAdjudicator:
    """Minimal OpenAI-compatible chat client with caching and accounting."""

    def __init__(self, cache_path: Path | None = None) -> None:
        base = os.environ.get("GHOSTDATA_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.endpoint = base + "/chat/completions"
        self.api_key = os.environ.get("GHOSTDATA_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
        self.model = os.environ.get("GHOSTDATA_LLM_MODEL", "gpt-4o-mini")
        self.provider = os.environ.get("GHOSTDATA_LLM_PROVIDER", "openai-compatible")
        try:
            self.timeout = float(os.environ.get("GHOSTDATA_LLM_TIMEOUT", "20"))
        except ValueError:
            self.timeout = 20.0
        self.ledger = UsageLedger(provider=self.provider, model=self.model)
        self.cache_path = cache_path
        self._cache: dict[str, dict] = {}
        if cache_path and cache_path.is_file():
            try:
                self._cache = json.loads(cache_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._cache = {}

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def __call__(self, text: str) -> IntentVerdict | None:
        if not self.available:
            return None
        key = hashlib.sha256((self.model + "\n" + text).encode("utf-8")).hexdigest()
        if key in self._cache:
            self.ledger.cached_calls += 1
            payload = self._cache[key]
            return IntentVerdict(
                authorised=bool(payload.get("authorised")), intent=str(payload.get("intent", "other"))
            )
        body = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": 120,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": text[:4000]},
            ],
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            usage = data.get("usage") or {}
            self.ledger.calls += 1
            self.ledger.prompt_tokens += int(usage.get("prompt_tokens") or 0)
            self.ledger.completion_tokens += int(usage.get("completion_tokens") or 0)
            self.ledger.total_tokens += int(usage.get("total_tokens") or 0)
            self.ledger.records.append(
                {
                    "kind": "intent",
                    "prompt_tokens": int(usage.get("prompt_tokens") or 0),
                    "completion_tokens": int(usage.get("completion_tokens") or 0),
                }
            )
            content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or "{}"
            parsed = json.loads(content) if content.strip().startswith("{") else {}
            verdict = {
                "authorised": bool(parsed.get("authorised")),
                "intent": str(parsed.get("intent") or "other"),
            }
            self._cache[key] = verdict
            self._persist()
            return IntentVerdict(authorised=verdict["authorised"], intent=verdict["intent"])
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError):
            self.ledger.failed_calls += 1
            return None

    def _persist(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache), encoding="utf-8")
        except OSError:
            pass
