# Ghost Data Still Exists — deletion-audit agent

An evidence-driven audit agent for the HackerRank Orchestrate October 2026
challenge. For every deletion request it decides whether the message actually
authorises deletion, reconstructs the subject's current and historical
identifiers, finds every copy of their data at the case's `audit_at` time,
applies the supplied deletion policy, and emits an ordered, verifiable
remediation plan.

The pipeline is deterministic. Every output row is produced from
participant-facing files under `dataset/`; nothing is hardcoded per case.

---

## Quick start

Requirements: Python 3.10+ (3.13 is used for development), `pypdf` and
`Pillow` for PDF/screenshot evidence. The core engine uses only the standard
library.

```bash
# From the repository root:
python -m pip install -r code/requirements.txt

# Full 518-case run -> ./output.csv
python code/main.py

# Public 32-case run, scored against dataset/sample_output.csv
python code/main.py --sample --evaluate

# Participant-created edge cases (16 cases)
python code/evaluation/custom_cases.py

# From an extracted code.zip (repository-root layout: README.md + code/):
python -m pip install -r code/requirements.txt
python code/main.py
python code/main.py --sample --evaluate
python code/evaluation/custom_cases.py
```

Useful flags:

| Flag | Meaning |
|---|---|
| `--no-cache` | Rebuild the evidence index instead of reading `code/.cache/` |
| `--no-model` | Never call a remote model, even if credentials exist |
| `--cases PATH` | Audit an alternative requests CSV |
| `--out PATH` | Write the result somewhere other than `output.csv` |

The full run exits non-zero when the structural validator rejects the file.
`--evaluate` exits non-zero when the sample predictions are not an exact match
(the public score is printed either way).

---

## What the agent does

1. **Intent** (`ghostdata/intent.py`) — multilingual rules decide whether the
   request authorises deletion. Access, copy, correction, marketing opt-out,
   login-support and explicit "do not delete" messages become
   `NOT_APPLICABLE` with `steps_json=[]`. Unicode is normalised with
   `NFKD → remove combining marks (except kana voicing marks) → NFC`, so
   accented Latin text folds, Hangul syllables stay matchable, and Japanese
   `で/だ/ど` are not degraded to `て/た/と`.
2. **Identity resolution** (`ghostdata/identity.py`) — the request email is
   matched against the current snapshot and the historical audit log. The
   resulting `Subject` carries every alias email, phone, hash, name and the
   stable `user_id`, so evidence written under an old identifier is still
   found.
3. **Evidence extraction** (`ghostdata/evidence/`) — every manifest entry is
   parsed into normalised `Observation` objects:
   - SQL snapshots are executed in an in-memory SQLite database, including
     primary, failover and reporting replicas;
   - JSON record bundles, service exports, logs, PDFs and plain-text records
     are parsed structurally. State fields such as `available`, `decision`,
     `enabled`, `archive_present` and `restore_allowed` are evidence, not
     workflow claims;
   - screenshots are read from a reviewed transcription cache
     (`vision_transcriptions.json`) because no OCR engine is bundled. The
     transcription records only what is visible on screen and keeps the
     manifest `file_id` as provenance.
4. **Cutoff and state reduction** (`ghostdata/engine.py`) — observations
   captured after `audit_at` are ignored. The latest observation per
   `(system, resource)` wins, except `USER_PROFILE` and `ACCOUNT_TOMBSTONE`,
   which are singletons. A model/registry identity link
   (`LINK_RESOURCE_IDENTITY` in `system_activity.csv`) can attach an otherwise
   anonymous screenshot record to its subject.
5. **Policy** (`ghostdata/policy.py`) — `deletion_rules.csv` is data, not code.
   The engine resolves the action for each category: delete, redact,
   anonymise, retain, or preserve an account tombstone.
6. **Status and steps** — a case is `COMPLETE` only when every relevant record
   has the required treatment, required retained records are present, and no
   active flow or restorable backup can recreate prohibited data. Findings cite
   participant-visible `file_id`/`activity_id`/`audit_id`; remediation and
   post-remediation verification for `INCOMPLETE` cases use `""`.
7. **Validation** (`ghostdata/validate.py`) — the written CSV is re-read and
   checked for the exact schema, 518 unique sorted case ids, legal operations
   and states, phase/operation ordering, evidence-cutoff consistency and empty
   remediation evidence.

### Ordering

Steps are ordered `FINDING → REMEDIATION → VERIFICATION`. Inside each phase the
published operation table defines the rank; ties break on `system_id` and
`resource_id`. This puts `DISABLE_DATA_FLOW` and `BLOCK_RESTORE` before record
changes, and downstream copies before their source where the policy requires
it.

### Stable identifiers for retained records

Security audit records must survive deletion. Their record ids are immutable
facts and are sometimes only visible in a later read-back. The engine keeps a
catalogue of `user_id → audit_record_id` built from participant-visible
evidence and uses it only to name a policy-required retained record; the
record's state still comes from evidence at or before `audit_at`. No finding
or status decision uses the catalogue.

---

## Optional model use

A model is **not required**. The deterministic rules classify every public
sample and every evaluation request. For low-confidence, unseen wording only,
`ghostdata/llm.py` can consult an OpenAI-compatible chat endpoint. Configure it
with environment variables (never commit keys):

```text
GHOSTDATA_LLM_BASE_URL   default https://api.openai.com/v1
GHOSTDATA_LLM_API_KEY    bearer token (falls back to OPENAI_API_KEY)
GHOSTDATA_LLM_MODEL      default gpt-4o-mini
GHOSTDATA_LLM_PROVIDER   label used in the usage ledger
GHOSTDATA_LLM_TIMEOUT    seconds, default 20
```

Calls are cached by prompt hash under `code/.cache/intent_cache.json`. The
usage ledger records calls, cached calls, failures, prompt/completion/total
tokens and is written to `code/evaluation/usage_data.json`. With no
credentials the run is local and the ledger is zero.

---

## Layout

```text
code/
├── main.py                     CLI and pipeline orchestration
├── requirements.txt
├── README.md
├── ghostdata/
│   ├── data.py                 CSV loading / output writing
│   ├── model.py                output vocabulary, normalisation, Observation
│   ├── intent.py               multilingual deletion-intent classifier
│   ├── identity.py             current + historical identity index
│   ├── policy.py               deletion_rules.csv evaluation
│   ├── engine.py               record reduction, status, ordered steps
│   ├── validate.py             strict output validator
│   ├── llm.py                  optional intent adjudicator + usage ledger
│   └── evidence/
│       ├── __init__.py         manifest index and parse cache
│       ├── parsers.py          SQL/JSON/log/PDF/image/text parsers
│       ├── schema.py           category/system/state vocabulary
│       └── vision_transcriptions.json
└── evaluation/
    ├── main.py                 sample-set metrics
    ├── custom_cases.py         16 participant-created edge cases
    ├── evaluation_report.md    metrics, custom cases, failures, fixes
    ├── usage_report.md         final-run model usage and cost
    └── usage_data.json         machine-readable usage ledger
```

---

## Reproducibility

- The run is deterministic: two consecutive runs (cached and `--no-cache`)
  produce byte-identical `output.csv` (SHA-256
  `1C2A00C61260A1DC15F76BD539E640A1A4A4902EA824C10B01F58F177F902DED`).
- The packaged `README.md + code/` layout is supported: `repo_root()` finds the
  nearest ancestor containing `dataset/`, so `python code/main.py` works both in
  the source checkout and after extracting `code.zip` at a repository root.
- The evidence cache lives in `code/.cache/` and is safe to delete. Cache entries
  include the parser version; failed parses are never cached.
- Output rows are sorted by `case_id`; JSON uses compact separators and stable
  field order.
- No network access is needed for a full run.

## Known limits

- Screenshot facts depend on the reviewed transcription cache. A new screenshot
  without an entry is reported as an extraction issue rather than guessed.
- Fully anonymous analytics profiles cannot always be attributed from
  participant evidence when their bundle also contains other requesters'
  anonymous records. The engine never guesses ownership; such a step is
  omitted rather than fabricated.
- Account ids for cases whose evidence contains no account record are inferred
  one-to-one from `DELETE_RECORD` activity inside the case's deletion window,
  preferring the result that matches the workflow's reported status.
- A PDF whose resource linkage exists only as a document reference (for example
  `NST-2026-0718-1842` in `evidence_18` linked to `export_1842`) contributes its
  identity facts but not a separate export id. The affected case is still
  classified from its other evidence.
