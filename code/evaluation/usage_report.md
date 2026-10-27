# Usage report — final full-dataset run

## 1. Run summary

| Item | Value |
|---|---:|
| Requests audited | 518 |
| Wall-clock time | 1.58 s |
| Evidence files indexed | 94 |
| Extracted observations | 2,564 |
| Policy rules loaded | 15 |
| Output validation | PASS (518 unique rows, 0 problems) |
| Output status mix | COMPLETE 174 · INCOMPLETE 334 · NOT_APPLICABLE 10 |

Evidence formats indexed: 28 JSON, 26 log, 24 SQL, 11 image, 4 PDF, 1 text.
All 94 files parsed without an extraction issue.

## 2. Model usage

The submitted pipeline is deterministic. The optional OpenAI-compatible intent
adjudicator was **not activated** for the final run because no model
credentials were configured (`model_available: false`). No request text left
the machine.

| Provider | Model | Calls | Cached calls | Failed calls | Input tokens | Output tokens | Total tokens |
|---|---|---:|---:|---:|---:|---:|---:|
| _none_ | _none_ | 0 | 0 | 0 | 0 | 0 | 0 |

No provider or model name is applicable because no model was configured; the
`_none_` row records that explicitly rather than leaving an unrecorded value.
Per-model and overall totals are both zero.

## 3. Token and cost accounting

| Metric | Value |
|---|---:|
| Total input tokens | 0 |
| Total output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0.0 |
| Estimated total cost | USD 0.00 |
| Estimated cost per request | USD 0.00 |

Cost is zero because no hosted model was called. The engine performs all
identity linking, evidence parsing, policy application, status decisions and
step serialisation locally with Python's standard library (plus `pypdf` and
`Pillow` for file decoding).

## 4. Optional model path (not exercised in this run)

If `GHOSTDATA_LLM_API_KEY` (or `OPENAI_API_KEY`) is set, low-confidence intent
messages can be sent to an OpenAI-compatible `/chat/completions` endpoint. The
adjudicator records actual `usage.prompt_tokens`, `usage.completion_tokens` and
`usage.total_tokens` returned by the provider into
`code/evaluation/usage_data.json`; it never estimates them. The model is used
only for intent classification — never for the final deletion status or the
step list.

Configuration lives in environment variables:

```text
GHOSTDATA_LLM_BASE_URL
GHOSTDATA_LLM_API_KEY
GHOSTDATA_LLM_MODEL
GHOSTDATA_LLM_PROVIDER
GHOSTDATA_LLM_TIMEOUT
```

No keys, tokens or credentials are stored in the repository or in this report.

## 5. Machine-readable ledger

The authoritative ledger for the run is `code/evaluation/usage_data.json`. Its
`model` object is reproduced verbatim:

```json
{
  "provider": "",
  "model": "",
  "calls": 0,
  "cached_calls": 0,
  "failed_calls": 0,
  "prompt_tokens": 0,
  "completion_tokens": 0,
  "total_tokens": 0,
  "records": []
}
```
