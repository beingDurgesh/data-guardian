# Evaluation report — Ghost Data Still Exists

## 1. How to reproduce

```bash
python -m pip install -r code/requirements.txt
python code/main.py --sample --evaluate
python code/evaluation/custom_cases.py
python code/main.py --no-cache
```

`--evaluate` scores the 32 public sample requests against
`dataset/sample_output.csv` using `code/evaluation/main.py`. The full 518-case
run writes `output.csv` at the repository root and is validated by
`ghostdata/validate.py`; the process exits non-zero if any structural rule is
violated.

## 2. Public sample metrics (32 cases)

| Metric | Value |
|---|---:|
| Case-level deletion-status accuracy | **1.0000** (32/32) |
| Exact row match (status + every step field + order) | **0.6250** (20/32) |
| Ordered-sequence accuracy (operation sequence) | **0.7188** (23/32) |
| Step precision | **0.9565** (176 TP / 8 FP) |
| Step recall | **0.9119** (176 TP / 17 FN) |
| Step F1 | **0.9337** |
| Finding precision / recall | **1.0000 / 1.0000** |
| Remediation precision / recall | **1.0000 / 1.0000** |
| Operation accuracy (position-aligned) | **0.9457** |
| Field accuracy (all 7 fields, position-aligned) | **0.9620** |
| Supplementary field accuracy (semantically matched steps) | **0.9867** (1264/1281) |
| Evidence-reference accuracy | **0.9946** |
| False COMPLETE | **0** |
| False INCOMPLETE | **0** |
| Missed NOT_APPLICABLE | **0** |

The status decision is exact on every public case, including all ten
non-deletion requests and the tombstone cases. The remaining exact-match gap is
almost entirely a missing *anonymous* analytics or security-audit verification
step whose resource id is not derivable from the subject's identifiers.

The position-aligned field metric zips predicted and expected steps by index.
A single missing step therefore shifts every later `step_no` and depresses the
score. The supplementary row aligns steps by
`(phase, system_id, resource_id, operation)` and then compares all seven
fields. On those 1,281 matched field values, 10 `step_no` values and 7
`resource_id` values differ; the 7 resource mismatches are exactly the
account-id ambiguities in §4.2. `phase`, `system_id`, `operation`, `state` and
`evidence_id` are 100% correct on the matched steps. Both views are printed by
`python code/main.py --sample --evaluate` (`field_accuracy` and
`semantic_field_accuracy`).

## 3. Independent evaluator pass

I re-inspected the source, `output.csv`, the evaluation reports and validation
result as a skeptical reviewer, reran the public evaluator and the custom
suite, and added parser-level tests for gaps the public samples do not cover.
The public score is unchanged by the fixes below: status **1.0000**, exact
**0.6250**, sequence **0.7188**, step P/R/F1 **0.9565 / 0.9119 / 0.9337**,
position-aligned field **0.9620**, evidence **0.9946**.

### 3.1 False positives, false negatives and ordering

- **Step errors:** 8 false positives and 17 false negatives. All 8 false
  positives are wrong account ids (the expected account id exists only in
  truth). Of the 17 false negatives, 7 are anonymous analytics profiles with no
  participant-visible identifier, 2 are audit ids absent from every file, and 8
  are the matching account ids.
- **Status errors:** 0 false COMPLETE, 0 false INCOMPLETE, 0 missed
  NOT_APPLICABLE.
- **Evidence:** 0 predicted references that are unknown, captured after
  `audit_at`, or empty on a finding/COMPLETE verification. Evidence accuracy is
  0.9946; the single position-aligned mismatch is the account-id choice in
  `case_04` (a different account record has a different source file). All cited
  files are valid for their case and cutoff.
- **Ordering:** 0 rows violate the published phase/operation order. No case has
  the right multiset of steps in the wrong order; every sequence mismatch is
  caused by a missing or extra step.

### 3.2 High-impact defect found: downloadable exports were dropped

Completed log traces of the form

```text
event=export_download_check_completed resource_id=export_6406 file=... available=true
```

were classified `UNKNOWN` and discarded: `_infer_state` looked at
`http_status`, `rows`, `result` and `total_hits`, but not `available`. The same
omission affected `restore_authorization_completed ... decision=deny`.

This was not visible in the public sample because none of its cases has such a
trace. In the full set it produced four rows that said COMPLETE while the
case's own pre-cutoff evidence showed a downloadable export:

| Case | Evidence at audit | Before | After |
|---|---|---|---|
| `case_168` | `export_4102` available at 05:44, audit at 06:00 | COMPLETE | INCOMPLETE |
| `case_288` | `export_7906` available at 05:49, audit at 08:00 | COMPLETE | INCOMPLETE |
| `case_372` | `export_5081` available at 06:55, audit at 07:00 | COMPLETE | INCOMPLETE |
| `case_420` | `export_389` available at 08:57, audit at 09:00 | COMPLETE | INCOMPLETE |

Three more cases (`case_120`, `case_240`, `case_492`) were already INCOMPLETE
and gained the missing export finding, remediation and verification.

Measured full-dataset effect (same code, only the parser change):

| Metric | Before | After |
|---|---:|---:|
| COMPLETE rows | 178 | 174 |
| INCOMPLETE rows | 330 | 334 |
| NOT_APPLICABLE rows | 10 | 10 |
| Total steps | 2,804 | 2,825 |
| Finding steps | 623 | 630 |

The +21 steps are exactly seven findings, seven `DELETE_RECORD` remediations and
seven `VERIFY_RECORD_ABSENT` verifications. The four status flips also correctly
remove the now-inappropriate evidence ids from their post-remediation
verification steps (INCOMPLETE verification uses `""`).

### 3.3 Other defects fixed in the same pass

- **Kana voicing loss.** `NFKD` decomposes Japanese `で/だ/ど` into a base kana
  plus a combining dakuten, which the old normaliser stripped, turning
  `削除しないで` into `削除しないて`. Negated Japanese requests were therefore
  authorised as deletions. Kana voicing marks are now preserved and recomposed
  with NFC; a parser/intent test covers it.
- **Negated deletion in unsupported languages.** Portuguese, German, Polish,
  Chinese, Dutch, Arabic and Japanese requests that mention deletion only to
  rule it out were classified as deletion. Explicit negation patterns were
  added for all supported languages; the test asserts both the negative and
  positive directions.
- **Attributable analytics with only a stable reference.** A JSON analytics
  record retaining `user_id`/`customer_reference` but no email/name/phone/hash
  was labelled ANONYMIZED by the generic JSON parser. It is still attributable
  and now produces `REPORT_EXPOSED_PII`/`ANONYMIZE_RECORD`; the log parser
  already behaved this way.
- **Backup archive absent.** `archive_present=false` now yields ABSENT rather
  than being overridden by `restore_allowed=true`; the engine emits no restore
  risk for an archive that does not exist.

### 3.4 Tests added

The custom suite grew from 13 to **16** cases, and all 16 pass. The new tests
are assertion-based, not smoke tests:

- `multilingual_non_deletion` checks eight languages plus positive deletion
  controls;
- `parser_states` feeds attributable/anonymous/tombstone records through the
  real JSON state function;
- `log_export_and_restore_states` writes a real log fixture, parses it with
  `parse_log_file`, and asserts PRESENT export, BLOCKED deny, ABSENT archive,
  ACTIVE connector, plus disable-before-delete and absent-before-disabled
  ordering.

## 4. Per-case error analysis

12 of 32 sample rows are not byte-identical. They fall into three groups.

### 4.1 Anonymous analytics profiles (7 cases: 03, 04, 21, 25, 26, 27, 28)

The expected answer attributes one analytics profile whose `user_id`, email,
phone and hash are all `null`. Several such profiles share the same bundle and
belong to different requesters (for example five anonymous profiles in
`evidence_92`). Participant-facing evidence contains no identifier that links
a specific anonymous profile to a specific subject. The engine deliberately
does not guess ownership, so it omits the step. Status stays correct
(`COMPLETE`) because the unlinked profile cannot be shown to contain the
subject's data. Adding a "dedicated bundle" heuristic was tested and rejected:
it added the right step for one case but introduced a false step for `case_09`
and reduced exact match from 0.625 to 0.594.

### 4.2 Account ids that exist only in organizer truth (4 cases: 04, 23, 29, 31)

The expected account resource (`account_004`, `account_410`, `account_7012`,
`account_4857`) appears in no participant evidence file, and its
`DELETE_RECORD` activity row has the same result and a similar timestamp to
several other candidates in the same window. The engine assigns accounts
one-to-one within the case window, preferring the result that matches the
reported workflow status and then the closest event. For these four clusters
the remaining ambiguity cannot be resolved from the supplied files; the engine
picks a different candidate but still emits the correct operation and state.

### 4.3 Audit records absent from every participant file (2 cases: 18, 20)

`audit_record_6645` and `audit_record_5569` do not occur in any evidence file
or activity row. The policy still requires a retained security-audit record,
so the case is correct in status but one verification step cannot be named.

## 5. Failures found during development and fixes applied

| Failure | Root cause | Fix | Effect |
|---|---|---|---|
| Korean requests classified `NOT_APPLICABLE` | `NFKD` decomposes Hangul syllables into jamo, so `삭제` never matched | Normalise `NFKD → strip combining marks (preserve kana voicing) → NFC` | 12 evaluation requests moved from N/A to correctly audited deletion cases |
| Five COMPLETE cases had empty `steps` | Image parser called with the old one-argument signature; then `norm_name` was undefined inside the new image path | Pass `file_id/captured_at/origin`; import `norm_name` | Screenshots now contribute records; validator passes |
| All images silently returned zero facts after a failed parse | Parse failures were cached as empty successes | Cache only successful parses; bump cache version | 11 screenshots parsed with zero issues |
| No retained-audit verification for cases whose audit id is only visible in a later read-back | Catalogue did not exist | Added a user→audit-record id catalogue used only to name the retained record | Exact match 0.500 → 0.625; no status changes |
| Stale tombstone reported for a re-created account (`case_17`) | Any tombstone matching the subject was treated as current | A tombstone observed before `requested_at` is excluded | Removed one false step |
| `case_61` (Feb 2026) produced an empty COMPLETE row | Its only evidence is a screenshot with no identifiers; the catalogue link was ignored | Added `LINK_RESOURCE_IDENTITY` ownership links with a 60-day freshness guard | Case now reports the remaining attachment and a remediation plan |
| Fast failover replica still held the profile | Latest-state reduction already handled it; the test suite locks the behaviour in | Added `replica_drift` custom case | Regression coverage |
| Four COMPLETE rows had a downloadable export | Completed export-download traces were dropped because `_infer_state` ignored `available` | Parse `available`, `file` and `object_key` as export state | 4 false COMPLETEs became INCOMPLETE; +7 findings overall |
| Denied restores and absent backup archives were invisible | `decision` and `archive_present` were not parsed | Parse deny/allow and archive presence; skip ABSENT archives | Correct BLOCKED/ACTIVE/ABSENT backup state; parser test added |
| Japanese negated requests were authorised | NFKD + blanket combining-mark removal turned `で` into `て` | Preserve U+3099/U+309A and recompose with NFC | Japanese negation works; test added |
| Negated deletion in Portuguese/German/Polish/Chinese/Dutch/Arabic/Japanese authorised | Only a few English/Latin negation patterns existed | Added language-specific negation patterns and positive controls | 8-language test added; no public/eval rows changed |
| Analytics profile with only `user_id` was labelled anonymous | Generic JSON state counted only direct identifiers | Count stable user references as attributable for analytics/telemetry | Policy-correct state; parser test added |

## 6. Participant-created evaluation cases

16 cases are implemented in `code/evaluation/custom_cases.py`; all 16 pass.
They use self-contained fixtures and the published policy actions, so they run
from `code.zip` without `dataset/`.

| # | Case | What it asserts |
|---|---|---|
| 1 | `korean_intent` | Korean deletion language authorises deletion after Unicode normalisation; an English correction does not |
| 2 | `multilingual_non_deletion` | Portuguese, German, Polish, Turkish, Chinese, Dutch, Arabic, Japanese and Korean "do not delete" messages are NOT_APPLICABLE; positive controls in the same languages still authorise deletion |
| 3 | `parser_states` | A JSON analytics record with only `user_id` is attributable; a fully anonymous one is ANONYMIZED; a tombstone with only `subject_reference` is REDACTED |
| 4 | `log_export_and_restore_states` | Real log fixture: `available=true` export is PRESENT, `decision=deny` backup is BLOCKED, `archive_present=false` is ABSENT, active connector heartbeat is ACTIVE, and disable/delete/verify ordering is exact |
| 5 | `correction_not_applicable` | Non-deletion request → `NOT_APPLICABLE`, empty steps |
| 6 | `historical_email` | A pre-change email resolves to the current `user_id` with `historical_audit_email` |
| 7 | `active_flow_ordering` | Active connector is disabled before the dependent record is deleted; verification order is absent-before-disabled; non-finding evidence is blank |
| 8 | `backup_restore` | Restorable backup → report, block, verify; exact operation order |
| 9 | `tombstone_exposed` | Tombstone with direct identifiers → `REPORT_EXPOSED_PII` + redact + verify |
| 10 | `tombstone_redacted` | Already-redacted tombstone → verification-only COMPLETE, no finding |
| 11 | `analytics` | Attributable profile is anonymised; anonymous profile passes with a verification |
| 12 | `retained_audit_catalogue` | A retained audit record is verified even when its id appears only after the cutoff |
| 13 | `replica_drift` | Latest replica state at the cutoff wins over an older primary snapshot |
| 14 | `post_cutoff_ignored` | A record captured after `audit_at` cannot create a finding |
| 15 | `clean_complete` | Clean deletion → COMPLETE with four evidence-backed verifications in operation order |
| 16 | `attachment_catalogue_link` | A catalogue identity link attributes an anonymous attachment without inventing a state |

## 7. Structural validation

The final full run writes 518 rows, sorted by `case_id`, with exactly the
header `case_id,deletion_status,steps_json`. The validator reports:

```text
ok: true
rows: 518
unique_case_ids: 518
status_counts: COMPLETE 174, INCOMPLETE 334, NOT_APPLICABLE 10
problems: []
```

Checks include: legal status/operation/state vocabulary, consecutive step
numbers, phase and operation ordering, non-empty system/resource ids, finding
evidence present, no finding or COMPLETE evidence captured after `audit_at`,
and empty evidence on INCOMPLETE remediation/verification steps.

## 8. Determinism

Two full runs — one with `--no-cache`, one with the populated cache — produced
byte-identical output:

```text
SHA-256 1C2A00C61260A1DC15F76BD539E640A1A4A4902EA824C10B01F58F177F902DED
```

The packaged `code.zip` (repository-root layout: `README.md` plus `code/`) was
also extracted into an empty directory, a dataset junction was added at the
extraction root, and `python code/main.py --no-cache`, the 16 custom cases and
`python code/main.py --sample --evaluate` were run from the extracted package.
The output hash was identical and the validator passed, confirming the packaged
layout resolves the repository root correctly.

No model call was made; see `usage_report.md`.

## 9. Residual risks

- Anonymous analytics/audit records with no participant-visible identifier can
  reduce exact-match and step recall but do not change the status decision.
- Account-id inference is a one-to-one matching problem when several deletion
  events share a window; ties are broken deterministically, not semantically.
- Screenshot coverage is limited to the reviewed transcription cache. New
  screenshots would need a transcription entry; they are reported as extraction
  issues rather than guessed.
- The customer-statement PDF `evidence_18` carries
  `NST-2026-0718-1842`, which `activity_4009` links to `export_1842`. The PDF
  parser extracts the subject's identity but not a standalone resource id, so
  `export_1842` is not emitted as a separate record. The affected case
  (`case_33`) is already INCOMPLETE from `export_1260`; this is a step-recall
  gap, not a status gap.
- An empty collection snapshot (`scope_only`) is treated as neutral rather than
  as proof that every record of that category is absent. The public
  `case_24` expects a record-level present observation to win over an empty
  account collection captured at the cutoff, so the engine deliberately does
  not over-apply empty snapshots.
- Many `COMPLETE` account-absence verifications cite a full SQL snapshot in
  which the account is absent rather than a per-record observation. This is a
  legitimate absence proof only if the snapshot is complete for that table;
  the public sample uses the same convention.
- One full-dataset `COMPLETE` case (`case_46`) names a retained security-audit
  record from a later read-back. Its cited pre-cutoff file demonstrates that
  security-audit records are retained but does not contain that exact record id.
  The step is retained for policy completeness; the citation-specificity risk
  is documented rather than hidden.
