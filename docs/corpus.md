# The Phase B feature-level corpus

A corpus of Claude Code behaviour derived from this machine's own event store: what was
asked, how long it took, what failed, how often an edit had to be repeated. It exists so
Gate 2 has something to learn a detector against that is not a simulation.

It contains **numeric, boolean and enum columns only**. No free text, no file paths, no
prompts, no completions, ever. Not in a column, not in a comment, not in an error message.

| file | what one row is |
|---|---|
| `corpus/requests.parquet` | one API attempt — a success from `api_requests`, or a failure from `api_errors` |
| `corpus/tool_results.parquet` | one tool call |
| `corpus/turn_features.parquet` | one prompt, rolled up |
| `corpus/canary_cycles.parquet` | one (canary cycle, task) pair |
| `corpus/change_points.parquet` | one thing changing underneath the measurements |
| `corpus/manifest.json` | provenance: dates, counts, span, enum cardinalities, key id, sampling |

## Running the extractor

**Locally only. Never in CI.** `scripts/extract_corpus.py` is the one file in this repository
that opens the real event store. It is a script rather than a `vitals` subcommand, no
workflow under `.github/` references it, and CI has neither the data nor the key. The fast
suite tests it against a synthetic store built from the same migrations.

```powershell
# A fresh random key, exported for this shell only. Never commit it, never echo it, never
# paste it into a report. The key is generated inline, so the SHELL HISTORY records how it
# was made and not what it is; typing a literal key here would leave it in the history file.
$b = New-Object byte[] 32
(New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b)
$env:VITALS_CORPUS_HMAC_KEY = ($b | ForEach-Object { $_.ToString('x2') }) -join ''
Remove-Variable b

uv run python scripts/extract_corpus.py
```

(`RNGCryptoServiceProvider` rather than `RandomNumberGenerator.GetBytes`, and a hex join
rather than `[Convert]::ToHexString`: this project's shell is Windows PowerShell 5.1, whose
.NET Framework has neither of the newer forms.)

| variable | meaning |
|---|---|
| `VITALS_CORPUS_HMAC_KEY` | **required.** The HMAC-SHA256 key behind every identity column. At least **32 bytes**, and *random* — not a passphrase. Never committed. |
| `VITALS_DATA_DIR` | optional, already used by `vitals.config`; the store path is resolved from config, never guessed. |

The 32-byte floor is not about the strength of SHA-256. `file_hash` HMACs **file paths**,
which are low-entropy and guessable, so a key recovered by a dictionary attack turns every
`file_hash` in a committed corpus back into a path. For the same reason `manifest.json`
publishes an id derived as `HMAC(key, label)` and **not** `sha256(key)`: a generic digest of
a secret, sitting in a committed file, is a confirmation oracle — one hash per wordlist
guess, offline, with no other input needed.

The store is opened `file:...?mode=ro` with `PRAGMA query_only` on top. The daemon and nine
hooks write to it concurrently in WAL mode while the extractor reads.

Losing the key means the next corpus cannot be joined to this one — the identities will all
be different. That is the intended property: a hash is an identity, not a lookup.

## What is a column, and what is not

Every column is one of seven kinds, declared in `corpus/schema.py`. There is deliberately no
`TEXT` kind; adding one is the single change that would let a path into a committed file.

* **int / float / bool** — counts, durations, token totals, flags.
* **enum** — a member of a closed vocabulary in `corpus/schema.py`. A value outside it aborts
  the extraction.
* **hash** — HMAC-SHA256 hex, 64 characters, domain-separated so a session id and a file path
  that happen to be the same string do not collide.
* **timestamp** — hour-resolution UTC. Physically an int64.
* **version** — a dotted numeric `cc_version` and nothing else; the pattern is what stops the
  `claude --version` banner (which carries a product name) getting in.

Free text IS read: an error body, a file path, a transcript's self-correction markers. Each is
reduced to a class, a count, or a hash before it reaches a column. The reduction happens in
one place, and `_validate` in the extractor re-checks every cell against its declared kind
immediately before writing.

### The transcripts

The spec names transcripts as an input for the text-derived features. They reach the corpus
through `vitals.ingest.transcripts`, which has already distilled them into store columns —
`transcript_turns.self_corr_hits`, `tool_results.test_runner`, `tool_results.bash_exit_code`.
The extractor reads those columns and never opens a `.jsonl`, so no line of conversation is
ever in its memory. Same features, smaller leak surface.

## Enums are added deliberately

An unknown tool name or model string **fails the extraction**. It is not written as free
text, and it is not dropped. Violations accumulate across the whole read and are raised once,
before the first byte is written, so a failed run leaves no partial corpus behind.

The abort message names the enum class, the columns, the row count and the distinct-value
count — and an **HMAC digest** of each offending value, never the value. An unrecognised tool
name is an unknown quantity by definition: it could be a path, a project name, or a username,
and an abort message is exactly what gets pasted into an issue.

To add a value, edit `corpus/schema.py` and say in the diff why it is real.

## Where the vocabularies came from

Read from the live store on 2026-09-01, not from the spec's illustrative examples. The
divergences that mattered:

* **`error_class` gained `unknown`.** The store holds otel `api_errors` rows with no
  `status_code` and no timeout marker. Calling those `none` would file a failed request as a
  successful one.
* **`requests` is a union.** The store's `api_errors` carry request ids matching **no**
  `api_requests` row — 0 of 219 — because a failed attempt never emits an api_request event.
  Without unioning the failures in, `error_class` would be the constant `none`.
  That disjointness is a property of today's telemetry, not an invariant, so it is **measured
  on every run** and recorded in the manifest as `excluded.requests_error_rows_deduped`. On
  overlap the `api_requests` row wins and the error row is dropped — the store's own rule
  (`migrations/001_core.sql`: "dedup: request_id wins"), since a shared request id means two
  views of one attempt, and counting it twice would inflate every per-attempt rate.
* **Sidechain tool calls are excluded**, matching `v_edit_loops` in
  `migrations/002_views.sql` and therefore the project's own edit-loop signal. Sidechain rows
  are a *subagent's* tool calls, recorded against the parent session and prompt; counting
  them would make `tool_calls` mean "this turn plus everything every subagent it spawned
  did" and let `edit_retry_max` report a loop the main thread never ran. On this machine that
  is 70% of the rows, so the count is in the manifest as `excluded.tool_results_sidechain`
  rather than passing in silence. A prompt whose only activity was a subagent's still gets
  its ordinal and a `turn_features` row — it happened — with counts of zero.
* **`retries` comes from `api_errors.attempt`.** There is no `requests.retries` column
  upstream. `vitals.ingest.normalize` overloads `attempt`: normally the zero-based attempt
  index, but total attempts when retries were exhausted, which is one more than the retries.
* **MCP tool names are normalized** from `mcp__<server>__<suffix>` to `mcp__<suffix>`. The
  server segment is a per-install UUID on this machine, so leaving it in would grow the
  vocabulary on every reinstall and put an install identity in a committed file.
* **`canary_cycles` is one row per (cycle, task).** `task_id` is a spec column and a cycle
  spans the whole suite, so cycle grain could not carry it.
* **`api_errors` with `source = 'transcript_synthetic'` are excluded**, and the count is in
  the manifest. `migrations/003_api_error_source.sql` is explicit that they are client-side
  messages — session limits, connection notices — not provider errors.
* **`test_exit_code` is null unless the store recorded one.** A hook parses an exit code out
  of a failure; a successful run's implicit zero is not invented here.

## Size and sampling

The cap is 50 MB. Over it, whole **sessions** are dropped — never columns — at a
deterministic rate keyed on the session hash, and `manifest.json` records the rate. Sampling
is monotone in the rate, so a later resample at a higher rate is a superset, not a different
population.

## The manifest

`manifest.json` carries the extraction date, the schema and extractor versions, row counts
per table, the time span covered (per corpus table and per source table — they differ by
months, and one must not be inferred from the other; every endpoint is hour-floored, like
every other instant in the corpus, because the manifest is a committed file too), every enum
with its declared and observed cardinality, the sampling rate, the `excluded` counts above,
and the **HMAC key id** — `HMAC(key, "vitals-corpus-hmac-v1")` truncated to 8 hex, which
identifies a corpus without publishing a digest anyone could build a lookup table for.
