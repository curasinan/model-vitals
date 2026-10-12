# ADR-002: the feature-level corpus, its identity scheme, and the gates around it

**Status:** Accepted — CI phase 2 shipped 2026-09-01 (branch `ci-phase-2`, PR #1)
**Date:** 2026-09-01
**Decider:** operator (sole maintainer)
**Scope:** `model-vitals` only.
**Supersedes:** ADR-001's corpus decision (Option A, "fitted synthetic") and its
Phase B action items 4–6. Everything else in ADR-001 stands.

## Context

ADR-001 resolved a contradiction — Gate 2 wants ≥30 days of real sessions, the
security gate forbids real transcript paths in the repo — by keeping the real
data off the repo entirely: fit distribution parameters locally, commit the
numbers, generate a synthetic corpus in CI from a seed. That decision was
correct for what it knew, and it has one honest limitation which ADR-001 stated
itself: *"it measures whether a change regressed the detector against a fixed
statistical world. It does not measure whether the thresholds are still right
for real usage."*

Phase 2 changes the input to that decision. The thing Gate 2 needs to learn a
detector against is the **joint** structure of real usage — the correlation
between a rising `edit_retry_max` and a `context_bucket`, the co-movement of
`output_tokens` and `latency_ms` across a `cc_version` change point. A corpus
generated from marginal distributions has no such structure except the structure
someone remembered to fit. Sampling per-model latency quantiles and per-hour
session cadence independently produces a world in which nothing is correlated
with anything, and a detector that scores well there has been measured against
its own author's assumptions.

The second input is that the data can now be reduced without being redacted.
Redaction is a filter over text and its residue is text. A *feature-level*
extract is not a filter — it is a change of type. There is no column in which a
path could survive, because no column holds a string that is not a member of a
closed vocabulary, a hex digest, or a dotted version number.

## Decision

**Commit a feature-level extract of this machine's real event store**, produced
by a local-only extractor, guarded by a blocking privacy boundary test, behind a
blocking secret-scanning gate.

Five Parquet tables and a manifest under `corpus/`:

| file | one row is | rows | bytes |
|---|---|---|---|
| `requests.parquet` | one API attempt (success or failure) | 29,533 | 289,031 |
| `tool_results.parquet` | one main-session tool call | 5,716 | 43,058 |
| `turn_features.parquet` | one prompt, rolled up | 1,384 | 17,547 |
| `canary_cycles.parquet` | one (cycle, task) pair | 163 | 5,977 |
| `change_points.parquet` | one thing changing underneath | 26 | 2,676 |
| `manifest.json` | provenance | — | 2,915 |

Total **361,204 bytes (0.34 MiB)** — 0.69 % of the 50 MB cap, so the session
sampler never engaged (383 of 383 sessions, `sampling_rate` 1.0). Span
**2026-04-21T04:00Z .. 2026-09-01T03:00Z = 132.96 days**, comfortably over
Gate 2's 30. Extracted 2026-09-01T03:28:55Z, key id
`vitals-corpus-hmac-v1:80ce10d3`.

### What makes this safe, stated as a type rule rather than a promise

`corpus/schema.py` declares every column as one of seven `ColumnKind`s — int,
float, bool, enum, hash, timestamp, version. **There is deliberately no `TEXT`
kind**, and adding one is the single change that would let a path into a
committed file. Free text *is read* during extraction — an error body, a file
path, a transcript's self-correction markers — and each is reduced to a class, a
count or a hash before it reaches a column. `_validate` re-checks every cell
against its declared kind immediately before writing, and an out-of-vocabulary
value aborts the extraction rather than being written as free text.

The extractor is structurally local-only: a script under `scripts/`, not a
`vitals` subcommand; no file under `.github/` names it; and it refuses to start
without `VITALS_CORPUS_HMAC_KEY`, which CI does not have.

### The HMAC identity scheme

`session_hash`, `file_hash`, `plugins_hash`, `from_hash`/`to_hash` are
HMAC-SHA256 over `domain \x00 value`, keyed by a value read from
**`VITALS_CORPUS_HMAC_KEY`** and never committed, echoed, or written to the
manifest. Three properties are load-bearing:

- **Domain separation.** A session id and a file path that happen to be the same
  string must not collide into one identity.
- **A 32-byte floor** (`MIN_KEY_BYTES = 32`), and *random*, not a passphrase.
  This is not about SHA-256's strength. `file_hash` HMACs **file paths**, which
  are low-entropy and guessable, so a key recovered by a dictionary attack does
  not merely identify the corpus — it reverses every path identity in it.
- **A keyed key-id derivation.** The manifest publishes
  `HMAC(key, "vitals-corpus-hmac-v1")[:8]`, **not** `sha256(key)[:8]`. A plain
  digest of a secret sitting in a committed file is a confirmation oracle: one
  hash per wordlist guess, offline, with no other input. Keying the derivation
  leaves the guess cost unchanged but removes the oracle. (The first
  implementation used the unsalted form; a review caught it, and both
  properties are now pinned by tests.)

Losing the key means the next corpus cannot be joined to this one. That is the
intended property: a hash is an identity, not a lookup.

### Canary detection latency: 24 hours, accepted

`DetectCfg.K_cycles = 3` at `CanaryCfg.schedule_hours = 8` means the canary
layer needs **24 hours** of sustained degradation before C1 fires. This is
accepted, not merely tolerated: `K_cycles` is what stops a single decimated
cycle from opening an anomaly, and the 2026-08-28 record has cycles failing
20/20 on infrastructure grounds alone.

**The consequence for class C is the part that must be written down.** Class C
is "provider incident". On sub-day timescales, class-C attribution is the
responsibility of the **passive** signals — the OTel/hook-derived error rates,
latency and retry statistics that update continuously — and **not** of the
canaries. A canary-based gate cannot, by construction, tell you about a
four-hour provider incident. Anyone tuning C-class detection against
`canary_cycles` is measuring the wrong layer.

### The mypy ratchet

`scripts/mypy_ratchet.py` + `mypy_baseline.json` (`win32` **238**, `linux`
**243**, both confirmed by CI run 33450048015). The gate fails when the count
**rises**, and also when it **falls** without the baseline being updated in the
same commit — slack in the baseline is where the next regression hides. The two
numbers genuinely differ: roughly five errors live in platform-conditional code
that only one leg of the matrix ever type-checks. Blocking on zero would leave
the pipeline red from its first run, and a permanently red pipeline is
indistinguishable from a broken one. `corpus/` was added to `[tool.mypy] files`
and contributes **zero** errors; `scripts/` is not covered, so
`scripts/extract_corpus.py` is not type-checked — recorded here as a known gap,
not a claim.

### The dead-man's switch

Recorded here because it is the compensating control for everything above. This
monitor's characteristic failure is not a wrong number, it is a quiet one: the
2026-08-29 review found the canary subsystem dead for three cycles while
`vitals status` still read healthy, and every stage of the collection path is
fail-open by contract, so a break raises nothing anywhere. `vitals.watch.deadman`
takes its evidence from outside the pipeline — transcript file mtimes, which
Claude Code writes whether or not our hook runs — and reports only the
*conjunction*: transcripts modified recently AND nothing ingested for longer
than `no_data_window_minutes` (30). Either half alone is unremarkable, and an
idle machine trips neither, which matters because an alert that fires every
evening is an alert the operator learns to close unread. It drafts at WARN with
attribution class **E** (inconclusive), which is the honest class: it knows data
stopped arriving, not why. A corpus and a canary suite both measure things that
happened; the dead-man's switch is the only gate that measures the absence of
things happening, and no amount of corpus fidelity substitutes for it.

## Options considered

| Option | Privacy risk | Joint structure | Reproducible in CI |
|---|---|---|---|
| **Feature-level committed extract (chosen)** | Low, and type-enforced | Real | Yes — the bytes are in git |
| ADR-001's fitted synthetic corpus | None | Only what was fitted | Yes, by seed |
| Raw redacted corpus | **High — one-way** | Real | Yes |
| Self-hosted runner on the dev machine | Low | Real | No |

**Raw redacted corpus — rejected.** Redaction is a filter over text whose output
is still text, so its failure mode is a residue: one un-anticipated shape, one
path spelled a way the regexes did not expect, and it is in git history, which
cannot be un-published. Every mitigation makes the filter more elaborate without
ever making it total, and the review burden grows with the corpus instead of
staying fixed. The feature-level extract is not a stricter filter, it is a
different type: the question "did the redactor miss something" cannot be asked of
a column that holds an int64, and the residual risk collapses from "did we think
of every text shape" to "is every column's declared kind enforced" — which one
test answers, on every push, over the actual committed bytes.

**Self-hosted runner — rejected.** It is the only option that needs no corpus at
all: run the gates on the machine that has the data. It was rejected for the
same two reasons ADR-001 gave and one new one. It makes a personal machine into
CI infrastructure, so a laptop being asleep becomes a red build; it produces
results nobody else can reproduce, which is fatal for a gate whose whole purpose
is to say "this change regressed the detector" in a way a reader can check; and
— the new reason — a self-hosted runner executing untrusted PR workflow code on
the machine that holds the live event store inverts the entire threat model this
ADR exists to serve. The security gate would be protecting the repo from the
data while the runner handed the data to the repo's CI.

## Rulings recorded (these were decided during phase 2, not assumed)

### 1. Supersession of ADR-001's corpus decision, and the changed privacy posture

ADR-001 chose "fitted synthetic" **because** committing real data was judged
high-risk and one-way, and it committed only `corpus_params.json` — numbers with
no identities at all. This ADR commits a real extract. That is a genuine change
of posture and is stated as one rather than presented as a refinement: the repo
now contains 29,533 rows describing when this account made API calls, how long
they took, and which of them failed. What it does not contain is any text, path,
prompt, completion, or reversible identifier. ADR-001's Phase B items 4–6
(`fit_corpus_params.py`, `test_corpus_params.py`, `make_corpus.py`) are
**withdrawn, not deferred** — `corpus/schema.py`, `scripts/extract_corpus.py`
and `tests/corpus/test_privacy_boundary.py` replace them.

### 2. MCP tool names are normalized to `mcp__<suffix>`

MCP tool names as emitted carry the server's UUID
(`mcp__<server-uuid>__list_projects`). The server id is an installation detail of
this machine, it has no meaning to a detector, and its cardinality grows with
every connector the operator adds. `normalize_tool_name` drops the server
segment before the value meets the `tool` enum. Degenerate shapes are returned
untouched, which is why the literal name `mcp_tool` — the name OTel itself uses
for a generic MCP call, with no `mcp__` prefix — passes through and is judged as
its own vocabulary member rather than being silently rewritten.

### 3. Real vocabularies override the spec's example enums

The spec's example lists were illustrative; the live store is authoritative, and
where they disagree the live store wins with the divergence noted at the
constant. Confirmed at extraction time:

- **`context_bucket`** is `lt30k` / `b30_100k` / `b100_180k` / `gt180k` — the
  numeric-leading forms `30_100k` / `100_180k` do not occur.
- **`change_point_kind`** is `plugins`, `settings`, `canary_suite`,
  `vitals_config`, `cc_version` (observed counts 1 / 19 / 2 / 1 / 3). The spec's
  `plugin_set` and `model_default` do not exist.
- **`retries` is derived from `api_errors.attempt`** — there is no
  `requests.retries` column. `vitals.ingest.normalize` overloads `attempt`:
  normally the zero-based attempt index, but *total attempts* when
  `retries_exhausted` is set, one more than the retries taken. `derive_retries`
  handles both. Consequence worth stating: a successful request always carries
  `retries = 0`, because the store cannot associate a success with the failures
  that preceded it.
- **`model`** keeps `claude-opus-5[1m]` distinct from `claude-opus-5` (it behaves
  differently at long context), and keeps one junk value,
  `definitely-not-a-real-model-xyz`, which is a real 2026-08-28 otel `api_error`:
  a 404 for a model that does not exist. Dropping the row would hide a real
  failed request; coercing the model would file a measurement under a model that
  was never called.
- **`error_class`** needed a sixth member, `unknown`, for otel errors carrying
  no status code and no timeout/overload/rate marker. Calling those `none` would
  record a failed request as a successful one.

### 4. Transcript features are read from store-distilled columns, not from `.jsonl`

The spec names transcripts as an input for the text-derived features. They are —
but `vitals.ingest.transcripts` has already distilled them into store columns
(`transcript_turns.self_corr_hits`, `tool_results.test_runner`,
`tool_results.bash_exit_code`). The extractor reads **those** and never opens a
transcript file. This is a deviation from the letter of the spec and it is
accepted deliberately: it yields the same features with a strictly smaller leak
surface — no line of conversation is ever in the extractor's address space, so
no exception message, traceback or partial write can carry one.

### 5. Sidechain tool calls are excluded

`tool_results` reads `WHERE prompt_id IS NOT NULL AND is_sidechain = 0`, matching
the population `v_edit_loops` already uses. The cost is large and is stated
plainly rather than buried: **19,237 rows → 5,716 (−70 %)**, observed `tool`
cardinality 41 → 35, `test_runner` 5 → 3, `file_hash` non-null 5,571 → 1,289.
`StructuredOutput`, `ReportFindings`, `mcp__javascript_tool`, `mcp__preview_list`,
`mcp__spawn_task`, `mcp__tabs_select`, `eslint` and `flake8` now appear nowhere
in the corpus — on this machine they only ever ran inside subagents. The
justification is population consistency: Gate 2 compares against `v_edit_loops`,
subagent dynamics are not the main-session degradation signal this project
detects, and mixing the two silently is worse than excluding one loudly. The
declared enums are unchanged (they are the store's full vocabulary), so a future
main-thread use of any of those tools will not fail extraction. If Gate 2 later
needs the coverage back, the correct move is an explicit `is_sidechain` boolean
column, not a silent reunion of the two populations; the manifest carries
`excluded.tool_results_sidechain = 13,595` either way.

### 6. Two content-rule exceptions, ratified

The privacy boundary's content assertion is the spec's verbatim "under 64
characters and `^[A-Za-z0-9_.\-]+$`". Two narrow exceptions were found by running
it against the real corpus, and both are ratified:

- **`claude-opus-5[1m]`.** The charset rejects exactly one value in the whole
  corpus, and it is a deliberately-distinct declared enum member. Rather than
  widening the charset globally, a second pattern (`[` and `]` added) applies
  **only** to a value that is already a declared member of the vocabulary its own
  column names. Brackets in a column that names no vocabulary remain a violation,
  and a test asserts that **exactly one** member across all seven vocabularies
  needs the exception and names it — a second one turns the suite red, so it
  becomes a decision someone makes on purpose. The rejected alternative was
  renaming the enum member, which would make the corpus record a model identifier
  the telemetry never emitted.
- **Hash columns are pinned to exactly 64, not bounded under 64.** An
  HMAC-SHA256 hex digest is 64 characters, one over the spec's bound. Loosening
  the bound to `<= 64` would admit every other 64-character string too; instead
  hash columns are pinned by `HASH_RE = ^[0-9a-f]{64}$` in the schema assertion
  and the length bound is not applied to them. A fixed width admits strictly less
  than a bound does. Enum and version columns keep the verbatim `< 64` rule.

### 7. Gate 5 (cost cap) is covered

The canary daily budget/cost-cap guard is regression-covered by
`tests/test_cost_cap_regression.py` — six tests in the fast suite, no `slow`
marker, no real subprocess — proving the hard stop fires on both the dollar and
the token cap with nothing launching after it, that spend survives a daemon
restart within the budget day, that the actual reported cost beats a
token-derived estimate, that a missing cost settles at the configurable
pessimistic rate rather than $0, and that the cap check strictly precedes the
subprocess it gates. Each assertion was proven RED by temporarily inverting the
real guard before being confirmed GREEN against unmodified code. Adjacent
observation, deliberately not fixed here: the dollar-cap SQL sums all
`spend_ledger` rows for the day regardless of `source`, so a `probe` row would
count against the canary's own cap, a known `spend_ledger` design issue
(reservations and settlements share one table), not a new finding.

## Consequences

**Easier.** Gate 2 can be trained and evaluated against the real joint structure
of this account's usage rather than against a set of marginals someone chose to
fit, and the corpus is in git, so a metric computed today is recomputable from
the same bytes in a year. The privacy boundary is mechanical rather than
remembered: `tests/corpus/test_privacy_boundary.py` runs in the fast suite on
every push, reads the committed Parquet from disk knowing nothing about how it
was produced, and fails on a partial corpus rather than skipping — the extractor
could be wrong, bypassed or replaced and the gate still holds. Type enforcement
at both ends (write-time in `schema.py`, read-time in `boundary.py`) means "no
text can be in the corpus" is a checked claim rather than an assurance.
**Harder.** The corpus is now a committed artifact with a refresh cost:
re-extraction needs the same HMAC key or every identity changes, so a refreshed
corpus is a new corpus and any longitudinal comparison across it is invalid. The
key for the committed extract was generated per-run and is gone, which is the
intended security property and also means the next extraction starts a new
identity space. The repo now carries real behavioural data, so the security gate
is not optional infrastructure — it is the thing standing between an extractor
bug and an unpublishable repository. And the boundary test can only inspect what
the ~10 custom `.gitleaks.toml` rules can express: gitleaks reads bytes, a
zstd-compressed columnar file does not contain its values as searchable text, so
for the corpus the boundary test is the **only** value inspector and gitleaks'
~160 built-in rules do not reach it. A string shaped like an AWS key in a column
is caught by the schema and content assertions, not by the pattern assertion.

## Honest caveats — read these before building a gate on this corpus

1. **The canary tables are thin.** `canary_cycles` holds **163 rows** — 15
   distinct cycles × 12 tasks, spanning 2026-08-25T17:00Z .. 2026-09-01T02:00Z,
   about 6.4 days. Three of those fifteen cycles — 6, 7 and 8 — are entirely
   invalid: 0 passes across 20, 22 and 14 attempted runs respectively, so they
   carry no effectiveness signal at all. A canary-based gate calibrated on this is
   calibrated on a fortnight of a single week's behaviour, and no arithmetic on
   the corpus changes that. The 132.96-day headline belongs to `requests`, not to
   the canary layer.
2. **The tool-level tables reach back ~7 days, not 133.** `requests` and
   `turn_features` inherit `api_requests`/`transcript_turns`' full span from
   2026-04-21, but `tool_results` starts 2026-08-25T01:00Z, `canary_cycles`
   2026-08-25T17:00Z and `change_points` 2026-08-25T17:00Z — that is when the
   hooks and the canary were installed. The manifest carries `per_source_table`
   spans precisely because they differ by months. Do not read the headline span
   as applying to every table.
3. **`canary_cycles.cc_version` is NULL in all 163 rows, and `model` has
   cardinality 1** (`claude-sonnet-5` throughout). **Gate 2 must not stratify on
   either.** A stratification on `cc_version` yields one empty stratum; a
   stratification on `model` yields one stratum containing everything, which will
   look like a working stratification while being a constant. Class-C detection
   ("all models drop together, `cc_version` unchanged, no change point") cannot be
   evaluated on this corpus at all: there is only one canary model and no canary
   `cc_version` to hold constant.
4. **The corpus mixes canary-generated traffic with human sessions**, and there
   is no `is_canary` column. The extractor's own run notes record 289 of 764
   live-store sessions as canary runs at extraction time; the corpus itself
   cannot be asked, which is the point. If Gate 2 wants to stratify on that, it
   is a deliberate schema change, not something to reverse-engineer from
   `canary_cycles`. (Relatedly, `manifest.sessions.in_store` currently reports
   383 — the number *in the corpus*, not the number in the store. A known
   mislabel, deferred, recorded here so nobody reads it as a sampling claim.)
5. **`test_exit_code` is sparse** (17 non-null of 5,716): the store records an
   exit code only when a hook parsed one out of a failure. A successful run's
   implicit 0 is not invented.
6. **`requests` is a union of two disjoint event streams** — successes from
   `api_requests`, failures from otel `api_errors`, which join to 0 of 219 rows
   because a failed attempt never emits an api_request event. Error rows carry
   NULL, not zero, for `input_tokens`, `output_tokens`, `cache_read_tokens` and
   `context_bucket` (90 NULL `context_bucket` rows), because an error event
   measures none of those. Disjointness is re-measured on every extraction and
   published as `excluded.requests_error_rows_deduped` (currently 0) rather than
   being assumed.

## Action items

1. [x] gitleaks + custom path rules, blocking, in CI and as a pre-commit hook.
2. [x] Trivy fs on the lockfile (dev deps included) + Syft SPDX SBOM artifact.
3. [x] Gate 5 cost-cap regression suite.
4. [x] `corpus/schema.py`, `scripts/extract_corpus.py`, `docs/corpus.md`.
5. [x] `tests/corpus/test_privacy_boundary.py` — five assertions, blocking.
6. [x] `corpus/inject.py` — class A–D interface stubs; D raises.
7. [x] The corpus data commit itself.
8. [x] Gate 1 populates the A–C injection stubs.
9. [ ] Gate 2 consumes the corpus, subject to the caveats above.
10. [ ] Re-extract periodically. A stale corpus silently measures an account that
        no longer behaves this way — the same drift ADR-001 named for its params
        file, unchanged by the switch to an extract.

## Verification

Every claim in this ADR is traceable to a run, a command or a file. The
load-bearing ones:

- The security gate is blocking and green on real infrastructure: PR #1, run
  **33461807041** — `security (gitleaks)`, `security (trivy fs)`,
  `security (syft sbom)` all success, with `detector-eval` (**33461807018**)
  making four.
- The privacy boundary's RED proof is committed, not narrated: a corpus built in
  a temp directory with one added text column must fail on schema, content and
  pattern simultaneously, alongside a control asserting the same builder without
  that column is clean.
- The corpus's own numbers in this document were read from
  `corpus/manifest.json` and the Parquet files themselves, not carried over from
  earlier notes.
