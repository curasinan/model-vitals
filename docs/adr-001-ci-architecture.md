# ADR-001: CI architecture for model-vitals

**Status:** Accepted — Phase A shipped 2026-08-31
**Date:** 2026-08-30
**Decider:** operator (sole maintainer)
**Scope:** `model-vitals` only. `claude-token-tracker` deferred — see Consequences.

## Context

Neither repo had CI until today, and vitals had no git remote at all until this
afternoon, so CI was not previously possible. 651 tests exist and run only when
a human decides to run them.

The obvious CI — "run pytest" — is worth little here, because the interesting
failure is not a crashing test. It is a detector that stops detecting, or starts
crying wolf, while every unit test still passes. The 2026-08-29 system review
found the canary subsystem dead for three cycles while `vitals status` reported
healthy. That is the failure class CI has to cover.

**Most of the machinery already exists.** `src/vitals/validate/` contains
`inject.py` (synthetic degradation injection, four window-shift kinds plus a
canary model-swap drill) and `replay.py` (replays real history through
`tick → evaluate → classify → dispatch` and reports what fired), with `vitals
inject` / `vitals replay` CLI commands and 107 tests across
inject/replay/engine/attribution. `engine.tick(conn, cfg, now)` already takes
`now` as a parameter, so the clock seam that deterministic replay requires is
present.

This ADR is therefore mostly about **promoting existing local tooling into
enforced gates**, not about building detection evaluation from scratch.

### The contradiction that shaped the design

The original sketch contained two requirements that cannot both hold:

- Gate 2 replays "at least 30 days of real past sessions" in CI.
- The security gate blocks fixtures containing `~/.claude/projects/` paths.

Real history lives only on the operator's machine. Resolving this in favour of
privacy is what forces the synthetic-corpus decision below, and it is the single
choice from which the rest of the architecture follows.

### Two corrections to the sketch's premises

- **There are five attribution classes, not four.** `attribution.py` declares
  `cls: Literal["A","B","C","D","E"]`, where **E is "inconclusive" and is often
  the correct answer.** A confusion matrix over A–D alone scores every honest
  "I don't know" as a miss, which pressures the detector toward overconfidence —
  the precise failure that would make a report to Anthropic embarrassing.
- **`mypy --strict` is not a multi-day project here.** Measured 2026-08-30:
  240 errors in 23 of 42 files, of which ~141 are `type-arg` (`dict` →
  `dict[str, Any]`) and 32 are missing signatures. Roughly 28 are genuine
  correctness signals (`union-attr`, `arg-type`, `operator`). An earlier
  estimate in conversation of "four figures" was wrong by an order of magnitude.
  `ruff` reports 109, 46 auto-fixable.

## Decision

Two workflows on `model-vitals`, triggered on **push to `main`**, **reporting
metrics without blocking** until thresholds are set from observed data.

1. **`ci.yml`** — correctness and supply chain. Matrix: `ubuntu-latest` for the
   portable suite, `windows-latest` for the full suite including
   `tests/test_channels.py`.
2. **`detector-eval.yml`** — the statistical gates, on `ubuntu-latest` only,
   against a **deterministic synthetic corpus generated from distribution
   parameters fitted locally from real data**.

### The privacy boundary, stated precisely

`scripts/fit_corpus_params.py` runs **only on the operator's machine, never in
CI**. It reads the live database and emits `tests/corpus/corpus_params.json`
containing **numbers only** — latency quantiles per model, error rate, output
token distribution, session cadence, context-bucket mix. No prompt text, no
path, no session id, no cwd.

`scripts/make_corpus.py --params … --seed 42 --days 30` turns those numbers into
a corpus in CI. The corpus is generated, never committed.

This boundary is enforced by a test, not by discipline: `test_corpus_params.py`
asserts every leaf value in the params file is numeric, and a repo-wide check
asserts no tracked file contains `~/.claude/projects` or a session-id-shaped
string. Both run in the ordinary local suite as well as in CI, so the boundary
fails at commit time rather than at push time.

## Options considered

### Corpus: where the replay data lives

| Option | Complexity | Privacy risk | Statistical meaning | Reproducible |
|---|---|---|---|---|
| **A. Fitted synthetic (chosen)** | Med | None | Faithful to real distributions | Yes, by seed |
| B. Self-hosted runner on the dev machine | Med | Low | True calibration | No |
| C. Committed redacted corpus | Low | **High — one-way** | Faithful | Yes |
| D. Hand-authored distributions | Low | None | Measures invented numbers | Yes |
| E. Scale up the 15-record fixture | Trivial | None | Near-meaningless | Yes |

**Chosen: A.** It is the only option that is simultaneously reproducible by CI,
free of real content, and statistically connected to how this account actually
uses Claude. C was rejected because redaction is irreversible and a repo cannot
be fully un-published; B was rejected because it makes a personal machine into
CI infrastructure and produces results nobody else can reproduce.

**The honest limitation of A:** it measures whether a change *regressed* the
detector against a fixed statistical world. It does not measure whether the
thresholds are still right for real usage — real distributions drift, and the
committed params freeze a moment. Mitigation: `vitals replay` against real
history stays a local command, re-run periodically, and `fit_corpus_params.py`
is re-run when it drifts. CI answers "did this change break it"; the local
command answers "is it still calibrated".

### Trigger: what CI gates

| Option | Blocks bad merges | Fits current workflow | Ceremony |
|---|---|---|---|
| **Push to `main`, report-only (chosen)** | No | Yes | None |
| Pull requests with required checks | Yes | No — every commit today went to `main` | High for a solo repo |
| Hybrid: push CI, PRs for risky areas | Partly | Partly | Medium |

**Chosen: push to `main`.** A required check that never runs because there is no
PR is worse than no check. Revisit once the thresholds are real; at that point
the hybrid becomes attractive for `detect/`, `attribution/` and `budget.py`.

### Strictness: hard thresholds vs measurement

**Chosen: measure first.** The sketch's numbers — precision ≥ 0.80, ≤ 1 false
positive per week — are reasonable guesses with no measurement behind them. A
gate set below the true baseline is red forever and teaches you to ignore CI,
which costs more than having none. The workflows compute and publish every
metric from day one; the thresholds land in a follow-up commit once there is a
distribution to set them from.

One nuance the sketch missed: **"≤ 1 FP per week" is not measurable on a fixed
corpus.** A deterministic 30-day corpus yields a fixed FP *count*, not a rate.
It will be expressed as a count over a named corpus (`≤ N over corpus-v1,
seed 42`), which is the honest and reproducible form.

### Class E in the confusion matrix

**Chosen: E is a real class with its own row.** Injection scenarios must include
genuinely ambiguous cases whose correct answer is E. Scoring E as a miss would
reward a detector that always guesses a concrete class.

Starting proposal for an ambiguous injection, to be validated against the real
rule table: a provider-shaped shift where only one stratum has a live baseline,
so the cross-stratum evidence attribution needs is structurally unavailable.
`insert_fake_version_change_point` already demonstrates the inverse — it moves a
verdict from C to B by planting a change point — so the rule table is known to
be sensitive to exactly this kind of manipulation.

### Runner OS

**Chosen: matrix.** `ubuntu-latest` carries the detector, replay and injection
gates — pure arithmetic, 1× billing. `windows-latest` runs the full suite
including `tests/test_channels.py`, which matters because **desktop toast is the
only enabled alert channel**, so on Linux alone the live alerting path would
have no CI coverage at all. Platform coupling is otherwise narrow: exactly one
test file in this repo is Windows-bound.

## Trade-off analysis

The central trade is **fidelity against reproducibility**, and it is resolved
differently for the two questions that look similar:

- *Does this change break the detector?* Needs reproducibility above all —
  answered by the synthetic corpus, in CI, on every push.
- *Is the detector still calibrated for my usage?* Needs fidelity above all —
  answered by `vitals replay` against real history, locally, periodically.

Collapsing these into one gate is what created the sketch's contradiction.
Separating them dissolves it.

Second trade: **rigour against signal**. Report-only CI catches less on day one
but stays readable. A blocking gate on unmeasured thresholds catches more in
theory and nothing in practice, because a permanently red pipeline is
indistinguishable from a broken one.

## Consequences

**Easier**
- A detector regression becomes visible on the push that causes it.
- The 240 mypy findings, ~28 of which are genuine type errors in statistics
  code, get a place to be tracked down rather than discovered by accident.
- The privacy boundary becomes mechanical rather than remembered.

**Harder**
- The corpus params need periodic re-fitting; a stale corpus silently measures a
  world that no longer resembles the account's usage.
- Designing genuinely-ambiguous E-class injections is harder than designing
  clear ones, and doing it badly makes the E row meaningless.
- CI minutes: roughly 4 min ubuntu + 6 min windows at 2× ≈ **16 billed minutes
  per push**. Docs-only commits must be excluded via `paths-ignore`, or a day
  like 2026-08-30 (six pushes, two of them documentation) burns ~96 minutes for
  nothing.

**To revisit**
- Thresholds, once 2–4 weeks of metric history exist.
- Whether `claude-token-tracker` gets its own (much simpler) `pytest` gate. It
  was scoped out because a dashboard failure is visible the moment you open it,
  whereas a detector failure is silent — but its 543 tests are equally unguarded.
- Trivy and Syft: low value against two direct dependencies. Kept because they
  are cheap, but `uv lock --upgrade` on a schedule likely matters more.

## Action items

**Phase A — scaffolding, no gates yet — DONE 2026-08-31**
1. [x] `pyproject.toml`: `[tool.ruff]` and `[tool.mypy]`, both excluding
       `canary/tasks/` (fixture data; `diff-golden` has duplicate module names
       by design, which aborts mypy entirely).
2. [x] ruff: 56 auto-fixed, the rest triaged. **Green and BLOCKING**, via a
       documented ratchet with per-rule counts rather than a report-only lint.
3. [x] `.github/workflows/ci.yml` — matrix, `uv sync --frozen`, pytest and
       ruff blocking, mypy report-only, `paths-ignore` on docs.

### What Phase A actually found

Three commits, because the first two CI runs failed — which is the pipeline
working, not the pipeline broken.

**A latent SQL injection, found by keeping bandit's rules on.**
`db.py:upsert_session(conn, session_id, **fields)` interpolated every
caller-supplied key straight into SQL as a column name with no allowlist. Not
exploitable as written — all seven call sites pass literal keywords — but
`ingest/spool.py` handles `rec` dicts built from hook input a few lines from a
call to it, so it was one `**rec` away. Now validated against `PRAGMA
table_info(sessions)`, raising on an unknown column rather than skipping it,
since a mistyped keyword that silently wrote nothing would be data loss
disguised as success. The other seven S608 sites were each read and annotated
per-site, so a genuinely unsafe new one still fails the build.

**A false negative in the detector's own drill — the most valuable find.**
`_canary_baseline` selected prior cycles with `c.started_at < before`, and
`utcnow_iso()` has second resolution, so cycles beginning in the same second
were excluded from each other's baseline. At the production cadence of eight
hours that cannot happen. It appears the moment cycles run back to back, which
is exactly what `model_swap_drill` does — and with the drill running exactly
`K_cycles` = 3 degraded cycles, losing one to a missing baseline makes firing
arithmetically impossible. The drill then reports that the detector ignored a
clean 1.0 → 0.6 drop.

Proven by holding everything else constant:

    same nine cycles, distinct timestamps -> 1 anomaly opened
    same nine cycles, same-second ties    -> 0 anomalies opened

Ordering now uses `cycle_id`. **This is the case for CI in one paragraph:** the
drill tests passed on this machine for weeks because each cycle takes ~19s
here, and failed on a runner that finishes the suite in 36s. A test that only
passes because the developer's machine is slow is not a passing test, and no
amount of local running would have said so.

Three earlier hypotheses were wrong and are recorded because each was
plausible: decimated cycles (invalid-run count was zero), the zero-dispersion
guard (the `0.05*|mu0|` relative floor keeps sigma0 at 0.05 for a constant
series, not None), and hour-bucketing (C1 is per-cycle). A diagnostic
assertion, added deliberately in its own commit, is what settled it.

**One Windows-only test that asserted nothing on Linux.**
`test_shutil_which_resolves_claude...` resolves through a `claude.cmd` shim, a
batch file that POSIX `shutil.which('claude')` cannot match. Now marked, and
the windows leg still runs it.

**The matrix is already earning its 2× minutes** beyond `test_channels`: mypy
reports 245 errors on ubuntu against 240 on windows, so five platform-
conditional type errors exist that a single-OS run would never show.

**Phase B — the corpus and its boundary**
4. [ ] `scripts/fit_corpus_params.py` (local only) → `tests/corpus/corpus_params.json`.
5. [ ] `tests/test_corpus_params.py` — every leaf numeric; no tracked file
       contains `~/.claude/projects` or a session-id-shaped string.
6. [ ] `scripts/make_corpus.py --params --seed --days`; test that one seed
       yields a byte-identical corpus twice.

**Phase C — the statistical gates**
7. [ ] `scripts/detector_eval.py`: injection recall per class, replay FP count,
       A–E confusion matrix → `metrics.json`. **First half shipped:** Gate 1 —
       injection recall per class plus the clean-corpus FP count — is
       published in `metrics.json`, and the structural gate binds to a
       deterministic synthetic world, not the committed one (see the Gate 1
       plan's two-world ruling, `corpus/evaluate.py`). The A–E confusion
       matrix is Gate 3, still open.
8. [ ] Design and add E-class ambiguous injections.
9. [x] `.github/workflows/detector-eval.yml`; publish to
       `$GITHUB_STEP_SUMMARY` and upload `metrics.json` as an artifact.
       (Not a PR comment — there are no PRs.)

**Phase D — security**
10. [ ] gitleaks; Trivy fs; Syft SBOM as artifact.

**Phase E — close the loop (2–4 weeks later)**
11. [ ] Set thresholds from observed metric history; flip those gates to
        blocking.
12. [ ] Drive mypy to zero, triaging the ~28 real type errors first.

## Verification

Each phase is verified before the next begins:

- **A**: a deliberately broken commit (delete an assertion in `test_engine.py`)
  must turn the run red; a docs-only commit must not trigger a run at all.
- **B**: `make_corpus.py` twice with one seed produces identical bytes; the
  params test fails when a string is planted in `corpus_params.json`.
- **C**: each injection class fires with the expected attribution; a deliberately
  desensitised `DetectCfg` (`h=50`) must drop recall and show it in the metrics.
- **D**: a planted fake token in a scratch commit is caught by gitleaks and the
  commit is not pushed.
- **E**: thresholds are set from the observed distribution, not chosen first.
