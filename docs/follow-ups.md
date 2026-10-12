# model-vitals — deferred follow-ups

Deliberate deferrals from the Phase 2/3 build, recorded here rather than in a scratch ledger
so they survive. Each says why it was deferred, not just what it is.

## 1. The false-positive rate is not yet validated

The replay calibration ran over ~126 days of real transcripts and produced **0 WARN/week**, which
technically meets the spec's "< 1 WARN/week" criterion. It is not meaningful evidence.

A transcript-only replay populates just 2 of 13 passive signals (`self_corr_rate`,
`output_tokens_per_req`). Transcripts carry no `duration_ms`, no OTel-sourced errors, no
`tool_results` and no `compactions`, so S1, S1b, S2, S3, S4, S5, S6 and S9 are all structurally
empty. `self_corr_rate` is a weak signal excluded from family counting, leaving exactly one
non-weak family — and a WARN requires two. **WARN could not have fired at any threshold.**

What *was* validated: single-family behaviour of the verbosity signal over real history.

To actually calibrate, replay the OTel and hook spools (now accumulating under
`~/.model-vitals/spool/`) rather than only transcripts, and re-derive the weekly WARN count.
Until then treat the stated false-positive rates as a-priori estimates.

## 2. Suite-wide clock-independence guard (not adopted)

A date-hardcoded test silently flipped to failing when the wall clock passed its assertion
instant. It was fixed by injecting "now" instead of reading it ambiently. A peer review then
swept the whole suite at simulated dates (2026-08-26, 2026-09-30, 2027-11-09) and found no other
date fuse, with per-file reasoning.

The sweep harness was **not** adopted into the repo: it would multiply a ~70 s suite to guard a
bug class we now have evidence is absent. Recorded here so the option is a decision, not a
memory. Source below so it does not depend on a temp directory surviving.

`timetravel.py` — relocates the whole suite's "now":

```python
"""Pytest plugin: move the whole suite's notion of 'now' to $FAKE_CLOCK.

Patches vitals.timeutil's `datetime`, which is the namespace utcnow_iso / days_ago_iso /
local_day execute in -- so every module that did `from vitals.timeutil import utcnow_iso`
gets the fake clock too, without touching pytest's own use of time.
"""

import os
from datetime import datetime as _dt

import vitals.timeutil as tu

FAKE = _dt.fromisoformat(os.environ["FAKE_CLOCK"])


class _FakeDateTime(_dt):
    @classmethod
    def now(cls, tz=None):
        return FAKE.astimezone(tz) if tz is not None else FAKE.replace(tzinfo=None)


def pytest_configure(config):
    tu.datetime = _FakeDateTime
```

`tfreeze.py` — pins just the poller's clock:

```python
import os
import pytest
import vitals.watch.status_poller as sp

FAKE = os.environ["FAKE_NOW"]


@pytest.fixture(autouse=True)
def _freeze(monkeypatch):
    monkeypatch.setattr(sp, "utcnow_iso", lambda: FAKE)
```

Usage: put the file on `PYTHONPATH`, set `FAKE_CLOCK` (or `FAKE_NOW`), run
`pytest -q -p timetravel`.

**Two caveats that must travel with this code:**

1. **Validate the harness against a no-op first.** A plugin that silently fails to patch
   produces a passing sweep that proves nothing — worse than no sweep, because it looks like
   evidence. Before trusting a run: `poll()` into a temp DB under the fake clock and assert the
   stamped `resolved_at` equals the fake value exactly.
2. **Coverage is bounded to the `timeutil` helpers.** Direct real-clock calls are deliberately
   not faked — `daemon.py`'s archive `datetime.now`, `transcripts.py`, `hook.py`,
   `otlp_receiver.py`, and `daemon.py`'s `time.time()` calls. That is by design, since those
   compare against real file mtimes and stay self-consistent, but anyone extending the harness
   must know the boundary rather than assume total coverage.

## 3. Known redaction residuals

All deliberate, all pinned by tests named as limitations rather than bugs:

- **Comma/semicolon inside a secret.** `secret=part1,part2,part3` leaves `part2,part3` in
  plaintext. The value is bounded at separators so that cookies and connection strings
  (`Cookie: session=abc; token=xyz`) redact each value independently rather than swallowing the
  whole line. A long high-entropy tail is still caught by the entropy rule.
- **Email local parts over 64 characters** fall through to the entropy rule; when they do, the
  `@domain` suffix survives.
- **A secret split across a line break** redacts only up to the newline.
- **IPv6 is not handled at all.** A future rule must exempt `::1`, follow the existing
  loopback-only exemption precedent rather than exempting link-local, handle `::` compression and
  IPv4-mapped forms, and run before the entropy catch-all.

## 4. Channel secret-scrubbing invariant

Secret scrubbing has an 8-character floor, so short values are not scrubbed from diagnostics
(a `chat_id` of `1` would otherwise turn `HTTP 401` into `HTTP 40***`).

This is safe today only **incidentally**: a chat id is POST-body-only and never formatted into a
raised message, and a short ntfy topic only ever reaches a message embedded inside the full URL,
which is itself scrubbed because it is long. **A future channel whose short secret reaches a URL
independently of a longer co-scrubbed string would leak.** State this invariant in the `Channel`
protocol docstring so it is a designed guarantee rather than an accident.

## 5. Smaller items

- `replay --since-days N` filters files by **mtime**, not content date, so `--since-days 90`
  covered ~126 days. Labelling only; the extra history is real and chronologically ordered.
- `next_due`'s unparseable-timestamp branch is untested (defensive-only path).
- `001_core.sql`'s `alerts.resolution` comment predates `auto_false_positive`.
- The 60-minute alert cooldown and the 8-character scrub floor are judgement calls without
  formal derivation.

## 6. Canary auth -- RESOLVED 2026-08-25

Headless `claude -p` previously failed with `OAuth refresh token is no longer valid; run /login
to re-authenticate`, which blocked every canary cycle. **Cleared.** Canary cycle 1 ran at
2026-08-25T17:11:20Z against the real CLI: 20 runs, 16 of 16 valid runs passed
(`pass_rate = 1.0`), 4 invalid, $0.85 recorded in `spend_ledger` against the $6/day cap.

Previously listed here as blocked, now live:

- Signals C1/C2 produce data.
- Attribution rule 4 branch (a) can fire.
- The canary runner's real-subprocess path has been exercised against the real CLI, not only
  against the stub.

Remaining canary issue, unrelated to auth: 4 of the 20 runs came back `invalid` with
`terminal_reason = error_max_turns` -- `json-extract` at `max_turns = 1`, `test-writing` at
`max_turns = 6`. `pass_rate` correctly excluded them and only $0.05 was spent on them, but 20%
of each cycle's budget currently buys nothing. Raise those two task limits.

## 7. Known development hazard

Under strict TDD, `tests/test_X.py` exists before `src/.../X.py`, and pytest aborts the **entire**
run on a collection error. Anyone sampling the suite during that window sees a total failure that
looks nothing like its cause. Check `git status` for a half-written red-phase test before
believing an inexplicable full-suite failure.

## 8. Parked (shipped knowingly)

Three residuals were adjudicated at the last gate and shipped rather than fixed. Each is
recorded here with the reasoning, so they are decisions rather than oversights.

### 8.1 Double-escaped quotes still leak — and the current approach is not converging

`\"token\": \"value\"` (one `json.dumps`) is redacted. `\\"token\\": \\"value\\"` (two) is not,
and neither is the tail of a value that itself contains an escaped quote
(`\"token\": \"abc\"LEAKYTAIL\"` leaves `LEAKYTAIL`). Both fall below the 24-character entropy
floor, so the catch-all cannot net them.

Not introduced by the last round of fixes — the earlier pattern failed on these too. In practice
`hook.slim` applies exactly one `json.dumps`, so the tier that actually fires is the one now
fixed.

**The structural point matters more than the gap.** This is the fourth round of the *same*
failure — a regex that must match a whole assignment, defeated by one more unanticipated form
in the middle of it (doubled `Bearer`; a quote before the colon; a backslash before the quote;
now two backslashes). Each round added another optional prefix, and each time a fifth form was
still reachable. Adding a sixth optional group is not the fix.

The next attempt should change approach rather than widen the pattern: normalise escapes before
matching (decode `\` and `\"` on a working copy, redact, map back), or run a JSON-aware pass
over text that parses as JSON, and keep the regex for the genuinely unstructured remainder.

### 8.2 The class-A headline sentence is uninformative on the S9 path

`builder.py`'s class-A one-liner is gated on `facts["contrast_bucket"]`, which is `None` on the
new intrinsic-contrast path (an anomaly on `post_compaction_fail_rate`, where the signal is
itself a ratio and carries its own contrast). The sentence degrades to "attribution rule 3
(context_confined) matched" — true, but silent about compaction.

Shipped because it is uninformative, not false: no user is misled about *what was checked*, and
the evidence dict carries the full reasoning. It is the same class of defect as the class-B
sentence fixed in the final wave, reappearing on a path that wave opened, so it is worth closing
next time that file is touched.

### 8.3 A total delivery failure still burns the INFO cooldown

`dispatch` marks the 24-hour INFO slot after the channel fan-out completes, even if every
channel raised. "Successful dispatch" means "dispatch ran to completion", consistent with
`_mark_dispatched`'s existing semantics elsewhere in the module.

The alternative — retry on the next tick whenever delivery fails — reintroduces the notification
storm the cooldown exists to prevent, on exactly the failure mode (a persistently misconfigured
channel) most likely to recur every tick. The alert row and its report still exist locally, so
nothing is lost, only un-notified. Recorded as a deliberate choice rather than an assumption.

## 9. `_find_uv()` misses a cross-Python-version uv install

`install-service` silently falls back to stdlib `venv` + `pip` on this machine even when
launched via `uv run`. `_find_uv()` (`cli.py`) tries `shutil.which("uv")`, then probes
`site.getusersitepackages()/Scripts/uv.exe` — but the CLI runs from the project's Python 3.12
venv, so that probe resolves to a 3.12 user-site path, while uv actually lives under
`AppData\Roaming\Python\Python314\Scripts\uv.exe` (installed with `pip install --user uv` on
Python 3.14).

Harmless — the fallback produces a correct venv, just more slowly. Fix by also checking the
`UV` environment variable and the invoking process's own uv, rather than assuming uv shares the
running interpreter's user-site version.

Observed 2026-08-25 on two separate `install-service` runs.

## 10. The service runs as a launcher/worker pair — Task Scheduler tracks the wrong PID

`install-service` registers the task against
`~/.model-vitals/venv/Scripts/pythonw.exe -m vitals serve`, but that executable does not stay
the process doing the work. It spawns the base interpreter named in `pyvenv.cfg`
(`home = ...\Programs\Python\Python312`) as a CHILD and then idles — behaviour consistent with
the CPython Windows venv launcher. Observed 2026-08-25:

```
16716  venv\Scripts\pythonw.exe   -m vitals serve   parent 1104 (svchost/Task Scheduler)  CPU 0
12436  Python312\pythonw.exe      -m vitals serve   parent 16716    CPU 96, LISTENING on 4318
```

The child owns the socket and burns the CPU; the parent exists only to keep the task alive.

This is not a packaging fault, and the running code is still the venv's: the base interpreter
cannot `import vitals` on its own (`ModuleNotFoundError`), so the child resolves the venv's
site-packages through the inherited venv context. Verifying deployed-vs-repo by diffing the
installed package against `src/` remains correct — but diff CR-insensitively
(`diff -r --strip-trailing-cr`), because the repo working tree is CRLF while the pip-installed
copy is LF, so a plain `diff -r` reports every file as differing when nothing has changed.

The hazard is the PID split. Terminating the launcher WITHOUT its child leaves an orphaned
worker still holding 4318, and the next start then fails at the bind and records
`receiver_state = down, detail = "port <n> in use (...)"` (`daemon.py:312-319`) — so `vitals
status` reports the receiver DOWN while the scheduled task itself still looks Running. Task
Scheduler's own End / `schtasks /end` path normally tears down the whole tree; the exposure is
the manual path — `Stop-Process -Id <launcher>` or `taskkill /PID <launcher>` without `/T`.
Kill the tree, not the PID.

NOT empirically reproduced. This is derived from the process topology on purpose: demonstrating
it means killing a live monitor. Treat the orphan as reasoned, not observed.

UPDATE 2026-08-28: the SAFE half is now observed. A real deploy stopped the daemon with
`Stop-ScheduledTask`, and it tore down the whole tree -- launcher and worker both gone, port
4318 released, verified by process list and netstat. So the scheduler path is confirmed safe and
the exposure is narrowed to the manual one (`Stop-Process`/`taskkill` on the launcher PID without
`/T`), which remains untested.

Durable fix if it ever bites: register the task against the base interpreter directly with the
venv's `site-packages` on `PYTHONPATH`, removing the middle process entirely. Cheaper
mitigation: have the bind failure name the PID currently holding the port, so the status detail
points at the orphan instead of only reporting the port busy.

Observed 2026-08-25 while verifying the phase-2 merge.

## 11. Degenerate baselines: the relative floor vanishes at mu0 = 0

`robust()` (`src/vitals/detect/baseline.py:84-98`) sets

    sigma0 = max(1.4826*MAD, IQR/1.349, 0.05*|mu0|, 1e-9)

and its own docstring names the relative term as the thing that "stops a near-constant signal
from hair-triggering". That term is MULTIPLICATIVE in mu0, so at mu0 = 0 it contributes nothing.
A baseline of identically-zero samples drives MAD, IQR and the relative floor all to 0, and the
`1e-9` epsilon becomes the divisor.

Observed live 2026-08-25 (`anomalies` id 1 and 2):

    signal=self_corr_rate model=claude-opus-5 bucket=all  mu0=0.0  sigma0=1e-09  baseline_n=50
    peak_stat=57.5   ->   peak_z = 90,909,090

Harmless in this instance, and harmless BY DESIGN: `self_corr_rate` is the sole member of
`WEAK_SIGNALS` (`signal_ids.py:53`), excluded from family counting, so it can only ever reach
INFO -- which is exactly what happened (one INFO alert, attribution C). The defence-in-depth
held. The finding is the general case, not this instance.

Any signal reaching `robust()` with an all-zero baseline becomes a hair-trigger: the first
non-zero window yields an effectively infinite z. Rate signals are protected -- `pooled_rate()`
applies the Jeffreys-style floor `p0 = max(events/samples, 0.5/samples)`, which can never reach
0 -- but membership of `RATE_SIGNALS` is an explicit list (`signal_ids.py:57-69`), and two
signals NAMED `_rate` are absent from it:

- `S7_SELF_CORR_RATE` -- weak, so capped at INFO. The observed case above.
- `S3_RETRY_RATE` (`api_retry_rate`) -- family `errors`, NOT weak, so it DOES count toward the
  WARN family threshold. An all-zero baseline is entirely plausible for it (`vitals status`
  currently reports "0 retries-exhausted"), which would make the first retry-exhausted window
  alarm at an absurd z on a signal that can help fire a WARN.

Reachable, not yet realised: `api_retry_rate` has no fitted baseline in the live DB at all. As
of 2026-08-25 only three strata have baselines, all `self_corr_rate`, and all three are
degenerate; `api_error_rate` -- a `RATE_SIGNALS` member -- sits at a healthy sigma0 = 0.0154,
which is the Jeffreys floor doing its job.

This is section 1's unvalidated false-positive rate with a concrete mechanism attached, and it
is the first thing to settle before anyone trusts a WARN. Options, in rough order of appeal:

1. Refuse to alarm from a stratum whose baseline has zero dispersion (MAD and IQR both 0). An
   all-constant baseline carries no scale information, so no z computed against it means
   anything; suspend the stratum until it has seen variation.
2. Decide whether `api_retry_rate` and `self_corr_rate` belong in `RATE_SIGNALS`. Both are
   proportions by name; if they are proportions in fact, the Jeffreys floor already solves this.
3. Failing either, replace the additive `1e-9` with an absolute floor derived from the signal's
   own quantisation (one event per window), so z stays finite and interpretable.

Interaction worth knowing: a degenerate stratum in alarm also FREEZES its baseline
(`detector_state.frozen = 1`), and `auto_resolve_days` adjudicates only CLOSED episodes -- by
design, per the `DetectCfg.auto_resolve_days` comment. Anomalies 1 and 2 have been open since
2026-08-24T09:00Z across 39 evaluated windows, so until someone runs `vitals resolve` those
strata's baselines stay frozen.

Observed 2026-08-25 while assessing deployment readiness.


## 12. `install-service` cannot redeploy over a running daemon

Re-running `vitals install-service` on a live install fails:

```
Error: [Errno 13] Permission denied: 'C:\Users\...\.model-vitals\venv\Scripts\pythonw.exe'
```

`_cmd_install_service` (`cli.py:527`) rebuilds the venv as its first act and never stops the
daemon that is running out of it, so the running `pythonw.exe` holds its own executable open and
the rebuild cannot overwrite it.

Stopping the task is NOT sufficient on its own, which is the part that surprises. The task
carries two triggers -- `AtLogOn` plus a `-Once` repetition at `PT2M` -- so `Stop-ScheduledTask`
ends only the current instance and the repetition relaunches the daemon within two minutes,
re-locking the venv mid-install. Observed 2026-08-28: stopped at 17:43, relaunched by the
trigger at 17:45:07, install failed on the lock. That repetition is deliberate (it is what makes
a force-killed daemon come back -- see the trigger comment in `scripts/install_task.ps1`); it
simply also fights maintenance.

The working sequence, used for the 2026-08-28 deploy:

```
Disable-ScheduledTask -TaskName model-vitals   # stop the PT2M trigger relaunching it
Stop-ScheduledTask    -TaskName model-vitals   # end the current instance
# verify: no pythonw with '-m vitals serve', and nothing LISTENING on 4318
vitals install-service                          # rebuild venv, reinstall, re-register
Enable-ScheduledTask  -TaskName model-vitals
Start-ScheduledTask   -TaskName model-vitals
```

Note `install-service` unregisters and re-registers the task, so the disable does not survive it
-- the `Enable` above is belt and braces, not a correction.

Fix: have `install-service` disable + stop the task before touching the venv and restore the
previous state afterwards, so a redeploy is one command rather than a six-step runbook someone
has to remember. Until then this is a footgun that presents as a permissions error, which sends
the reader looking at ACLs rather than at a lock.

A second, quieter trap in the same command: verify a deploy with
`diff -r --strip-trailing-cr`, never a plain `diff -r`. The repo working tree is CRLF and the
pip-installed copy is LF, so a plain diff reports every file as differing on a perfectly good
deploy. See follow-ups 10.

Observed 2026-08-28 while deploying the detector fixes.
