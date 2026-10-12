# model-vitals

A local-first monitor that detects model effectiveness degradation in Claude Code early, from
passive telemetry and active canary probes. It attributes a regression to a cause class
(A session/context, B harness/version, C provider, D local hardware, E inconclusive) and
prepares, but never auto-submits, a `/bug`-ready report.

All data stays on your machine. No SaaS, no auto-submission, no prompt text on disk.

## What it does

- **Collection:** nine async Claude Code hooks, an OTLP/HTTP receiver on `127.0.0.1:4318`, and
  a transcript scanner over `~/.claude/projects`, all drained into a local SQLite store.
- **Detection:** hourly signal windows, robust baselines, CUSUM/EWMA per stratum
  (signal × model × context bucket × Claude Code version), change-point and status-page
  watchers.
- **Attribution and alerts:** ordered attribution rules, severity by signal family, desktop
  toasts (Windows), Telegram and ntfy channels.
- **Canaries:** a small fixed task suite run against the `claude` CLI on a schedule, behind a
  hard daily spend cap.
- **Reports:** a redacted Markdown report per alert, ready to review and file.

```bash
vitals status
```

## Where things live

| what | path | why |
|---|---|---|
| data (db, spool, logs, venv) | `~/.model-vitals` | not OneDrive, not `%LOCALAPPDATA%`, see below |
| hook script | `~/.model-vitals/hook.py` | copied out of the repo at install time |
| daemon | scheduled task `model-vitals` | `pythonw -m vitals serve`, no console window |

Installs made under the old name keep working: if `~/.claude-vitals` exists and
`~/.model-vitals` does not, the old directory is used, and `install-service` replaces the old
`claude-vitals` scheduled task.

**`%LOCALAPPDATA%` is avoided on purpose.** The Claude desktop app is an MSIX package, so
writes its child processes make under `%LOCALAPPDATA%` are redirected into
`AppData\Local\Packages\Claude_*\LocalCache\Local`. Hooks spawned by the desktop app would land
there, while hooks from a terminal `claude` session and the scheduled daemon would use the real
path, and collection would split in half with no error anywhere. The profile root is not
virtualised.

## Managing the daemon

```powershell
Start-ScheduledTask -TaskName model-vitals
```

The task has two triggers: at logon, and a `-Once` trigger repeating every 2 minutes with
`MultipleInstances IgnoreNew`. The repetition is what makes it self-healing: Windows does not
reliably treat an externally killed process as a task failure, so `-RestartCount` alone never
restarts it, and a repetition attached to the logon trigger only fires right after a logon.

To redeploy over a running daemon, disable and stop the task first, otherwise the repetition
relaunches it and locks the venv mid-install:

```powershell
Disable-ScheduledTask -TaskName model-vitals
Stop-ScheduledTask    -TaskName model-vitals
vitals install-service
Enable-ScheduledTask  -TaskName model-vitals
Start-ScheduledTask   -TaskName model-vitals
```

To remove everything:

```powershell
Unregister-ScheduledTask -TaskName model-vitals -Confirm:$false
```

then restore `~/.claude/settings.json` from the newest `settings.json.vitals-bak-*` beside it,
and delete `~/.model-vitals`.

## Development

```bash
uv sync
uv run pytest -m "not slow"
uv run pytest -m slow
uv run ruff check .
uv run python scripts/mypy_ratchet.py
```

uv provisions its own CPython 3.12 for the venv.

## Install into Claude Code

```bash
uv run vitals install-hooks --dry-run
```

Review the diff, then drop `--dry-run`. The installer:

1. copies `src/vitals/hook.py` to `~/.model-vitals/hook.py`, so a synced or deleted repo
   cannot silently kill collection;
2. registers it for nine hook events with `"async": true`, so Claude Code never waits on it
   and a crashing hook is non-blocking;
3. merges the OTel env block (`http/json` to `127.0.0.1:4318`), leaving every content
   privacy gate unset;
4. smoke-runs the exact installed command and refuses to write `settings.json` unless a spool
   line actually appears.

Existing hooks and env values are preserved; conflicting env values are reported, never
overwritten. A timestamped `settings.json.vitals-bak-*` is written before any change.

### Measured hook overhead

25 invocations of the installed command (base CPython 3.12, `-I`, script on local disk) on a
Windows laptop:

| | mean | median | min | p90 |
|---|---|---|---|---|
| `python -I hook.py` | 735 ms | 520 ms | 285 ms | 1148 ms |

Almost all of it is Windows process creation, not the script: a bare `python -c pass`
measures the same, and antivirus scanning of every `CreateProcess` is the likely cause. There
is no user-visible latency because every hook is async. Hooks run under the base interpreter
rather than the venv launcher, which would double the cost and disappear on a venv rebuild.

## The feature-level corpus

`corpus/` holds a feature-level corpus derived from a real event store: numeric, boolean and
enum columns only, no free text, no file paths, no prompts. `corpus/schema.py` owns every
vocabulary and enforces that at write time.

The extractor runs locally and never in CI. `scripts/extract_corpus.py` is the only file that
opens the real event store; no workflow references it.

```powershell
$b = New-Object byte[] 32
(New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b)
$env:VITALS_CORPUS_HMAC_KEY = ($b | ForEach-Object { $_.ToString('x2') }) -join ''
Remove-Variable b
uv run python scripts/extract_corpus.py
```

`VITALS_CORPUS_HMAC_KEY` is required, must be at least 32 random bytes, and is never committed.
It keys the HMAC-SHA256 behind every identity column. Details: [`docs/corpus.md`](docs/corpus.md).

## Layout

```
src/vitals/        the monitor (CLI: vitals)
  ingest/ watch/   collection and change watchers
  detect/          signals, baselines, CUSUM, attribution
  alert/ report/   alert rules, channels, redacted reports
  canary/          canary runner, budget, task suite
corpus/            corpus schema, privacy boundary, injection and evaluation harness
scripts/           extractor, detector eval, gitleaks wrapper, mypy ratchet
tests/
docs/              ADRs and design notes
```

`hook.py` has hard constraints: stdlib only, no package imports, never writes to stdout,
always exits 0.
