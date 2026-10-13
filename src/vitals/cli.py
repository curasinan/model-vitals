from __future__ import annotations

import argparse
import difflib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from vitals import config as config_mod


def _cfg(args: argparse.Namespace):
    return config_mod.load(Path(args.config) if getattr(args, "config", None) else None)


def _cmd_install_hooks(args: argparse.Namespace) -> int:
    from vitals.install import (
        backup_settings,
        default_hook_cmd,
        default_settings_path,
        load_settings,
        merge_settings,
        smoke_check,
    )

    cfg = _cfg(args)
    settings_path = Path(args.settings) if args.settings else default_settings_path()
    hook_cmd = default_hook_cmd()
    current = load_settings(settings_path)
    merged, conflicts = merge_settings(current, hook_cmd)

    before = json.dumps(current, indent=2, sort_keys=True).splitlines(keepends=True)
    after = json.dumps(merged, indent=2, sort_keys=True).splitlines(keepends=True)
    diff = list(
        difflib.unified_diff(before, after, fromfile=str(settings_path), tofile="(merged)", n=2)
    )
    print("".join(diff) if diff else "settings.json already up to date")
    for conflict in conflicts:
        print(f"CONFLICT (not overwritten): {conflict}")

    if args.dry_run:
        print("\n--dry-run: nothing written.")
        print(f"hook command would be: {hook_cmd}")
        return 0

    smoke_check(hook_cmd, cfg.data_dir)
    print(f"smoke check OK: {hook_cmd}")

    if not diff:
        return 0
    backup = backup_settings(settings_path)
    if backup:
        print(f"backup written: {backup}")
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    print(f"updated {settings_path}")
    print("Restart any running Claude Code sessions for the env block to take effect.")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    from vitals.db import get_conn, init_db
    from vitals.status import render_status

    cfg = _cfg(args)
    conn = get_conn(cfg.db_path)
    init_db(conn)
    try:
        print(render_status(conn, args.hours))
    finally:
        conn.close()
    return 0


def _cmd_ingest_once(args: argparse.Namespace) -> int:
    from vitals.daemon import ingest_once

    ingest_once(_cfg(args))
    print("ingest complete")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from vitals.daemon import Daemon

    return Daemon(_cfg(args)).run()


def _cmd_canary_run(args: argparse.Namespace) -> int:
    from vitals.canary.checkers import default_tasks_dir, load_tasks
    from vitals.canary.runner import run_cycle
    from vitals.db import get_conn, init_db

    cfg = _cfg(args)
    tasks = load_tasks(default_tasks_dir())
    if args.task:
        tasks = [t for t in tasks if t.task_id == args.task]
        if not tasks:
            print(f"unknown task id: {args.task!r}")
            return 1

    conn = get_conn(cfg.db_path)
    init_db(conn)
    try:
        cycle_id = run_cycle(conn, cfg.canary, tasks, inject_model=args.inject_model)
        row = conn.execute(
            "SELECT n_runs, n_pass, n_invalid, pass_rate, cost_usd, aborted_reason "
            "FROM canary_cycles WHERE cycle_id = ?",
            (cycle_id,),
        ).fetchone()
        pass_rate = "n/a" if row["pass_rate"] is None else f"{row['pass_rate']:.2f}"
        print(
            f"cycle {cycle_id}: runs={row['n_runs']} pass={row['n_pass']} "
            f"invalid={row['n_invalid']} pass_rate={pass_rate} "
            f"cost_usd={row['cost_usd']:.4f} aborted_reason={row['aborted_reason']}"
        )
    finally:
        conn.close()
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    from vitals.validate.replay import backfill, open_replay_db, render_replay_report

    cfg = _cfg(args)
    conn, db_path = open_replay_db()
    try:
        report = backfill(conn, cfg.projects_dir, since_days=args.since_days, detect_cfg=cfg.detect)
    finally:
        conn.close()
    print(f"replay database (throwaway, safe to delete): {db_path}")
    print(render_replay_report(report, args.since_days))
    return 0


def _cmd_inject(args: argparse.Namespace) -> int:
    if not args.model_swap:
        print("nothing to do: pass --model-swap")
        return 1

    from vitals.canary.checkers import default_tasks_dir, load_tasks
    from vitals.db import get_conn, init_db
    from vitals.validate.inject import insert_fake_version_change_point, model_swap_drill

    cfg = _cfg(args)
    tasks = load_tasks(default_tasks_dir())
    conn = get_conn(cfg.db_path)
    init_db(conn)
    try:
        if args.with_version_cp:
            cp_id = insert_fake_version_change_point(conn)
            print(f"planted fake change_points row id={cp_id} (kind=cc_version)")

        results = model_swap_drill(conn, cfg, tasks, inject_model=args.inject_model)
        if not results:
            print(
                "model-swap drill: no draft alert produced this run (no live canary baseline "
                "yet, or the K-consecutive rule has not fired) -- see vitals status"
            )
            return 0
        for draft, attribution in results:
            print(
                f"{draft.severity} attribution={attribution.cls} "
                f"rule={attribution.evidence['matched_rule_name']}: {draft.title}"
            )
    finally:
        conn.close()
    return 0


def _cmd_resolve(args: argparse.Namespace) -> int:
    from vitals.db import get_conn, init_db
    from vitals.detect.engine import resolve

    cfg = _cfg(args)
    conn = get_conn(cfg.db_path)
    init_db(conn)
    try:
        resolved = resolve(conn, args.alert_id, args.as_, cfg=cfg.detect)
        if not resolved:
            print(f"nothing to resolve: no alert or anomaly row with id {args.alert_id}")
            return 1
        normalized = args.as_.replace("-", "_").lower()
        if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (args.alert_id,)).fetchone():
            from vitals.alert.labels import record_label

            label = "real" if normalized == "confirmed" else "false_alarm"
            record_label(conn, args.alert_id, label, "cli")
        if normalized == "false_positive":
            print(
                f"resolved anomaly id(s) {resolved} as false-positive: folded back into"
                " healthy history -- the stratum's baseline recomputes over these hours once"
                " every anomaly on it is settled."
            )
        else:
            print(
                f"resolved anomaly id(s) {resolved} as confirmed: excluded from the baseline"
                " and the healthy-day counter restarts -- the stratum has no baseline again"
                " until fresh healthy hours accumulate."
            )
    finally:
        conn.close()
    return 0


def _cmd_label(args: argparse.Namespace) -> int:
    from vitals.alert.labels import apply_label
    from vitals.db import get_conn, init_db

    cfg = _cfg(args)
    conn = get_conn(cfg.db_path)
    init_db(conn)
    label = args.label.replace("-", "_")
    try:
        apply_label(conn, args.alert_id, label, "cli", cfg.detect)
    except LookupError:
        print(f"no alert with id {args.alert_id}")
        return 1
    finally:
        conn.close()
    print(f"alert {args.alert_id} labelled {args.label}")
    return 0


def _cmd_handle_uri(args: argparse.Namespace) -> int:
    from vitals.alert.protocol import handle_uri

    return handle_uri(_cfg(args), args.uri)


def _cmd_alert_test(args: argparse.Namespace) -> int:
    import uuid

    from vitals.alert.dispatcher import dispatch
    from vitals.alert.rules import AlertDraft
    from vitals.db import get_conn, init_db
    from vitals.detect.attribution import Attribution
    from vitals.timeutil import utcnow_iso

    cfg = _cfg(args)
    conn = get_conn(cfg.db_path)
    init_db(conn)
    try:
        now_iso = utcnow_iso()
        draft = AlertDraft(
            severity="WARN",
            title="vitals alert-test: synthetic WARN",
            anomaly_ids=[],
            families=["latency", "errors"],
            suppressed_by_incident=None,
            dedup_key=f"alert-test::{uuid.uuid4().hex}",
            first_seen=now_iso,
        )
        attribution = Attribution(
            cls="E",
            evidence={
                "cls": "E",
                "matched_rule": 6,
                "matched_rule_name": "inconclusive",
                "generated_at": now_iso,
                "note": "synthetic alert generated by `vitals alert-test`",
                "strata": {"signals": [], "models": [], "context_buckets": [], "cc_versions": []},
                "rules": [],
            },
        )
        alert_id = dispatch(conn, cfg, draft, attribution, now_iso=now_iso)
        from vitals.alert.channels import load_channels

        names = [c.name for c in load_channels(cfg)]
        print(f"alert-test: dispatched alert id={alert_id} to channels={names or 'none enabled'}")
    finally:
        conn.close()
    return 0


GH_REPO = "anthropics/claude-code"


def run_gh(cmd: list[str]):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _load_alert_row(conn, alert_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row is not None else None


def _resolve_report_path(row: dict, alert_id: int) -> Path | str:
    report_path = row.get("report_path")
    if not report_path:
        return (
            f"alert {alert_id} has no report on file (alerts.report_path is empty). A report is"
            " built automatically only for CRITICAL alerts -- run"
            f" `vitals report build {alert_id}` to build one for this alert."
        )
    path = Path(report_path)
    if not path.exists():
        return (
            f"alert {alert_id}'s recorded report is missing on disk: {path}"
            " (moved or deleted after it was generated)."
        )
    return path


def _cmd_report_build(args: argparse.Namespace) -> int:
    from vitals.db import get_conn, init_db
    from vitals.report.builder import build

    cfg = _cfg(args)
    conn = get_conn(cfg.db_path)
    init_db(conn)
    try:
        if _load_alert_row(conn, args.alert_id) is None:
            print(f"no alerts row with id {args.alert_id}")
            return 1
        try:
            md_path, json_path = build(conn, cfg, args.alert_id)
        except (OSError, ValueError) as exc:
            print(f"could not build a report for alert {args.alert_id}: {exc}")
            return 1
        conn.execute(
            "UPDATE alerts SET report_path = ? WHERE id = ?", (str(md_path), args.alert_id)
        )
        conn.commit()
        print(str(md_path))
        print(f"(machine-readable mirror: {json_path})")
        print(
            "Review it before sharing -- then `vitals report open"
            f" {args.alert_id}` or `vitals report issue {args.alert_id}`."
        )
        return 0
    finally:
        conn.close()


def _cmd_report_open(args: argparse.Namespace) -> int:
    from vitals.db import get_conn, init_db

    cfg = _cfg(args)
    conn = get_conn(cfg.db_path)
    init_db(conn)
    try:
        row = _load_alert_row(conn, args.alert_id)
        if row is None:
            print(f"no alerts row with id {args.alert_id}")
            return 1
        resolved = _resolve_report_path(row, args.alert_id)
        if isinstance(resolved, str):
            print(resolved)
            return 1
        print(str(resolved))
        if hasattr(os, "startfile"):
            os.startfile(resolved)  # type: ignore[attr-defined]
        else:
            print("(os.startfile is Windows-only -- open the path above manually)")
        return 0
    finally:
        conn.close()


def _record_issue_url(conn, alert_id: int, url: str) -> None:
    row = conn.execute("SELECT evidence_json FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    raw = row["evidence_json"] if row else None
    try:
        evidence = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        evidence = {}
    if not isinstance(evidence, dict):
        evidence = {"_prior_evidence": evidence}
    evidence["gh_issue_url"] = url
    conn.execute(
        "UPDATE alerts SET evidence_json = ? WHERE id = ?", (json.dumps(evidence), alert_id)
    )
    conn.commit()


def _cmd_report_issue(args: argparse.Namespace) -> int:
    from vitals.db import get_conn, init_db

    cfg = _cfg(args)
    conn = get_conn(cfg.db_path)
    init_db(conn)
    try:
        row = _load_alert_row(conn, args.alert_id)
        if row is None:
            print(f"no alerts row with id {args.alert_id}")
            return 1
        resolved = _resolve_report_path(row, args.alert_id)
        if isinstance(resolved, str):
            print(resolved)
            return 1
        body_path = resolved

        title = f"[model-vitals] {row['title']}"
        cmd = [
            "gh",
            "issue",
            "create",
            "--repo",
            GH_REPO,
            "--title",
            title,
            "--body-file",
            str(body_path),
        ]
        print(" ".join(shlex.quote(part) for part in cmd))

        if not args.yes_post:
            print(
                "Not submitted -- this tool never auto-submits to Anthropic. Rerun with"
                " --yes-post to be prompted for confirmation, or copy the command above and"
                " run it yourself."
            )
            return 0

        print(f"About to publicly file this issue in {GH_REPO}:")
        print(f"  title: {title}")
        answer = input("Type 'yes' to proceed, anything else aborts: ")
        if answer.strip().lower() != "yes":
            print("aborted -- gh was not run.")
            return 0

        try:
            result = run_gh(cmd)
        except OSError as exc:
            print(f"could not run gh: {exc}")
            return 1

        if result.returncode != 0:
            print(
                f"gh issue create failed (exit {result.returncode}):"
                f" {(result.stderr or '').strip()}"
            )
            return 1

        lines = [ln.strip() for ln in (result.stdout or "").splitlines() if ln.strip()]
        url = lines[-1] if lines else ""
        if url:
            _record_issue_url(conn, args.alert_id, url)
            print(f"filed: {url}")
        else:
            print("gh issue create succeeded but produced no output to record as the issue URL.")
        return 0
    finally:
        conn.close()


def _find_uv() -> str | None:
    import shutil

    found = shutil.which("uv")
    if found:
        return found
    import site

    candidates = [
        Path(p).parent / "Scripts" / "uv.exe" for p in site.getusersitepackages().split(";")
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def _cmd_install_service(args: argparse.Namespace) -> int:
    from vitals.alert.protocol import handler_command, register, scheme, smoke_check

    cfg = _cfg(args)
    repo = Path(__file__).resolve().parents[2]
    venv = cfg.data_dir / "venv"
    script = repo / "scripts" / "install_task.ps1"
    venv_python = venv / "Scripts" / "python.exe"

    print(f"creating venv at {venv}")
    uv = _find_uv()
    if uv:
        subprocess.run([uv, "venv", str(venv)], check=True)
        subprocess.run([uv, "pip", "install", "--python", str(venv_python), str(repo)], check=True)
    else:
        print("uv not found; falling back to stdlib venv + pip")
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        subprocess.run([str(venv_python), "-m", "pip", "install", "-q", str(repo)], check=True)

    pythonw = venv / "Scripts" / "pythonw.exe"
    if args.dry_run:
        print(f"--dry-run: would register a logon task running {pythonw} -m vitals serve")
        print(f"--dry-run: would register {scheme()}:// -> {handler_command(pythonw)}")
        return 0
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-PythonW",
            str(pythonw),
        ],
        text=True,
    )
    if result.returncode != 0:
        return result.returncode

    register(pythonw)
    print(f"registered {scheme()}:// -> {handler_command(pythonw)}")
    if smoke_check(cfg):
        print("toast buttons: the link handler answered")
        return 0
    print(
        "toast buttons: the link handler did not answer within 15 s, so clicks on toast"
        " buttons will not be recorded; use `vitals label` instead"
    )
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vitals", description="Local-first Claude Code effectiveness monitor"
    )
    parser.add_argument("--config", help="path to config.toml (default: <data_dir>/config.toml)")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_install = sub.add_parser("install-hooks", help="register hooks + OTel env in settings.json")
    p_install.add_argument("--dry-run", action="store_true", help="print the diff, write nothing")
    p_install.add_argument(
        "--settings", help="settings.json path (default: ~/.claude/settings.json)"
    )
    p_install.set_defaults(func=_cmd_install_hooks)

    p_status = sub.add_parser("status", help="show collection health and recent signals")
    p_status.add_argument("--hours", type=int, default=24)
    p_status.set_defaults(func=_cmd_status)

    p_once = sub.add_parser("ingest-once", help="run one ingest + aggregate pass and exit")
    p_once.set_defaults(func=_cmd_ingest_once)

    p_serve = sub.add_parser("serve", help="run the resident daemon (receiver + jobs)")
    p_serve.set_defaults(func=_cmd_serve)

    p_service = sub.add_parser("install-service", help="register the daemon as a logon task")
    p_service.add_argument("--dry-run", action="store_true")
    p_service.set_defaults(func=_cmd_install_service)

    p_canary = sub.add_parser("canary", help="active canary probe commands")
    canary_sub = p_canary.add_subparsers(dest="canary_command", metavar="<canary-command>")
    p_canary_run = canary_sub.add_parser("run", help="run one canary cycle against claude -p")
    p_canary_run.add_argument(
        "--once",
        action="store_true",
        help="run a single cycle and exit -- this is what the command always does; accepted "
        "for explicit scripting clarity, but has no effect (scheduled/continuous canary runs "
        "live in `vitals serve`'s own scheduler thread, not here)",
    )
    p_canary_run.add_argument("--task", help="run only this task id, for smoke-testing one fixture")
    p_canary_run.add_argument(
        "--inject-model",
        dest="inject_model",
        default=None,
        help="invoke this model instead of cfg.canary.model, WITHOUT changing what "
        "canary_runs.model records -- the synthetic-injection hook that proves the detector "
        "actually notices a model swap, which it can only do if the recorded baseline model "
        "never silently changes underfoot",
    )
    p_canary_run.set_defaults(func=_cmd_canary_run)

    p_replay = sub.add_parser(
        "replay",
        help="replay historical transcripts through the full detector (task 23 calibration)",
    )
    p_replay.add_argument(
        "--since-days",
        type=int,
        default=90,
        help="replay transcript files MODIFIED within this many days (file mtime, not the"
        " conversation dates inside them -- a resumed session, a restore or a sync can make an"
        " old conversation look recent, and an unmodified file is skipped whole) (default: 90)",
    )
    p_replay.set_defaults(func=_cmd_replay)

    p_inject = sub.add_parser(
        "inject", help="synthetic injection drills that calibrate/validate the detector"
    )
    p_inject.add_argument(
        "--model-swap",
        action="store_true",
        help="run K canary cycles with the model silently swapped on argv (recorded model "
        "never changes) and report the resulting attribution",
    )
    p_inject.add_argument(
        "--with-version-cp",
        action="store_true",
        help="also plant a fake cc_version change point before the drill (rule-order check)",
    )
    p_inject.add_argument(
        "--inject-model",
        dest="inject_model",
        default="claude-haiku-4-5",
        help="model to silently invoke instead of cfg.canary.model (default: claude-haiku-4-5)",
    )
    p_inject.set_defaults(func=_cmd_inject)

    p_resolve = sub.add_parser(
        "resolve", help="adjudicate an alert or anomaly as confirmed or false-positive"
    )
    p_resolve.add_argument(
        "alert_id",
        type=int,
        help="alerts.id, or a bare anomalies.id if no alert row exists yet for it",
    )
    p_resolve.add_argument(
        "--as",
        dest="as_",
        required=True,
        choices=["confirmed", "false-positive"],
        help="confirmed: exclude the window from the baseline and restart the healthy-day "
        "counter. false-positive: fold the window back into healthy history.",
    )
    p_resolve.set_defaults(func=_cmd_resolve)

    p_label = sub.add_parser(
        "label",
        help="label an alert as real, a false alarm, or not sure (same as the toast buttons)",
    )
    p_label.add_argument("alert_id", type=int, help="alerts.id")
    p_label.add_argument("label", choices=["real", "false-alarm", "unsure"])
    p_label.set_defaults(func=_cmd_label)

    p_uri = sub.add_parser(
        "handle-uri", help="handle a model-vitals:// link (what the toast buttons launch)"
    )
    p_uri.add_argument("uri")
    p_uri.set_defaults(func=_cmd_handle_uri)

    p_alert_test = sub.add_parser(
        "alert-test",
        help="dispatch a synthetic WARN through every enabled alert channel (Phase 2 gate)",
    )
    p_alert_test.set_defaults(func=_cmd_alert_test)

    p_report = sub.add_parser(
        "report", help="build, open, or file as a GitHub issue, an alert's /bug-ready report"
    )
    report_sub = p_report.add_subparsers(dest="report_command", metavar="<report-command>")

    p_report_build = report_sub.add_parser(
        "build",
        help="build (or rebuild) an alert's redacted report at any severity and record it on"
        " the alert -- the dispatcher only ever builds one automatically for CRITICAL",
    )
    p_report_build.add_argument("alert_id", type=int, help="alerts.id")
    p_report_build.set_defaults(func=_cmd_report_build)

    p_report_open = report_sub.add_parser("open", help="print an alert's report path and open it")
    p_report_open.add_argument("alert_id", type=int, help="alerts.id")
    p_report_open.set_defaults(func=_cmd_report_open)

    p_report_issue = report_sub.add_parser(
        "issue",
        help="print the gh issue create command for an alert's report; --yes-post to file it"
        " after a typed confirmation (this tool never auto-submits to Anthropic)",
    )
    p_report_issue.add_argument("alert_id", type=int, help="alerts.id")
    p_report_issue.add_argument(
        "--yes-post",
        dest="yes_post",
        action="store_true",
        help="after an interactive typed 'yes' confirmation showing the title, actually run"
        " gh issue create -- omit to just print the command and run nothing",
    )
    p_report_issue.set_defaults(func=_cmd_report_issue)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return 1
    return int(handler(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
