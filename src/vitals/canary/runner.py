from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from vitals.canary.budget import check_and_reserve, settle
from vitals.canary.checkers import CHECKERS, RunArtifacts, TaskSpec, suite_hash
from vitals.canary.longctx import NEEDLE_SEED, generate_log
from vitals.config import CACHE_READ_PRICE_RATIO, CANARY_PRICE_PER_MTOK_USD, CanaryCfg
from vitals.db import kv_get, kv_set, log_ingest, upsert_session
from vitals.timeutil import utcnow_iso

__all__ = ["RunRow", "run_cycle", "run_task"]

_AUTH_ERROR_RE = re.compile(
    r"oauth refresh token|/login|not logged in|invalid x-api-key|authentication_error|"
    r"please run.{0,20}login|no api key",
    re.IGNORECASE,
)

_ABORT_TERMINAL_REASONS = {"claude-not-found", "auth"}


@dataclass
class RunRow:
    cycle_id: int
    task_id: str
    attempt: int
    session_id: str | None
    ts: str
    model: str
    passed: int | None
    invalid: int
    fail_detail: str | None
    duration_ms: float | None
    duration_api_ms: float | None
    ttft_ms: float | None
    num_turns: int | None
    input_tokens: int | None
    output_tokens: int | None
    cache_read_tokens: int | None
    cost_usd: float | None
    terminal_reason: str | None
    is_error: int | None
    subtype: str | None
    result_sha: str | None
    long_context: bool = False


def _price_for_model(model: str) -> tuple[float, float] | None:
    model_lower = (model or "").lower()
    for key, price in CANARY_PRICE_PER_MTOK_USD.items():
        if key in model_lower:
            return price
    return None


def _accumulate_usage(data: dict, actual_model: str) -> tuple[int, int, int, float | None]:
    model_usage = data.get("modelUsage") or {}
    tokens_in = tokens_out = cache_read = 0
    usage_cost = 0.0
    for entry in model_usage.values():
        if not isinstance(entry, dict):
            continue
        tokens_in += int(entry.get("inputTokens") or 0)
        tokens_out += int(entry.get("outputTokens") or 0)
        cache_read += int(entry.get("cacheReadInputTokens") or 0)
        usage_cost += float(entry.get("costUSD") or 0)

    total_cost_usd = data.get("total_cost_usd") or 0
    if total_cost_usd:
        cost = float(total_cost_usd)
    elif usage_cost:
        cost = usage_cost
    else:
        price = _price_for_model(actual_model)
        if price is None:
            cost = None
        else:
            cost = (
                (tokens_in / 1_000_000) * price[0]
                + (tokens_out / 1_000_000) * price[1]
                + (cache_read / 1_000_000) * price[0] * CACHE_READ_PRICE_RATIO
            )
    return tokens_in, tokens_out, cache_read, cost


def _insert_run(conn: sqlite3.Connection, row: RunRow) -> int:
    cur = conn.execute(
        "INSERT INTO canary_runs("
        " cycle_id, task_id, attempt, session_id, ts, model, passed, invalid, fail_detail,"
        " duration_ms, duration_api_ms, ttft_ms, num_turns, input_tokens, output_tokens,"
        " cache_read_tokens, cost_usd, terminal_reason, is_error, subtype, result_sha,"
        " long_context"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            row.cycle_id,
            row.task_id,
            row.attempt,
            row.session_id,
            row.ts,
            row.model,
            row.passed,
            row.invalid,
            row.fail_detail,
            row.duration_ms,
            row.duration_api_ms,
            row.ttft_ms,
            row.num_turns,
            row.input_tokens,
            row.output_tokens,
            row.cache_read_tokens,
            row.cost_usd,
            row.terminal_reason,
            row.is_error,
            row.subtype,
            row.result_sha,
            int(row.long_context),
        ),
    )
    conn.commit()
    return cur.lastrowid


def _build_args(
    base_cmd: list[str],
    task: TaskSpec,
    cfg: CanaryCfg,
    session_id: str,
    model_for_argv: str,
    per_run_budget_usd: float,
) -> list[str]:
    args = list(base_cmd) + [
        "-p",
        "--output-format",
        "json",
        "--model",
        model_for_argv,
        "--effort",
        cfg.effort,
        "--max-turns",
        str(task.max_turns),
        "--max-budget-usd",
        f"{per_run_budget_usd:.4f}",
        "--session-id",
        session_id,
        "--bare",
    ]
    if task.allowed_tools:
        args += ["--allowedTools", ",".join(task.allowed_tools)]
        args += ["--permission-mode", "acceptEdits"]
    if task.json_schema is not None and task.structured_output:
        args += ["--json-schema", json.dumps(task.json_schema)]
    return args


def run_task(
    task: TaskSpec,
    cfg: CanaryCfg,
    conn: sqlite3.Connection,
    cycle_id: int,
    attempt: int,
    claude_cmd: list[str] | None = None,
    inject_model: str | None = None,
) -> RunRow:
    ts = utcnow_iso()
    session_id = str(uuid.uuid4())

    def _early(
        *,
        terminal_reason: str,
        fail_detail: str,
        session_id: str | None = session_id,
        is_error: int | None = None,
        subtype: str | None = None,
    ) -> RunRow:
        row = RunRow(
            cycle_id=cycle_id,
            task_id=task.task_id,
            attempt=attempt,
            session_id=session_id,
            ts=ts,
            model=cfg.model,
            passed=None,
            invalid=1,
            fail_detail=fail_detail,
            duration_ms=None,
            duration_api_ms=None,
            ttft_ms=None,
            num_turns=None,
            input_tokens=None,
            output_tokens=None,
            cache_read_tokens=None,
            cost_usd=None,
            terminal_reason=terminal_reason,
            is_error=is_error,
            subtype=subtype,
            result_sha=None,
            long_context=task.long_context,
        )
        _insert_run(conn, row)
        return row

    base_cmd = claude_cmd
    if base_cmd is None:
        exe = shutil.which("claude")
        if not exe:
            return _early(
                terminal_reason="claude-not-found",
                fail_detail="claude executable not found on PATH (shutil.which returned None)",
                session_id=None,
            )
        base_cmd = [exe]

    upsert_session(conn, session_id, is_canary=1, started_at=ts)
    conn.commit()

    workspace: Path | None = None
    if task.workspace_template is not None:
        workspace = Path(tempfile.mkdtemp(prefix="vitals-canary-"))
        shutil.copytree(task.workspace_template, workspace, dirs_exist_ok=True)

    try:
        prompt_text = task.prompt
        if task.long_context and "{LOG}" in prompt_text:
            prompt_text = prompt_text.replace("{LOG}", generate_log(NEEDLE_SEED))

        model_for_argv = inject_model or cfg.model
        per_run_budget_usd = task.per_run_budget_usd or cfg.per_run_budget_usd
        args = _build_args(base_cmd, task, cfg, session_id, model_for_argv, per_run_budget_usd)

        env = dict(os.environ)
        env["CLAUDE_CODE_ENABLE_TELEMETRY"] = "0"
        timeout_s = task.per_run_timeout_s or cfg.per_run_timeout_s

        try:
            proc = subprocess.run(
                args,
                input=prompt_text,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                cwd=str(workspace) if workspace else None,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return _early(
                terminal_reason="timeout",
                fail_detail=f"subprocess exceeded the {timeout_s}s timeout",
            )
        except OSError as exc:
            return _early(
                terminal_reason="claude-not-found", fail_detail=f"could not spawn claude: {exc}"
            )

        raw_stdout = proc.stdout or ""
        try:
            data = json.loads(raw_stdout)
        except (ValueError, TypeError) as exc:
            detail = (
                f"could not parse result JSON ({exc}); exit={proc.returncode} "
                f"stdout={raw_stdout[:2000]!r} stderr={(proc.stderr or '')[:2000]!r}"
            )
            return _early(terminal_reason="parse-error", fail_detail=detail)

        if not isinstance(data, dict):
            return _early(
                terminal_reason="parse-error",
                fail_detail=f"result JSON was not an object: {data!r}",
            )

        is_error = bool(data.get("is_error"))
        subtype = data.get("subtype")
        result_text = data.get("result") or ""
        errors = data.get("errors") or []
        duration_ms = data.get("duration_ms")
        duration_api_ms = data.get("duration_api_ms")
        ttft_ms = data.get("ttft_ms")
        num_turns = data.get("num_turns")
        result_sha = hashlib.sha256(raw_stdout.encode("utf-8")).hexdigest()

        input_tokens, output_tokens, cache_read_tokens, cost_usd = _accumulate_usage(
            data, model_for_argv
        )

        if is_error:
            combined_text = " ".join([result_text, *[str(e) for e in errors]]).strip()
            terminal_reason = (
                "auth" if _AUTH_ERROR_RE.search(combined_text) else (subtype or "error")
            )
            row = RunRow(
                cycle_id=cycle_id,
                task_id=task.task_id,
                attempt=attempt,
                session_id=session_id,
                ts=ts,
                model=cfg.model,
                passed=None,
                invalid=1,
                fail_detail=combined_text or "is_error was true with no message text",
                duration_ms=duration_ms,
                duration_api_ms=duration_api_ms,
                ttft_ms=ttft_ms,
                num_turns=num_turns,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cache_read_tokens=cache_read_tokens,
                cost_usd=cost_usd,
                terminal_reason=terminal_reason,
                is_error=1,
                subtype=subtype,
                result_sha=result_sha,
                long_context=task.long_context,
            )
            _insert_run(conn, row)
            return row

        artifacts = RunArtifacts(
            result_text=result_text, structured_output=None, workspace=workspace
        )
        try:
            check = CHECKERS[task.checker](task, artifacts)
        except Exception as exc:
            row = RunRow(
                cycle_id=cycle_id,
                task_id=task.task_id,
                attempt=attempt,
                session_id=session_id,
                ts=ts,
                model=cfg.model,
                passed=None,
                invalid=1,
                fail_detail=(f"checker {task.checker!r} raised {type(exc).__name__}: {exc}"[:2000]),
                duration_ms=duration_ms,
                duration_api_ms=duration_api_ms,
                ttft_ms=ttft_ms,
                num_turns=num_turns,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cache_read_tokens=cache_read_tokens,
                cost_usd=cost_usd,
                terminal_reason="checker-error",
                is_error=0,
                subtype=subtype,
                result_sha=result_sha,
                long_context=task.long_context,
            )
            _insert_run(conn, row)
            return row
        is_infra = check.detail.startswith("INFRA:")
        row = RunRow(
            cycle_id=cycle_id,
            task_id=task.task_id,
            attempt=attempt,
            session_id=session_id,
            ts=ts,
            model=cfg.model,
            passed=None if is_infra else int(check.passed),
            invalid=1 if is_infra else 0,
            fail_detail=None if check.passed and not is_infra else check.detail,
            duration_ms=duration_ms,
            duration_api_ms=duration_api_ms,
            ttft_ms=ttft_ms,
            num_turns=num_turns,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens,
            cost_usd=cost_usd,
            terminal_reason=subtype,
            is_error=0,
            subtype=subtype,
            result_sha=result_sha,
            long_context=task.long_context,
        )
        _insert_run(conn, row)
        return row
    finally:
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)


def _record_suite_change_if_needed(conn: sqlite3.Connection, current_hash: str) -> None:
    previous = kv_get(conn, "canary_suite_hash")
    if previous is not None and previous != current_hash:
        conn.execute(
            "INSERT INTO change_points(ts, kind, old_value, new_value, detail) VALUES (?,?,?,?,?)",
            (utcnow_iso(), "canary_suite", previous, current_hash, None),
        )
        conn.commit()
    kv_set(conn, "canary_suite_hash", current_hash)


def run_cycle(
    conn: sqlite3.Connection,
    cfg: CanaryCfg,
    tasks: list[TaskSpec],
    inject_model: str | None = None,
    claude_cmd: list[str] | None = None,
) -> int:
    started_at = utcnow_iso()
    current_hash = suite_hash(tasks)
    _record_suite_change_if_needed(conn, current_hash)

    cur = conn.execute(
        "INSERT INTO canary_cycles(started_at, model, effort, cc_version, suite_hash) "
        "VALUES (?,?,?,?,?)",
        (started_at, cfg.model, cfg.effort, None, current_hash),
    )
    conn.commit()
    cycle_id = cur.lastrowid

    if not cfg.enabled:
        conn.execute(
            "UPDATE canary_cycles SET finished_at=?, n_runs=0, n_pass=0, n_invalid=0,"
            " pass_rate=NULL, tokens_in=0, tokens_out=0, cost_usd=0, aborted_reason='disabled'"
            " WHERE cycle_id=?",
            (utcnow_iso(), cycle_id),
        )
        conn.commit()
        return cycle_id

    cheap_tasks = [t for t in tasks if not t.long_context]
    long_tasks = [t for t in tasks if t.long_context] if cfg.long_context_daily else []

    n_runs = n_pass = n_invalid = 0
    tokens_in_total = tokens_out_total = 0
    cost_total = 0.0
    aborted_reason: str | None = None

    def _attempt(task: TaskSpec, attempt: int) -> bool:
        nonlocal n_runs, n_pass, n_invalid, tokens_in_total, tokens_out_total, cost_total
        nonlocal aborted_reason

        est_usd = task.per_run_budget_usd or cfg.per_run_budget_usd
        reservation_id = check_and_reserve(conn, cfg, est_usd)
        if reservation_id is None:
            aborted_reason = "budget"
            return False

        try:
            row = run_task(
                task,
                cfg,
                conn,
                cycle_id,
                attempt,
                claude_cmd=claude_cmd,
                inject_model=inject_model,
            )
        except sqlite3.OperationalError as exc:
            settle(conn, reservation_id, 0, 0, est_usd)
            log_ingest(conn, "canary_infra", 0, 1, f"{task.task_id}: run lost to {exc}"[:300])
            return True
        except BaseException:
            settle(conn, reservation_id, 0, 0, est_usd)
            raise
        settle_cost = row.cost_usd if row.cost_usd is not None else est_usd
        settle(conn, reservation_id, row.input_tokens or 0, row.output_tokens or 0, settle_cost)

        tokens_in_total += row.input_tokens or 0
        tokens_out_total += row.output_tokens or 0
        cost_total += settle_cost

        if not task.long_context:
            n_runs += 1
            if row.invalid:
                n_invalid += 1
            elif row.passed:
                n_pass += 1

        if row.terminal_reason in _ABORT_TERMINAL_REASONS:
            aborted_reason = row.terminal_reason
            return False
        return True

    def _finalise_cycle() -> None:
        pass_rate = (n_pass / (n_runs - n_invalid)) if (n_runs - n_invalid) > 0 else None
        try:
            conn.execute(
                "UPDATE canary_cycles SET finished_at=?, n_runs=?, n_pass=?, n_invalid=?,"
                " pass_rate=?, tokens_in=?, tokens_out=?, cost_usd=?, aborted_reason=?"
                " WHERE cycle_id=?",
                (
                    utcnow_iso(),
                    n_runs,
                    n_pass,
                    n_invalid,
                    pass_rate,
                    tokens_in_total,
                    tokens_out_total,
                    cost_total,
                    aborted_reason,
                    cycle_id,
                ),
            )
            conn.commit()
        except sqlite3.Error:  # pragma: no cover
            pass

    try:
        stopped = False
        for task in cheap_tasks:
            for attempt in range(1, cfg.runs_per_task + 1):
                if not _attempt(task, attempt):
                    stopped = True
                    break
            if stopped:
                break

        if not stopped:
            for task in long_tasks:
                if not _attempt(task, 1):
                    stopped = True
                    break
    except BaseException as exc:
        aborted_reason = aborted_reason or f"crashed: {type(exc).__name__}"
        raise
    finally:
        _finalise_cycle()

    return cycle_id
