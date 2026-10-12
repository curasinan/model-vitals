from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
SESSION = "11111111-1111-4111-8111-111111111111"
PROMPT = "22222222-2222-4222-8222-222222222222"


def s(v: str) -> dict:
    return {"stringValue": v}


def i_num(v: int) -> dict:
    return {"intValue": v}


def i_str(v: int) -> dict:
    return {"intValue": str(v)}


def d(v: float) -> dict:
    return {"doubleValue": v}


def record(name: str, ts_ns: int, seq: int, attrs: dict) -> dict:
    base = {
        "user.id": s("0" * 64),
        "session.id": s(SESSION),
        "app.version": s("2.1.226"),
        "terminal.type": s("vscode"),
        "event.name": s(name),
        "event.timestamp": s("2026-08-25T00:40:00.000Z"),
        "event.sequence": i_num(seq),
        "prompt.id": s(PROMPT),
    }
    base.update(attrs)
    return {
        "timeUnixNano": str(ts_ns),
        "observedTimeUnixNano": str(ts_ns),
        "body": s(f"claude_code.{name}"),
        "attributes": [{"key": k, "value": v} for k, v in base.items()],
    }


def main() -> int:
    envelope = json.loads((FIXTURES / "otlp_logs_sample.json").read_text(encoding="utf-8"))
    resource = envelope["resourceLogs"][0]["resource"]
    scope = envelope["resourceLogs"][0]["scopeLogs"][0]["scope"]
    t0 = 1_787_618_400_000_000_000

    records = [
        record(
            "api_request",
            t0,
            1,
            {
                "model": s("claude-sonnet-5"),
                "cost_usd": d(0.0123),
                "cost_usd_micros": i_num(12300),
                "duration_ms": i_num(2400),
                "input_tokens": i_num(1200),
                "output_tokens": i_str(350),
                "cache_read_tokens": i_num(8000),
                "cache_creation_tokens": i_num(0),
                "request_id": s("req_synth_001"),
                "speed": s("normal"),
                "query_source": s("main"),
                "effort": s("medium"),
            },
        ),
        record(
            "api_request",
            t0 + 60_000_000_000,
            2,
            {
                "model": s("claude-sonnet-5"),
                "cost_usd": d(0.91),
                "duration_ms": d(15400.5),
                "input_tokens": i_num(4000),
                "output_tokens": i_num(900),
                "cache_read_tokens": i_str(185000),
                "cache_creation_tokens": i_num(1200),
                "request_id": s("req_synth_002"),
                "speed": s("normal"),
                "query_source": s("main"),
                "effort": s("high"),
            },
        ),
        record(
            "tool_result",
            t0 + 5_000_000_000,
            3,
            {
                "tool_name": s("Edit"),
                "tool_use_id": s("toolu_synth_edit_1"),
                "success": s("true"),
                "duration_ms": i_num(120),
                "tool_input_size_bytes": i_num(2048),
                "tool_result_size_bytes": i_num(64),
                "decision_source": s("config"),
            },
        ),
        record(
            "tool_result",
            t0 + 6_000_000_000,
            4,
            {
                "tool_name": s("Bash"),
                "tool_use_id": s("toolu_synth_bash_1"),
                "success": s("false"),
                "duration_ms": i_num(3300),
                "error_type": s("command_failed"),
                "decision_source": s("user_permanent"),
            },
        ),
        record(
            "compaction",
            t0 + 120_000_000_000,
            5,
            {
                "trigger": s("auto"),
                "success": s("true"),
                "duration_ms": i_num(8200),
                "pre_tokens": i_num(178_000),
                "post_tokens": i_num(42_000),
            },
        ),
        record(
            "api_retries_exhausted",
            t0 + 180_000_000_000,
            6,
            {
                "model": s("claude-sonnet-5"),
                "error": s("529 Overloaded"),
                "status_code": i_num(529),
                "total_attempts": i_num(4),
                "total_retry_duration_ms": i_num(21000),
            },
        ),
        record(
            "api_error",
            t0 + 181_000_000_000,
            7,
            {
                "model": s("claude-sonnet-5"),
                "error": s("429 rate_limit_error"),
                "status_code": i_str(429),
                "duration_ms": i_num(90),
                "attempt": i_num(1),
                "query_source": s("main"),
            },
        ),
    ]

    body = {
        "resourceLogs": [
            {
                "resource": resource,
                "scopeLogs": [{"scope": scope, "logRecords": records}],
            }
        ]
    }
    dest = FIXTURES / "otlp_logs_synthetic.json"
    dest.write_text(json.dumps(body, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {dest} with {len(records)} synthetic records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
