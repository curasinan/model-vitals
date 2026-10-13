from __future__ import annotations

S1_LATENCY_P95 = "api_latency_p95"
S1B_LATENCY_P50 = "api_latency_p50"
S2_ERROR_RATE = "api_error_rate"
S3_RETRY_RATE = "api_retry_rate"
S4_TOOL_FAIL_EDIT = "tool_fail_rate_edit"
S4_TOOL_FAIL_WRITE = "tool_fail_rate_write"
S4_TOOL_FAIL_BASH = "tool_fail_rate_bash"
S4_TOOL_FAIL_ALL = "tool_fail_rate_all"
S5_EDIT_LOOP_RATE = "edit_loop_rate"
S6_TEST_FAIL_AFTER_EDIT = "test_fail_after_edit_rate"
S7_SELF_CORR_RATE = "self_corr_rate"
S8_OUTPUT_TOKENS = "output_tokens_per_req"
S9_POST_COMPACTION_FAIL = "post_compaction_fail_rate"

C1_CANARY_PASS = "canary_pass_rate"
C2_CANARY_LONGCTX = "canary_longctx_pass"
C3_CANARY_LATENCY = "canary_latency_p50"
C3_CANARY_TOKENS = "canary_tokens_out"

FAMILY: dict[str, str] = {
    S1_LATENCY_P95: "latency",
    S1B_LATENCY_P50: "latency",
    S2_ERROR_RATE: "errors",
    S3_RETRY_RATE: "errors",
    S4_TOOL_FAIL_EDIT: "tooling",
    S4_TOOL_FAIL_WRITE: "tooling",
    S4_TOOL_FAIL_BASH: "tooling",
    S4_TOOL_FAIL_ALL: "tooling",
    S5_EDIT_LOOP_RATE: "tooling-loops",
    S6_TEST_FAIL_AFTER_EDIT: "tests",
    S7_SELF_CORR_RATE: "weak",
    S8_OUTPUT_TOKENS: "verbosity",
    S9_POST_COMPACTION_FAIL: "context",
    C1_CANARY_PASS: "canary",
    C2_CANARY_LONGCTX: "canary",
    C3_CANARY_LATENCY: "canary-aux",
    C3_CANARY_TOKENS: "canary-aux",
}

WEAK_SIGNALS = frozenset({S7_SELF_CORR_RATE})

HARMFUL_DIRECTION: dict[str, str] = {
    S1_LATENCY_P95: "up",
    S1B_LATENCY_P50: "up",
    S2_ERROR_RATE: "up",
    S3_RETRY_RATE: "up",
    S4_TOOL_FAIL_EDIT: "up",
    S4_TOOL_FAIL_WRITE: "up",
    S4_TOOL_FAIL_BASH: "up",
    S4_TOOL_FAIL_ALL: "up",
    S5_EDIT_LOOP_RATE: "up",
    S6_TEST_FAIL_AFTER_EDIT: "up",
    S7_SELF_CORR_RATE: "up",
    S9_POST_COMPACTION_FAIL: "up",
    C1_CANARY_PASS: "down",
    C2_CANARY_LONGCTX: "down",
    C3_CANARY_LATENCY: "up",
}


def degrades(signal: str, direction: str | None) -> bool:
    harmful = HARMFUL_DIRECTION.get(signal)
    return harmful is None or direction is None or direction == harmful


RATE_SIGNALS = frozenset(
    {
        S2_ERROR_RATE,
        S3_RETRY_RATE,
        S7_SELF_CORR_RATE,
        S4_TOOL_FAIL_EDIT,
        S4_TOOL_FAIL_WRITE,
        S4_TOOL_FAIL_BASH,
        S4_TOOL_FAIL_ALL,
        S5_EDIT_LOOP_RATE,
        S6_TEST_FAIL_AFTER_EDIT,
        C1_CANARY_PASS,
        C2_CANARY_LONGCTX,
    }
)

PASSIVE_SIGNALS = tuple(s for s in FAMILY if not s.startswith("canary"))
