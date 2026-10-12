from __future__ import annotations

import random

__all__ = [
    "CHARS_PER_TOKEN",
    "EDIT_CONST_NAME",
    "EDIT_NEW_VALUE",
    "EDIT_OLD_VALUE",
    "EDIT_SEED",
    "EDIT_TARGET_LINES",
    "NEEDLE_SEED",
    "format_expected_answer",
    "generate_log",
    "generate_module",
    "planted_answers",
    "solved_module",
]


NEEDLE_SEED = 1
CHARS_PER_TOKEN = 4

_STATUSES = ("DELIVERED", "CANCELLED", "SHIPPED", "PENDING", "REFUNDED", "BACKORDERED")
_SERVICES = ("checkout", "inventory", "shipping", "billing", "notifications", "auth")
_DECOY_ERROR_CLASSES = (
    "DatabaseConnectionLost",
    "RateLimitExceeded",
    "AuthTokenExpired",
    "DiskQuotaExceeded",
    "CacheMiss",
    "SchemaValidationFailed",
)
_TARGET_ERROR_CLASS = "PaymentGatewayTimeout"
_ALL_ERROR_CLASSES = _DECOY_ERROR_CLASSES + (_TARGET_ERROR_CLASS,)

_DEPTH_FRACTIONS = (0.10, 0.50, 0.90)


def _build_log(seed: int, target_tokens: int) -> tuple[str, dict]:
    rng = random.Random(seed)
    target_chars = target_tokens * CHARS_PER_TOKEN

    target_ids: list[str] = []
    while len(target_ids) < 3:
        candidate = f"ORDER-{rng.randint(100_000, 999_999)}"
        if candidate not in target_ids:
            target_ids.append(candidate)
    reserved_ids = set(target_ids)
    target_statuses = [rng.choice(_STATUSES) for _ in range(3)]

    lines: list[str] = []
    length = 0
    seq = 0
    elapsed = 0
    error_count = 0

    def _prefix() -> str:
        nonlocal seq, elapsed
        seq += 1
        elapsed += rng.randint(2, 6)
        return f"[seq={seq:06d} t+{elapsed:05d}s]"

    def _draw_noise_order_id() -> str:
        while True:
            candidate = f"ORDER-{rng.randint(100_000, 999_999)}"
            if candidate not in reserved_ids:
                return candidate

    def _append(line: str) -> None:
        nonlocal length
        lines.append(line)
        length += len(line) + 1

    def _emit_noise() -> None:
        nonlocal error_count
        prefix = _prefix()
        svc = rng.choice(_SERVICES)
        roll = rng.random()
        if roll < 0.45:
            oid = _draw_noise_order_id()
            amount = rng.randint(500, 99_999) / 100
            _append(f"{prefix} INFO  svc={svc} event=order_created order={oid} amount={amount:.2f}")
        elif roll < 0.70:
            oid = _draw_noise_order_id()
            status = rng.choice(_STATUSES)
            _append(f"{prefix} INFO  svc={svc} event=status_change order={oid} status={status}")
        elif roll < 0.95:
            sku = rng.randint(1000, 9999)
            qty = rng.randint(1, 500)
            _append(f"{prefix} DEBUG svc={svc} event=stock_check sku=SKU-{sku} qty={qty}")
        else:
            oid = _draw_noise_order_id()
            klass = rng.choice(_ALL_ERROR_CLASSES)
            if klass == _TARGET_ERROR_CLASS:
                error_count += 1
            _append(
                f"{prefix} ERROR svc={svc} event=error class={klass} order={oid} "
                f'msg="operation failed"'
            )

    def _emit_planted_status(idx: int) -> None:
        prefix = _prefix()
        svc = rng.choice(_SERVICES)
        _append(
            f"{prefix} INFO  svc={svc} event=status_change "
            f"order={target_ids[idx]} status={target_statuses[idx]}"
        )

    def _emit_config_rotated() -> None:
        prefix = _prefix()
        _append(f"{prefix} INFO  svc=configd event=CONFIG_ROTATED file=app.yaml")

    def _grow_until(fraction: float) -> None:
        threshold = fraction * target_chars
        while length < threshold:
            _emit_noise()

    _grow_until(_DEPTH_FRACTIONS[0])
    _emit_planted_status(0)
    _grow_until(_DEPTH_FRACTIONS[1])
    _emit_config_rotated()
    _emit_planted_status(1)
    _grow_until(_DEPTH_FRACTIONS[2])
    _emit_planted_status(2)
    _grow_until(1.0)

    text = "\n".join(lines) + "\n"
    answers = {
        "orders": [{"id": target_ids[i], "status": target_statuses[i]} for i in range(3)],
        "error_class": _TARGET_ERROR_CLASS,
        "error_count": error_count,
    }
    return text, answers


def generate_log(seed: int, target_tokens: int = 100_000) -> str:
    text, _ = _build_log(seed, target_tokens)
    return text


def planted_answers(seed: int, target_tokens: int = 100_000) -> dict:
    _, answers = _build_log(seed, target_tokens)
    return answers


def format_expected_answer(answers: dict) -> str:
    lines = [f"{order['id']}: {order['status']}" for order in answers["orders"]]
    lines.append(f"{answers['error_class']}: {answers['error_count']}")
    return "\n".join(lines) + "\n"


EDIT_SEED = 1
EDIT_CONST_NAME = "MAX_POOL_SIZE"
EDIT_OLD_VALUE = 12
EDIT_NEW_VALUE = 48
EDIT_TARGET_LINES = 3_000

_VERBS = (
    "compute",
    "resolve",
    "normalize",
    "flatten",
    "merge",
    "extract",
    "validate",
    "transform",
    "aggregate",
    "dispatch",
    "reconcile",
    "hydrate",
)
_NOUNS = (
    "payload",
    "batch",
    "record",
    "entry",
    "chunk",
    "frame",
    "packet",
    "segment",
    "token",
    "window",
    "cursor",
    "shard",
)


def _filler_lines(rng: random.Random, idx: int) -> list[str]:
    verb = rng.choice(_VERBS)
    noun = rng.choice(_NOUNS)
    a = rng.randint(1, 50)
    b = rng.randint(2, 19)
    name = f"{verb}_{noun}_{idx:04d}"
    return [
        f"def {name}(value: int) -> int:",
        f'    """Auto-generated helper {idx:04d}."""',
        f"    total = (value + {a}) * {b}",
        "    return total % 9973",
        "",
        "",
    ]


def _usage_lines(rng: random.Random, idx: int, const_value: int) -> list[str]:
    verb = rng.choice(_VERBS)
    name = f"pool_guard_{verb}_{idx:04d}"
    return [
        f"def {name}(load: int) -> bool:",
        '    """Reject additional work once the pool is saturated."""',
        f"    return load >= {const_value}  # {EDIT_CONST_NAME}",
        "",
        "",
    ]


def _module_lines(seed: int, target_lines: int, const_value: int) -> list[str]:
    rng = random.Random(seed)
    lines: list[str] = [
        '"""Auto-generated synthetic service module (deterministic canary fixture).',
        "",
        "Every function below is generated filler with no real behavior; only the",
        f"{EDIT_CONST_NAME} constant and its three marked usages matter for this task.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "",
        f"{EDIT_CONST_NAME} = {const_value}  # default pool size",
        "",
        "",
    ]

    usage_at = sorted(
        (int(target_lines * frac), u_idx) for u_idx, frac in enumerate((0.20, 0.50, 0.80))
    )

    filler_idx = 0
    while usage_at or len(lines) < target_lines:
        if usage_at and len(lines) >= usage_at[0][0]:
            _, u_idx = usage_at.pop(0)
            lines.extend(_usage_lines(rng, u_idx, const_value))
            continue
        lines.extend(_filler_lines(rng, filler_idx))
        filler_idx += 1

    return lines


def generate_module(seed: int = EDIT_SEED, target_lines: int = EDIT_TARGET_LINES) -> str:
    return "\n".join(_module_lines(seed, target_lines, EDIT_OLD_VALUE)) + "\n"


def solved_module(seed: int = EDIT_SEED, target_lines: int = EDIT_TARGET_LINES) -> str:
    return "\n".join(_module_lines(seed, target_lines, EDIT_NEW_VALUE)) + "\n"
