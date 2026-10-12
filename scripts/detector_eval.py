from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from corpus.evaluate import (
    GATING_PROFILE,
    GATING_WORLD,
    PROFILES,
    WORLDS,
    dump_metrics,
    run_eval,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detector_eval",
        description="Run the real detector chain in one world and report Gate 1's metrics.",
    )
    parser.add_argument(
        "--world",
        default=GATING_WORLD,
        choices=sorted(WORLDS),
        help="; ".join(f"{name}: {why}" for name, why in sorted(WORLDS.items())),
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help=(
            "directory holding the corpus Parquet files. Required for --world real; ignored"
            " for --world synthetic, which builds its corpus in code."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="where to write the metrics JSON. Required unless --summarize is given.",
    )
    parser.add_argument(
        "--profile",
        default=GATING_PROFILE,
        choices=sorted(PROFILES),
        help="; ".join(f"{name}: {why}" for name, why in sorted(PROFILES.items())),
    )
    parser.add_argument(
        "--augment-baselines",
        action="store_true",
        help=(
            "densify baseline history before the earliest perturbed hour so a stratum the"
            " corpus leaves too sparse can form a baseline. Off by default: an augmented number"
            " is not a measurement of the corpus as committed. Recorded under lowering.augmented."
        ),
    )
    parser.add_argument(
        "--summarize",
        type=Path,
        default=None,
        metavar="METRICS_JSON",
        help=(
            "read a metrics JSON a previous --out run already wrote and print a compact"
            " per-world summary table to stdout -- for piping into $GITHUB_STEP_SUMMARY,"
            ' e.g. `detector_eval.py --summarize metrics.json >> "$GITHUB_STEP_SUMMARY"`.'
            " No evaluation runs in this mode: --world/--corpus/--profile/--augment-baselines"
            " are ignored, and --out is not required."
        ),
    )
    return parser


def headline(metrics: dict) -> str:
    gate = metrics["gate1"]
    role = "GATING" if gate["gating"] else "measured, non-gating"
    verdict = "PASS" if gate["structural_pass"] else "FAIL"
    version = metrics["corpus"].get("synthetic_world_version")
    stamp = f" world_version={version}" if version else ""
    return (
        f"world={metrics['world']}{stamp} profile={metrics['profile']}"
        f" [{role}] structural_pass={verdict}"
    )


def summarize(metrics: dict) -> str:
    classes: dict = metrics["classes"]
    clean: dict = metrics["clean"]
    lines = [f"#### {headline(metrics)}", ""]
    lines.append("| class | recall | clear_fired | clear_attributed |")
    lines.append("|---|---|---|---|")
    for letter, block in sorted(classes.items()):
        lines.append(
            f"| {letter} | {block['recall']:.4f} | {block['clear_fired']} |"
            f" {block['clear_attributed']} |"
        )
    lines.append("")
    lines.append(f"clean.fp_count: {clean['fp_count']}")

    limitations = metrics.get("limitations") or []
    if limitations:
        lines.append("")
        lines.append("limitations:")
        lines.extend(f"- {note}" for note in limitations)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.summarize is not None:
        metrics = json.loads(args.summarize.read_text(encoding="utf-8"))
        sys.stdout.write(summarize(metrics))
        return 0

    if args.out is None:
        parser.error("--out is required unless --summarize is given")

    metrics = run_eval(
        args.corpus,
        world=args.world,
        profile_name=args.profile,
        augment_baselines=args.augment_baselines,
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(dump_metrics(metrics), encoding="utf-8")

    gate = metrics["gate1"]
    violations = list(gate["failures"]) + list(gate["observations"])
    gating = bool(gate["gating"])
    failed = gating and not gate["structural_pass"]
    stream = sys.stderr if failed else sys.stdout

    print(headline(metrics), file=stream)
    if violations:
        label = "failure" if gating else "observation"
        print(f"  {len(violations)} structural {label}(s):", file=stream)
        for violation in violations:
            print(f"    {violation}", file=stream)
    for note in metrics["limitations"]:
        print(f"  limitation: {note}", file=stream)
    print(f"  metrics written to {out}", file=stream)

    if failed:
        return 1
    if violations:
        print(
            f"  exit 0: only (world={GATING_WORLD}, profile={GATING_PROFILE}) gates -- the"
            " violations above are published data, not a verdict",
            file=stream,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
