"""Gate a Terraform plan in CI.

    terraform plan -out=tf.plan
    terraform show -json tf.plan > plan.json
    python -m plan_gate plan.json --fail-on block --comment comment.md

Exit code 0 when the plan passes, 1 when it does not. The exit code comes
from the rules alone; the model, if it is reachable, only adds prose to the
comment.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .explain import explain
from .rules import BLOCK, NOTE, WARN, evaluate, verdict

ICON = {BLOCK: "🚫", WARN: "⚠️", NOTE: "ℹ️"}


def render(findings, counts, passed, prose: str | None, plan_path: str) -> str:
    lines = [f"## Terraform plan gate: {'pass' if passed else 'fail'}", ""]
    if not findings:
        lines += [f"No blocking, warning or note-level findings in `{plan_path}`.", ""]
        return "\n".join(lines)
    lines += [
        f"{counts[BLOCK]} blocking, {counts[WARN]} warning, {counts[NOTE]} note "
        f"from `{plan_path}`.",
        "",
        "| | Resource | Rule | What the plan does |",
        "| --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(f"| {ICON[f.severity]} | `{f.address}` | {f.rule} | {f.summary} |")
    lines.append("")
    if prose:
        lines += ["### What this means", "", prose, ""]
    lines += [
        "<details><summary>Findings as JSON</summary>",
        "",
        "```json",
        json.dumps([f.as_dict() for f in findings], indent=2),
        "```",
        "",
        "</details>",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="plan_gate", description=__doc__)
    parser.add_argument("plan", help="JSON from `terraform show -json <planfile>`")
    parser.add_argument("--fail-on", choices=[BLOCK, WARN, NOTE], default=BLOCK,
                        help="lowest severity that fails the job (default: block)")
    parser.add_argument("--comment", help="write the Markdown comment to this file")
    parser.add_argument("--json", dest="json_out", help="write the findings to this file")
    parser.add_argument("--no-explain", action="store_true", help="skip the model even when a key is set")
    args = parser.parse_args(argv)

    try:
        plan = json.loads(Path(args.plan).read_text())
    except (OSError, json.JSONDecodeError) as err:
        print(f"plan_gate: cannot read {args.plan}: {err}", file=sys.stderr)
        return 2

    findings = evaluate(plan)
    passed, counts = verdict(findings, args.fail_on)
    prose = None
    if findings and not args.no_explain:
        prose = explain([f.as_dict() for f in findings])

    comment = render(findings, counts, passed, prose, args.plan)
    if args.comment:
        Path(args.comment).write_text(comment)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps([f.as_dict() for f in findings], indent=2))
    print(comment)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as handle:
            handle.write(f"passed={'true' if passed else 'false'}\n")
            handle.write(f"blocking={counts[BLOCK]}\nwarnings={counts[WARN]}\nnotes={counts[NOTE]}\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
