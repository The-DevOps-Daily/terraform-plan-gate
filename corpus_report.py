"""Reproduce the numbers in the README from corpus/."""
import json, pathlib, sys
from plan_gate.rules import evaluate, verdict, BLOCK, WARN

rows = []
for f in sorted(pathlib.Path("corpus").glob("*.json")):
    label, name = f.stem.split("__")
    findings = evaluate(json.loads(f.read_text()))
    rows.append((name, label, not verdict(findings, BLOCK)[0], not verdict(findings, WARN)[0],
                 ",".join(sorted({x.rule for x in findings})) or "-"))

print(f"{'case':24s} {'label':10s} {'fail-on=block':14s} {'fail-on=warn':13s} rules fired")
for n, l, b, w, r in rows:
    print(f"{n:24s} {l:10s} {'STOP' if b else 'pass':14s} {'STOP' if w else 'pass':13s} {r}")

for name, i in (("block", 2), ("warn", 3)):
    tp = sum(1 for r in rows if r[1] == "dangerous" and r[i])
    fn = sum(1 for r in rows if r[1] == "dangerous" and not r[i])
    fp = sum(1 for r in rows if r[1] == "routine" and r[i])
    tn = sum(1 for r in rows if r[1] == "routine" and not r[i])
    print(f"\nfail-on={name}: stopped {tp}/{tp+fn} dangerous, {fp} false alarms out of {fp+tn} routine plans")
    if fn:
        print("  missed:", ", ".join(r[0] for r in rows if r[1] == "dangerous" and not r[i]))
    if fp:
        print("  false alarms:", ", ".join(r[0] for r in rows if r[1] == "routine" and r[i]))
