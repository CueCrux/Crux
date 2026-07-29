#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
"""Merge cargo-mutants shard outputs, score them, and ratchet against a baseline.

Used by .github/workflows/mutants.yml (merge job) and runnable locally:

    python3 scripts/mutants-report.py --outs mutants.out [shard2 ...] \
        --baseline .github/mutants-baseline.txt \
        [--summary "$GITHUB_STEP_SUMMARY"] [--write-baseline NEWFILE]

Each --outs directory is a cargo-mutants output dir containing caught.txt,
missed.txt, timeout.txt, unviable.txt (one mutant per line, formatted
"path:line:col: description").

Survivors are ratcheted as missed+timeout (a mutant drifting from missed to
timeout must not look like progress). Mutant identity is normalised to
"path: description" — line:col are stripped so
unrelated edits do not churn the baseline. Identical mutations of the same kind
inside one function (e.g. three `||`->`&&` in the same fn) collapse to one
normalised string; we track multiplicity, and a survivor is "new" only when its
current count exceeds the baseline count. Known limitation: within one bucket,
a swap (one old survivor caught while a different same-description mutant
appears) keeps the count equal and stays green — this is a count ratchet per
bucket, not per-mutant identity.

Each --outs dir must contain at least one category file — a dir with none is
an input error, not a clean run (guards against cargo-mutants output-layout
drift silently zeroing the report). --expect-min-viable N additionally fails
if caught+missed+timeout < N (nightly sanity floor; do not pass it for small
--in-diff runs).

Exit codes: 0 = no new survivors; 2 = new survivors (regression vs baseline);
1 = usage/input error. Baseline entries that are no longer missed never fail
the run — they are listed (split into now-caught / now-unviable / now-timeout /
no-longer-generated) so the baseline can be ratcheted down deliberately.
"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

LINE_RE = re.compile(r"^(?P<path>[^:]+):\d+:\d+: (?P<desc>.+)$")

CATEGORIES = ("caught", "missed", "timeout", "unviable")


def normalise(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None
    m = LINE_RE.match(line)
    if not m:
        # Tolerate lines without line:col (already-normalised baselines).
        return line
    return f"{m.group('path')}: {m.group('desc')}"


def read_category(out_dirs: list[Path], name: str) -> Counter:
    counts: Counter = Counter()
    for d in out_dirs:
        f = d / f"{name}.txt"
        if not f.is_file():
            continue
        for raw in f.read_text().splitlines():
            n = normalise(raw)
            if n:
                counts[n] += 1
    return counts


def read_baseline(path: Path) -> Counter:
    counts: Counter = Counter()
    if not path.is_file():
        return counts
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        n = normalise(line)
        if n:
            counts[n] += 1
    return counts


def crate_of(mutant: str) -> str:
    parts = mutant.split("/")
    return parts[1] if len(parts) > 1 and parts[0] == "crates" else "(other)"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--outs", nargs="+", required=True, type=Path,
                    help="one or more mutants.out directories (shards)")
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--summary", type=Path, default=None,
                    help="append a markdown report here (e.g. $GITHUB_STEP_SUMMARY)")
    ap.add_argument("--write-baseline", type=Path, default=None,
                    help="write the current survivor set as a new baseline file")
    ap.add_argument("--expect-min-viable", type=int, default=None,
                    help="fail if caught+missed+timeout is below this floor "
                         "(sanity check for full nightly runs)")
    args = ap.parse_args()

    missing = [d for d in args.outs if not d.is_dir()]
    if missing:
        print(f"error: not a directory: {', '.join(map(str, missing))}", file=sys.stderr)
        return 1
    for d in args.outs:
        if not any((d / f"{name}.txt").is_file() for name in CATEGORIES):
            print(f"error: {d} contains no cargo-mutants category files "
                  f"({', '.join(f'{n}.txt' for n in CATEGORIES)}) — output layout "
                  "changed or the run died before writing results", file=sys.stderr)
            return 1

    cats = {name: read_category(args.outs, name) for name in CATEGORIES}
    caught_n = sum(cats["caught"].values())
    missed_n = sum(cats["missed"].values())
    timeout_n = sum(cats["timeout"].values())
    unviable_n = sum(cats["unviable"].values())
    viable = caught_n + missed_n + timeout_n
    score = (100.0 * caught_n / viable) if viable else 0.0

    if args.expect_min_viable is not None and viable < args.expect_min_viable:
        print(f"error: only {viable} viable mutants tested, expected >= "
              f"{args.expect_min_viable} — results are partial or the output "
              "format drifted", file=sys.stderr)
        return 1

    baseline = read_baseline(args.baseline)
    # A timeout is a survivor for ratchet purposes: a mutant that flips from
    # missed to timing-out must not read as "greener" (codex review 2026-07-19).
    survivors = cats["missed"] + cats["timeout"]
    new = survivors - baseline       # counts above baseline
    fixed = baseline - survivors     # baseline entries no longer surviving

    crates = sorted({crate_of(m) for c in cats.values() for m in c})
    lines = ["# Mutation report (trust core)", ""]
    lines.append(f"| metric | count |")
    lines.append(f"|---|---|")
    lines.append(f"| caught | {caught_n} |")
    lines.append(f"| missed (survivors) | {missed_n} |")
    lines.append(f"| timeout | {timeout_n} |")
    lines.append(f"| unviable | {unviable_n} |")
    lines.append(f"| **mutation score** | **{score:.1f}%** |")
    lines.append("")
    lines.append("| crate | caught | missed | score |")
    lines.append("|---|---|---|---|")
    for crate in crates:
        c = sum(v for k, v in cats["caught"].items() if crate_of(k) == crate)
        m = sum(v for k, v in cats["missed"].items() if crate_of(k) == crate)
        t = sum(v for k, v in cats["timeout"].items() if crate_of(k) == crate)
        denom = c + m + t
        s = f"{100.0 * c / denom:.1f}%" if denom else "n/a"
        lines.append(f"| {crate} | {c} | {m} | {s} |")
    lines.append("")

    if new:
        lines.append(f"## ❌ {sum(new.values())} NEW survivor(s) vs baseline (missed + timeout)")
        lines.append("")
        for m in sorted(new):
            lines.append(f"- `{m}` (x{new[m]})")
        lines.append("")
        lines.append("Kill each with a test, or (only for genuinely inert code) add it to "
                     "`.github/mutants-baseline.txt` with a justification in the PR.")
    else:
        lines.append("## ✅ No new survivors vs baseline")
    lines.append("")

    if fixed:
        # "No longer missed" is not necessarily "caught": the mutant may have
        # become unviable, timed out, or stopped being generated after a code
        # change. Say which, so ratcheting the baseline down is a deliberate act.
        def disposition(m: str) -> str:
            if m in cats["caught"]:
                return "now caught"
            if m in cats["unviable"]:
                return "now UNVIABLE — verify before removing"
            if m in cats["timeout"]:
                return "now times out — verify before removing"
            return "no longer generated (code changed?)"

        lines.append(f"## Ratchet down: {sum(fixed.values())} baseline survivor(s) no longer missed")
        lines.append("")
        for m in sorted(fixed):
            lines.append(f"- `{m}` (x{fixed[m]}) — {disposition(m)}")
        lines.append("")
        lines.append("Remove the *now caught* ones from `.github/mutants-baseline.txt` "
                     "to lock in the gain; investigate the rest before removing.")
        lines.append("")

    report = "\n".join(lines)
    print(report)
    if args.summary:
        with args.summary.open("a") as fh:
            fh.write(report + "\n")

    if args.write_baseline:
        with args.write_baseline.open("w") as fh:
            fh.write("# cargo-mutants survivor baseline (normalised: path: description).\n")
            fh.write("# Regenerate: scripts/mutants-report.py --outs mutants.out "
                     "--baseline <this> --write-baseline <this>\n")
            for m in sorted(survivors.elements()):
                fh.write(m + "\n")

    return 2 if new else 0


if __name__ == "__main__":
    sys.exit(main())
