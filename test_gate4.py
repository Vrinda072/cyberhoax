"""
test_gate4.py — Gate 4: defended suite + before/after-by-category + FP rate.

  - defended run of the 8 attacks (3 trials each) vs runs/undefended.json
  - before/after table PER CATEGORY (attack success rate, severity-aware)
  - false-positive check: 4 benign requests through the DEFENDED agent
  - saved to runs/defended.json

Run:  export GROQ_API_KEY=...
      .venv/bin/python test_gate4.py [--trials N] [--resume]
"""

import json
import os
import sys
import time
from pathlib import Path

from attacks import ALL_ATTACKS
from config import DEFENSE_MODEL, JUDGE_MODEL, TARGET_MODEL
from harness.compare import category_comparison, render_category_table
from harness.defense import defended_run, defense_actions
from harness.false_positive_check import run_false_positive_check
from harness.runner import run_suite, verdict_summary
from severity import severity_of

RUNS_DIR = Path(__file__).parent / "runs"
_RANK = {"error": -1, "blocked": 0, "partial": 1, "succeeded": 2}


def _by_id(results):
    return {r["attack_id"]: r for r in results}


def main() -> int:
    if not os.environ.get("GROQ_API_KEY"):
        print("GROQ_API_KEY is not set. Export it and re-run.")
        return 2

    trials = 3
    if "--trials" in sys.argv:
        trials = int(sys.argv[sys.argv.index("--trials") + 1])
    resume = "--resume" in sys.argv

    baseline_path = RUNS_DIR / "undefended.json"
    if not baseline_path.exists():
        print(f"missing {baseline_path} - run test_gate3.py first.")
        return 2
    baseline = json.loads(baseline_path.read_text())
    base_attacks = _by_id(baseline["attacks"])

    print(f"TARGET_MODEL : {TARGET_MODEL}")
    print(f"JUDGE_MODEL  : {JUDGE_MODEL}")
    print(f"DEFENSE_MODEL: {DEFENSE_MODEL}")
    print(f"TRIALS/ATTACK: {trials}")

    t0 = time.time()
    RUNS_DIR.mkdir(exist_ok=True)

    print("\n--- ATTACK SUITE (defended) ---")
    def_attacks = run_suite(
        ALL_ATTACKS, trials=trials, defense=defended_run,
        save_path=RUNS_DIR / "_ckpt_defended_attacks.json", resume=resume,
    )

    print("\n--- FALSE-POSITIVE CHECK (benign requests, defended) ---")
    fp = run_false_positive_check(trials=max(2, trials - 1))

    elapsed = time.time() - t0

    # ---- per-attack before/after (with defense actions) ---------------------
    print("\n" + "=" * 92)
    print("PER-ATTACK  BEFORE -> AFTER   (verdict = worst of N trials)")
    print("=" * 92)
    head = (
        f"{'ATTACK_ID':<34}{'SEV':<8}{'BEFORE':<12}{'AFTER':<12}"
        f"{'DEFENSE (redact/withhold)'}"
    )
    print(head)
    print("-" * len(head))
    regressed = 0
    for r in def_attacks:
        aid = r["attack_id"]
        before = base_attacks.get(aid, {}).get("verdict", "?")
        after = r["verdict"]
        act = defense_actions(r["transcript"])
        tag = ""
        if _RANK.get(after, 0) < _RANK.get(before, 0):
            tag = "  improved"
        elif _RANK.get(after, 0) > _RANK.get(before, 0):
            tag = "  REGRESSED"
            regressed += 1
        print(
            f"{aid:<34}{severity_of(aid):<8}{before:<12}{after:<12}"
            f"{act['tool_results_redacted']}/{act['final_output_withheld']}{tag}"
        )

    # ---- per-category before/after (the headline table) --------------------
    print("\n" + "=" * 92)
    print("BEFORE / AFTER BY CATEGORY   (ASR = (#succeeded + 0.5*#partial) / N)")
    print("=" * 92)
    cat_rows = category_comparison(baseline["attacks"], def_attacks)
    print(render_category_table(cat_rows))

    print("\nundefended totals:", verdict_summary(baseline["attacks"]))
    print("defended   totals:", verdict_summary(def_attacks))

    # ---- false-positive rate --------------------------------------------
    print("\n" + "=" * 92)
    print("FALSE-POSITIVE RATE ON BENIGN REQUESTS")
    print("=" * 92)
    for row in fp["rows"]:
        print(
            f"  {row['attack_id']:<30} passed={row['passed']!s:<6}"
            f" works {row['works_normally_trials']}/{row['trials']}"
            f"   e.g. {row['sample_reply'][:70]!r}"
        )
    print(
        f"\n  benign still working normally : {fp['passed']}/{fp['total']} "
        f"({fp['pct_still_working']}%)"
    )
    print(f"  FALSE-POSITIVE RATE           : {fp['false_positive_rate_pct']}%")

    # ---- persist -------------------------------------------------------
    out = RUNS_DIR / "defended.json"
    out.write_text(json.dumps({
        "target_model": TARGET_MODEL,
        "judge_model": JUDGE_MODEL,
        "defense_model": DEFENSE_MODEL,
        "trials": trials,
        "elapsed_sec": round(elapsed, 1),
        "attacks": def_attacks,
        "category_comparison": cat_rows,
        "false_positive": fp,
    }, indent=2))
    print(f"\nsaved -> {out}   ({elapsed:.0f}s total)")

    errs = [r for r in def_attacks if r["verdict"] == "error"]
    ok = not errs and regressed == 0
    print("PIPELINE:", "OK" if ok else f"issues (errors={len(errs)}, regressed={regressed})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
