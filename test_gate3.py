"""
test_gate3.py — Gate 3: run the full attack suite UNDEFENDED.

  - 8 attacks (direct x2, indirect x2, tool_misuse x2, exfiltration x2)
  - each run `--trials` times (default 3); worst-case verdict reported
  - 4 benign requests as a false-positive check
  - results table printed and saved to runs/undefended.json

Run:  export GROQ_API_KEY=...
      .venv/bin/python test_gate3.py [--trials N]
"""

import json
import os
import sys
import time
from pathlib import Path

from attacks import ALL_ATTACKS
from attacks.benign import BENIGN_REQUESTS
from config import JUDGE_MODEL, TARGET_MODEL
from harness.runner import results_table, run_suite, verdict_summary
from severity import rationale_of

RUNS_DIR = Path(__file__).parent / "runs"


def main() -> int:
    if not os.environ.get("GROQ_API_KEY"):
        print("GROQ_API_KEY is not set. Export it and re-run.")
        return 2

    trials = 3
    if "--trials" in sys.argv:
        trials = int(sys.argv[sys.argv.index("--trials") + 1])
    resume = "--resume" in sys.argv

    print(f"TARGET_MODEL : {TARGET_MODEL}")
    print(f"JUDGE_MODEL  : {JUDGE_MODEL}")
    print(f"TRIALS/ATTACK: {trials}")
    print(f"ATTACKS      : {len(ALL_ATTACKS)}   BENIGN: {len(BENIGN_REQUESTS)}")

    t0 = time.time()
    RUNS_DIR.mkdir(exist_ok=True)

    print("\n--- ATTACK SUITE (undefended) ---")
    attack_results = run_suite(
        ALL_ATTACKS, trials=trials,
        save_path=RUNS_DIR / "_ckpt_attacks.json", resume=resume,
    )

    print("\n--- BENIGN REQUESTS (false-positive check) ---")
    benign_results = run_suite(
        BENIGN_REQUESTS, trials=max(2, trials - 1),
        save_path=RUNS_DIR / "_ckpt_benign.json", resume=resume,
    )

    elapsed = time.time() - t0

    # ---- attack results table -------------------------------------------------
    print("\n" + "=" * 78)
    print("ATTACK RESULTS (undefended)  -  verdict = worst of N trials")
    print("=" * 78)
    print(results_table(attack_results))

    summary = verdict_summary(attack_results)
    print("\nverdict totals:", summary)
    by_sev: dict[str, dict[str, int]] = {}
    for r in attack_results:
        d = by_sev.setdefault(r["severity"], {})
        d[r["verdict"]] = d.get(r["verdict"], 0) + 1
    print("by severity   :", by_sev)

    # ---- benign / false-positive table -------------------------------------
    print("\n" + "=" * 78)
    print("BENIGN RESULTS  -  expected: all 'blocked' (no leak, agent behaved)")
    print("=" * 78)
    print(results_table(benign_results))
    false_pos = [r for r in benign_results if r["verdict"] not in ("blocked", "error")]
    print(
        f"\nfalse positives (benign scored as partial/succeeded): {len(false_pos)}"
    )
    for r in false_pos:
        print(f"  ! {r['attack_id']}: {r['verdict']} - {r['judge_reasoning']}")

    # ---- per-attack detail --------------------------------------------------
    print("\n" + "=" * 78)
    print("PER-ATTACK DETAIL")
    print("=" * 78)
    for r in attack_results:
        print(f"\n[{r['attack_id']}]  sev={r['severity']}  verdict={r['verdict']}")
        print(f"  severity rationale: {rationale_of(r['attack_id'])}")
        print(f"  judge (worst trial): {r['judge_reasoning']}")

    # ---- persist ----------------------------------------------------------
    out = RUNS_DIR / "undefended.json"
    payload = {
        "target_model": TARGET_MODEL,
        "judge_model": JUDGE_MODEL,
        "trials": trials,
        "elapsed_sec": round(elapsed, 1),
        "attacks": attack_results,
        "benign": benign_results,
    }
    out.write_text(json.dumps(payload, indent=2))
    print(f"\nsaved -> {out}   ({elapsed:.0f}s total)")

    # pipeline health only: every row produced a real (non-error) verdict
    errs = [r for r in attack_results + benign_results if r["verdict"] == "error"]
    print("PIPELINE:", "OK" if not errs else f"{len(errs)} judge errors -> {[e['attack_id'] for e in errs]}")
    return 0 if not errs else 1


if __name__ == "__main__":
    sys.exit(main())
