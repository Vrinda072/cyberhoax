"""
cross_check.py - run the full before/after suite against several Groq target
models to show the harness is model-agnostic.

Each model runs in its own subprocess with TARGET_MODEL set, reusing the exact
tested pipeline (`python -m harness.runner`). No change to the core.

Output: runs/cross_check.json + runs/before_after_<model>.json per model, and a
residual-risk-per-model table.

Run:  export GROQ_API_KEY=...
      .venv/bin/python cross_check.py [--trials N]     # default 2
      CROSS_CHECK_MODELS="a,b" .venv/bin/python cross_check.py
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from config import CROSS_CHECK_MODELS
from severity import residual_risk

RUNS = Path(__file__).parent / "runs"


def _slug(model: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", model.lower()).strip("-")


def run_model(model: str, trials: int) -> dict:
    env = {**os.environ, "TARGET_MODEL": model}
    print(f"\n=== {model}  (trials={trials}) ===", flush=True)
    subprocess.run(
        [sys.executable, "-m", "harness.runner", "--trials", str(trials)],
        env=env, check=True,
    )
    src = RUNS / "before_after.json"
    dst = RUNS / f"before_after_{_slug(model)}.json"
    shutil.copy(src, dst)
    rows = json.loads(dst.read_text())

    before = [{"severity": r["severity"], "verdict": r["verdict_before"]} for r in rows]
    after = [{"severity": r["severity"], "verdict": r["verdict_after"]} for r in rows]
    return {
        "model": model,
        "trials": trials,
        "residual_risk_undefended": residual_risk(before),
        "residual_risk_defended": residual_risk(after),
        "verdicts": {
            r["attack_id"]: [r["verdict_before"], r["verdict_after"]] for r in rows
        },
        "file": dst.name,
    }


def main() -> int:
    if not os.environ.get("GROQ_API_KEY"):
        print("GROQ_API_KEY is not set.")
        return 2
    trials = 2
    if "--trials" in sys.argv:
        trials = int(sys.argv[sys.argv.index("--trials") + 1])

    models = [m.strip() for m in CROSS_CHECK_MODELS if m.strip()]
    print(f"model cross-check: {models}  x {trials} trials each")

    results, errors = [], []
    for m in models:
        try:
            results.append(run_model(m, trials))
        except subprocess.CalledProcessError as exc:
            print(f"  !! {m} failed: {exc}")
            errors.append(m)

    out = RUNS / "cross_check.json"
    if not results and out.exists():
        print(f"\nno model completed (quota). Keeping existing {out}.")
        return 1
    out.write_text(
        json.dumps({"trials": trials, "models": results, "errors": errors}, indent=2)
    )

    print("\n" + "=" * 66)
    print("MODEL CROSS-CHECK  (severity-weighted residual risk score)")
    print("=" * 66)
    print(f"{'model':<28}{'undefended':<16}{'defended':<16}")
    print("-" * 66)
    for r in results:
        u, d = r["residual_risk_undefended"], r["residual_risk_defended"]
        print(f"{r['model']:<28}{u['absolute']:>6.1f} / {u['ceiling']:<7}"
              f"{d['absolute']:>6.1f} / {d['ceiling']}")
    print(f"\nsaved -> runs/cross_check.json   ({len(results)} model(s), "
          f"{len(errors)} failed)")
    return 0 if results and not errors else 1


if __name__ == "__main__":
    sys.exit(main())
