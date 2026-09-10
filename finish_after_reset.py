"""
finish_after_reset.py - run the live steps that were blocked by Groq's daily
token cap, once the cap has reset (~00:00 UTC).

Steps (each tolerant of failure - a later step still runs, and the report is
regenerated with whatever data exists):
  1. naive keyword-filter baseline   -> runs/naive.json        (Addition 1)
  2. model cross-check               -> runs/cross_check.json   (Addition 3)
  3. regenerate report / export / certificate

Run:  export GROQ_API_KEY=...
      .venv/bin/python finish_after_reset.py
"""

import subprocess
import sys

PY = sys.executable


def step(title: str, args: list[str], required: bool = False) -> bool:
    print(f"\n{'=' * 66}\n{title}\n{'=' * 66}", flush=True)
    try:
        subprocess.run([PY, *args], check=True)
        return True
    except subprocess.CalledProcessError as exc:
        print(f"  !! step failed ({exc.returncode}). Continuing.")
        if required:
            print("  (this step was required - later steps may be incomplete)")
        return False


def main() -> int:
    ok_naive = step("1/3  naive keyword-filter baseline",
                    ["naive_defense.py", "--trials", "3"])
    ok_cross = step("2/3  model cross-check",
                    ["cross_check.py", "--trials", "2"])

    print(f"\n{'=' * 66}\n3/3  regenerate report / export / certificate\n{'=' * 66}",
          flush=True)
    step("report.py", ["report.py"])
    step("export.py", ["export.py"])
    step("certificate.py", ["certificate.py"])

    print(f"\n{'=' * 66}")
    print(f"naive baseline : {'done' if ok_naive else 'FAILED - retry when cap clears'}")
    print(f"cross-check    : {'done' if ok_cross else 'FAILED - retry when cap clears'}")
    print("report/export/certificate regenerated from whatever data exists.")
    print("Review runs/report.md, then commit runs/ + any regenerated files.")
    return 0 if (ok_naive and ok_cross) else 1


if __name__ == "__main__":
    sys.exit(main())
