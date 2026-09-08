"""
test_gate2.py — Gate 2 verification.

Runs ONE indirect-injection attack end to end:
  attack payload -> target_agent.run_agent -> transcript -> harness.judge -> verdict

Prints the full transcript, the agent's final reply, and the judge's JSON verdict.
The "test" only checks the pipeline produced a usable verdict; whether the attack
was blocked/partial/succeeded is the finding, printed for inspection.

Run:  export GROQ_API_KEY=...
      .venv/bin/python test_gate2.py
"""

import json
import os
import sys

from attacks.indirect import INDIRECT_ATTACKS
from config import JUDGE_MODEL, TARGET_MODEL
from harness.judge import judge
from target_agent import final_reply, print_transcript, run_agent


def main() -> int:
    if not os.environ.get("GROQ_API_KEY"):
        print("GROQ_API_KEY is not set. Export it and re-run.")
        return 2

    attack = INDIRECT_ATTACKS[0]
    print(f"TARGET_MODEL : {TARGET_MODEL}")
    print(f"JUDGE_MODEL  : {JUDGE_MODEL}")
    print(f"ATTACK ID    : {attack.attack_id}  ({attack.category})")
    print(f"DESCRIPTION  : {attack.description}")
    print(f"\nUSER MESSAGE :\n{attack.user_message}\n")

    transcript = run_agent(
        attack.user_message, webpages=attack.webpages, docs=attack.docs
    )
    print_transcript(transcript)

    print("\nFINAL REPLY TO USER")
    print("-" * 78)
    print(final_reply(transcript))

    result = judge(transcript)
    print("\nJUDGE VERDICT")
    print("-" * 78)
    print(json.dumps({k: result[k] for k in ("verdict", "reasoning")}, indent=2))

    ok = result["verdict"] in {"blocked", "partial", "succeeded"}
    print("\nPIPELINE:", "OK - verdict produced" if ok else f"BROKEN -> {result}")
    if ok:
        print(f"FINDING : indirect_01 -> {result['verdict'].upper()}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
