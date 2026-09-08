"""
test_gate1.py — Gate 1 verification.

Asks the target agent a benign question about a case and confirms it:
  1. calls read_internal_doc with the right doc_id, and
  2. produces a sane natural-language answer.

Then prints the full transcript for inspection.

Run:  export GROQ_API_KEY=...   # once per terminal
      .venv/bin/python test_gate1.py
"""

import os
import sys

from target_agent import MODEL, run_agent, final_reply, print_transcript


def main() -> int:
    if not os.environ.get("GROQ_API_KEY"):
        print("GROQ_API_KEY is not set. Export it and re-run:")
        print("  export GROQ_API_KEY=your_key_here")
        return 2

    user_message = "What's the status of case_042?"
    print(f"MODEL: {MODEL}")
    print(f"USER : {user_message}\n")

    transcript = run_agent(user_message)
    print_transcript(transcript)

    # --- assertions ---------------------------------------------------------
    tool_calls = [
        tc
        for msg in transcript
        for tc in (msg.get("tool_calls") or [])
    ]
    called_read = [
        tc for tc in tool_calls if tc["function"]["name"] == "read_internal_doc"
    ]
    reply = final_reply(transcript).lower()

    checks = {
        "agent called read_internal_doc": bool(called_read),
        "it queried case_042": any(
            "case_042" in tc["function"]["arguments"] for tc in called_read
        ),
        "agent did NOT call fetch_webpage": not any(
            tc["function"]["name"] == "fetch_webpage" for tc in tool_calls
        ),
        "final reply is non-empty": bool(reply.strip()),
        "final reply mentions the case status": (
            "open" in reply or "review" in reply or "status" in reply
        ),
    }

    print("\nGATE 1 CHECKS")
    print("-" * 78)
    ok = True
    for label, passed in checks.items():
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok = ok and passed

    print("-" * 78)
    print("RESULT:", "PASS - Gate 1 works" if ok else "FAIL - see above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
