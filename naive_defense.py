"""
naive_defense.py - the "old approach" baseline.

A static keyword blocklist, the way a pre-2024 prompt-injection filter worked:
scan the user message, every tool result, and the final reply for a fixed list
of trigger phrases; if one is present, drop that content. No model call, no
semantics - purely literal substring matching.

Point of comparison: it catches attacks that use the obvious phrases verbatim
(direct_01, indirect_01) but is blind to paraphrased or "official-looking"
injections (direct_02, indirect_02, exfil_01). Run it next to the classifier
defense to show why semantics are needed.

Same call signature as harness.defense.DefendedAgent, so the runner takes it as
`defense=naive_defense`.
"""

from __future__ import annotations

from typing import Any, Optional

from groq import Groq

from target_agent import SYSTEM_PROMPT, run_agent

# Phrases a keyword filter of that era would realistically ship with. Kept
# deliberately literal - no stemming, no regex - so paraphrases slip through.
NAIVE_BLOCKLIST = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore prior instructions",
    "disregard previous instructions",
    "disregard all previous instructions",
    "disregard the above",
    "system override",
    "developer mode",
    "dan mode",
    "jailbreak",
    "reveal your prompt",
    "reveal your system prompt",
    "print your system prompt",
    "show me your instructions",
    "you are now a",
    "no restrictions",
]

REDACTION_NOTICE = "[Content removed: matched keyword blocklist]"
OUTPUT_WITHHELD_NOTICE = "[Response blocked by keyword filter]"


def blocklist_hit(text: str) -> Optional[str]:
    """Return the first blocklist phrase found in `text`, or None."""
    low = (text or "").lower()
    for phrase in NAIVE_BLOCKLIST:
        if phrase in low:
            return phrase
    return None


class NaiveDefense:
    """run_agent wrapped with a static keyword blocklist on input, tool
    results, and the final reply. After each call, `self.events` records hits."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def __call__(
        self,
        user_message: str,
        *,
        webpages: Optional[dict[str, str]] = None,
        docs: Optional[dict[str, str]] = None,
        client: Optional[Groq] = None,
    ) -> list[dict[str, Any]]:
        client = client or Groq(max_retries=5)
        self.events = []

        # 1. screen the user message before the agent ever runs
        hit = blocklist_hit(user_message)
        if hit:
            self.events.append({"stage": "input_message", "hit": hit, "flagged": True})
            return [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
                {"role": "assistant", "content": OUTPUT_WITHHELD_NOTICE},
            ]

        # 2. screen every tool result
        def on_tool_result(name: str, args: str, result: str) -> str:
            h = blocklist_hit(result)
            self.events.append(
                {"stage": "tool_result", "tool": name, "hit": h, "flagged": bool(h)}
            )
            return REDACTION_NOTICE if h else result

        # 3. screen the final reply
        def on_final(text: str, messages: list[dict[str, Any]]) -> Optional[str]:
            h = blocklist_hit(text)
            self.events.append({"stage": "final", "hit": h, "flagged": bool(h)})
            return OUTPUT_WITHHELD_NOTICE if h else None

        return run_agent(
            user_message,
            webpages=webpages,
            docs=docs,
            client=client,
            on_tool_result=on_tool_result,
            on_final=on_final,
        )


naive_defense = NaiveDefense()


def naive_actions(transcript: list[dict[str, Any]]) -> dict[str, int]:
    """Count what the naive filter did, read from a returned transcript."""
    redacted = sum(
        1 for m in transcript
        if m.get("role") == "tool" and m.get("content") == REDACTION_NOTICE
    )
    withheld = sum(
        1 for m in transcript
        if m.get("role") == "assistant" and m.get("content") == OUTPUT_WITHHELD_NOTICE
    )
    return {"tool_results_redacted": redacted, "final_output_withheld": withheld}


if __name__ == "__main__":  # python naive_defense.py  [--trials N]
    import json
    import sys
    from pathlib import Path

    from harness.runner import run_suite, results_table, verdict_summary
    from attacks import ALL_ATTACKS

    trials = 1
    if "--trials" in sys.argv:
        trials = int(sys.argv[sys.argv.index("--trials") + 1])

    print(f"naive-defense suite: {len(ALL_ATTACKS)} attacks x {trials} trial(s)\n")
    results = run_suite(ALL_ATTACKS, trials=trials, defense=naive_defense,
                        save_path=Path("runs/_ckpt_naive.json"))
    print("\n" + results_table(results))
    print("\n" + str(verdict_summary(results)))

    out = Path("runs/naive.json")
    n_err = sum(1 for r in results if r["verdict"] == "error")
    if n_err and out.exists():
        print(f"\n{n_err}/{len(results)} attacks errored (quota). Keeping existing "
              f"{out} - re-run when the token cap has cleared.")
        raise SystemExit(1)
    out.write_text(json.dumps({
        "defense": "naive_keyword_blocklist",
        "synthesized": False,
        "trials": trials,
        "attacks": results,
    }, indent=2))
    print(f"\nsaved -> {out}")
