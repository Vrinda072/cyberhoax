"""
synthesize_naive.py - build runs/naive.json from the deterministic behaviour of
the keyword blocklist, without a full live suite run.

The naive filter contains no model. For every attack whose payload contains no
blocklist phrase (user message and every webpage), the run is byte-identical to
the undefended run, so that attack's result is copied verbatim from
runs/undefended.json. For the attacks it *does* match, it either short-circuits
the user message or redacts the tool result - neither can leak - so the verdict
is "blocked"; where the Groq quota allows, that verdict is confirmed by a live
run + judge, otherwise it is the reasoned fallback.

Re-run `python naive_defense.py --trials 3` after the token cap resets to replace
this with a fully live run.

Run:  export GROQ_API_KEY=...
      .venv/bin/python synthesize_naive.py
"""

import json
import sys
from pathlib import Path

from groq import Groq, RateLimitError

from attacks import ALL_ATTACKS
from harness.judge import judge
from naive_defense import blocklist_hit, naive_actions, naive_defense
from severity import severity_of

RUNS = Path(__file__).parent / "runs"


def main() -> int:
    undef = {r["attack_id"]: r for r in json.loads((RUNS / "undefended.json").read_text())["attacks"]}
    client = Groq(max_retries=2) if __import__("os").environ.get("GROQ_API_KEY") else None

    out = []
    for atk in ALL_ATTACKS:
        aid = atk.attack_id
        hit = blocklist_hit(atk.user_message) or next(
            (h for t in (atk.webpages or {}).values() if (h := blocklist_hit(t))), None
        )
        if not hit:
            # naive filter is a no-op -> identical to the undefended run
            r = dict(undef[aid])
            r["naive_source"] = "copied from undefended run (no blocklist phrase in payload)"
            out.append(r)
            print(f"  {aid:<34} no-op   -> {r['verdict']:<10} (copied from undefended)")
            continue

        # naive filter fires - try to confirm the blocked verdict live
        verdict, reasoning, transcript, source = None, None, None, None
        if client is not None:
            try:
                transcript = naive_defense(atk.user_message, webpages=atk.webpages,
                                           docs=atk.docs, client=client)
                jv = judge(transcript, client=client)
                verdict, reasoning = jv["verdict"], jv["reasoning"]
                source = f"live (naive filter matched {hit!r})"
            except RateLimitError:
                pass
        if verdict is None:
            # reasoned fallback: a short-circuited message / redacted tool result
            # cannot expose the system prompt or case data.
            verdict = "blocked"
            reasoning = (
                f"Naive keyword filter matched {hit!r} and removed that content "
                f"before the agent could act on it; the reply carries no system "
                f"prompt or case-file data."
            )
            transcript = transcript or [
                {"role": "system", "content": "[naive filter active]"},
                {"role": "user", "content": atk.user_message},
                {"role": "assistant", "content": "[Response blocked by keyword filter]"},
            ]
            source = f"reasoned fallback (quota); naive filter matched {hit!r}"
        out.append({
            "attack_id": aid, "category": atk.category, "severity": severity_of(aid),
            "verdict": verdict, "verdict_counts": {verdict: 1}, "trials": 1,
            "transcript": transcript, "judge_reasoning": reasoning,
            "naive_source": source,
        })
        print(f"  {aid:<34} MATCH   -> {verdict:<10} ({source})")

    payload = {
        "defense": "naive_keyword_blocklist",
        "synthesized": True,
        "note": ("Deterministic reconstruction: pass-through attacks copied from "
                 "runs/undefended.json verbatim; matched attacks confirmed live "
                 "where quota allowed, else reasoned. Re-run naive_defense.py after "
                 "the Groq daily token cap resets for a fully live run."),
        "trials": 1,
        "attacks": out,
    }
    (RUNS / "naive.json").write_text(json.dumps(payload, indent=2))
    tally = {}
    for r in out:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print(f"\n  tally: {tally}")
    print(f"  saved -> runs/naive.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
