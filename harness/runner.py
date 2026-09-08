"""
harness/runner.py — drive attacks through the target agent and score them.

Because temperature=0 is not deterministic on Groq's gpt-oss models, each attack
is run `trials` times. The reported verdict is the WORST observed (security is
about the worst case), with the per-trial breakdown kept alongside it.

Resilience: each trial retries on transient Groq errors (connection drops, 429
OTPM limits). `run_suite(save_path=...)` checkpoints after every attack, and
`resume=True` skips attacks already in that checkpoint.

run_suite(...) returns a list of dicts:
    {attack_id, category, severity, verdict, verdict_counts, trials,
     transcript, judge_reasoning}
"""

import json
import time
from pathlib import Path
from typing import Any, Callable, Optional

from groq import APIConnectionError, APIStatusError, RateLimitError
from groq import Groq

from attacks import Attack
from harness.judge import judge
from severity import severity_of
from target_agent import run_agent

# blocked < partial < succeeded ; "error" sorts lowest so a real verdict wins.
_VERDICT_RANK = {"error": -1, "blocked": 0, "partial": 1, "succeeded": 2}

_TRANSIENT = (APIConnectionError, RateLimitError, APIStatusError)


def with_retry(fn: Callable[[], Any], *, retries: int = 4, base_delay: float = 6.0) -> Any:
    """Call fn(); on a transient Groq error wait (backoff clears 60s OTPM windows)
    and retry. Re-raises the last error if all attempts fail."""
    last: Optional[BaseException] = None
    for attempt in range(retries + 1):
        try:
            return fn()
        except _TRANSIENT as exc:  # noqa: PERF203
            last = exc
            if attempt == retries:
                break
            delay = base_delay * (attempt + 1)
            print(f"      transient error ({type(exc).__name__}); retry in {delay:.0f}s", flush=True)
            time.sleep(delay)
    raise last  # type: ignore[misc]


def run_attack(
    attack: Attack,
    *,
    trials: int = 3,
    client: Optional[Groq] = None,
    defense: Optional[Callable[..., list[dict[str, Any]]]] = None,
    pause: float = 0.0,
) -> dict[str, Any]:
    """Run one attack `trials` times; return its worst-case result dict.

    `defense` (Gate 4) is a callable with the same signature as run_agent that
    wraps it with input/output screening. When None the agent runs undefended.
    """
    client = client or Groq(max_retries=5)
    driver = defense or run_agent
    runs: list[dict[str, Any]] = []

    for i in range(trials):
        try:
            transcript = with_retry(
                lambda: driver(
                    attack.user_message,
                    webpages=attack.webpages,
                    docs=attack.docs,
                    client=client,
                )
            )
            verdict = with_retry(lambda: judge(transcript, client=client))
            runs.append(
                {
                    "trial": i,
                    "verdict": verdict["verdict"],
                    "reasoning": verdict["reasoning"],
                    "transcript": transcript,
                }
            )
        except _TRANSIENT as exc:
            runs.append(
                {
                    "trial": i,
                    "verdict": "error",
                    "reasoning": f"{type(exc).__name__}: {exc}",
                    "transcript": [],
                }
            )
        if pause:
            time.sleep(pause)

    worst = max(runs, key=lambda r: _VERDICT_RANK.get(r["verdict"], -1))
    counts: dict[str, int] = {}
    for r in runs:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1

    return {
        "attack_id": attack.attack_id,
        "category": attack.category,
        "severity": severity_of(attack.attack_id),
        "verdict": worst["verdict"],          # worst case across trials
        "verdict_counts": counts,             # e.g. {"blocked": 2, "partial": 1}
        "trials": trials,
        "transcript": worst["transcript"],    # transcript of the worst trial
        "judge_reasoning": worst["reasoning"],
    }


def run_suite(
    attacks: list[Attack],
    *,
    trials: int = 3,
    defense: Optional[Callable[..., list[dict[str, Any]]]] = None,
    pause: float = 1.0,
    progress: bool = True,
    save_path: Optional[str | Path] = None,
    resume: bool = False,
) -> list[dict[str, Any]]:
    client = Groq(max_retries=5)
    results: list[dict[str, Any]] = []
    done: set[str] = set()

    if save_path and resume and Path(save_path).exists():
        results = json.loads(Path(save_path).read_text())
        done = {r["attack_id"] for r in results}
        if progress and done:
            print(f"  resuming - {len(done)} attack(s) already done: {sorted(done)}")

    for n, attack in enumerate(attacks, 1):
        if attack.attack_id in done:
            continue
        if progress:
            print(f"  [{n}/{len(attacks)}] {attack.attack_id} ...", flush=True)
        res = run_attack(attack, trials=trials, client=client, defense=defense, pause=pause)
        if progress:
            print(f"      -> {res['verdict'].upper():9s} {res['verdict_counts']}", flush=True)
        results.append(res)
        if save_path:
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            Path(save_path).write_text(json.dumps(results, indent=2))

    return results


def results_table(results: list[dict[str, Any]]) -> str:
    """Fixed-width text table of a suite run."""
    head = f"{'ATTACK_ID':<34}{'CATEGORY':<13}{'SEV':<8}{'VERDICT':<11}{'b/p/s/err'}"
    lines = [head, "-" * len(head)]
    for r in results:
        c = r["verdict_counts"]
        bpse = (
            f"{c.get('blocked', 0)}/{c.get('partial', 0)}/"
            f"{c.get('succeeded', 0)}/{c.get('error', 0)}"
        )
        lines.append(
            f"{r['attack_id']:<34}{r['category']:<13}{r['severity']:<8}"
            f"{r['verdict']:<11}{bpse}"
        )
    return "\n".join(lines)


def verdict_summary(results: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in results:
        out[r["verdict"]] = out.get(r["verdict"], 0) + 1
    return out
