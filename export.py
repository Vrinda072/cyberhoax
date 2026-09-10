"""
export.py — paste-ready results block for a written/PDF report.

Pulls from runs/undefended.json + runs/defended.json (produced by the suite) and
prints a compact markdown block: the per-attack before/after table, the
severity-weighted residual risk score, the false-positive rate, and the
most-dangerous-attack summary. Nothing here calls an API.

Run:  .venv/bin/python export.py            # prints, also writes runs/export.md
"""

import json
import sys
from pathlib import Path

from severity import (
    SEVERITY_WEIGHT,
    VERDICT_FACTOR,
    attack_risk,
    rationale_of,
    residual_risk,
    severity_of,
)

RUNS = Path(__file__).parent / "runs"
_RANK = {"error": -1, "blocked": 0, "partial": 1, "succeeded": 2}


def build() -> str:
    u = json.loads((RUNS / "undefended.json").read_text())
    d = json.loads((RUNS / "defended.json").read_text())
    u_by = {r["attack_id"]: r for r in u["attacks"]}
    d_by = {r["attack_id"]: r for r in d["attacks"]}
    ur, dr = residual_risk(u["attacks"]), residual_risk(d["attacks"])

    L: list[str] = []
    L.append("### Attack results (before / after defense)")
    L.append("")
    L.append(f"Target `{u.get('target_model', '?')}` · judge `{u.get('judge_model', '?')}` "
             f"· defense `{d.get('defense_model', '?')}` (threshold "
             f"{d.get('defense_flag_threshold', '?')}) · {u.get('trials', '?')} trials/attack, "
             f"worst-case verdict · $0 (Groq free tier)")
    L.append("")
    L.append("| attack_id | category | severity | verdict_before | verdict_after |")
    L.append("|---|---|---|---|---|")
    for aid, b in u_by.items():
        a = d_by.get(aid, {})
        L.append(f"| {aid} | {b['category']} | {severity_of(aid)} | "
                 f"{b['verdict']} | {a.get('verdict', '?')} |")
    L.append("")

    # verdict tallies
    def tally(rows):
        t = {"blocked": 0, "partial": 0, "succeeded": 0}
        for r in rows:
            t[r["verdict"]] = t.get(r["verdict"], 0) + 1
        return t
    tb, ta = tally(u["attacks"]), tally(d["attacks"])
    L.append(f"Totals — before: {tb['blocked']} blocked / {tb['partial']} partial / "
             f"{tb['succeeded']} succeeded · after: {ta['blocked']} blocked / "
             f"{ta['partial']} partial / {ta['succeeded']} succeeded")
    L.append("")

    L.append("### Residual risk score (severity-weighted)")
    L.append("")
    L.append("```")
    L.append("residual_risk = sum over 8 attacks of ( severity_weight x outcome )")
    L.append(f"  severity_weight : low={SEVERITY_WEIGHT['low']} medium={SEVERITY_WEIGHT['medium']} "
             f"high={SEVERITY_WEIGHT['high']}")
    L.append(f"  outcome         : succeeded={VERDICT_FACTOR['succeeded']} "
             f"partial={VERDICT_FACTOR['partial']} blocked={VERDICT_FACTOR['blocked']}")
    L.append("```")
    L.append("")
    L.append(f"- Undefended: **{ur['absolute']:.1f} / {ur['ceiling']}**")
    L.append(f"- Defended:   **{dr['absolute']:.1f} / {dr['ceiling']}**  "
             f"(reduction {ur['absolute'] - dr['absolute']:.1f} points, "
             f"{100 * (ur['absolute'] - dr['absolute']) / ur['absolute']:.0f}% relative)")
    L.append("")

    fp = d.get("false_positive", {})
    L.append("### False-positive rate")
    L.append("")
    L.append(f"{fp.get('passed', '?')} / {fp.get('total', '?')} benign requests still complete "
             f"normally through the defended agent — **false-positive rate "
             f"{fp.get('false_positive_rate_pct', '?')}%**.")
    L.append("")

    L.append("### Most dangerous attack still getting through")
    L.append("")
    residual = [r for r in d["attacks"] if r["verdict"] in ("succeeded", "partial")]
    if not residual:
        L.append("None — every attack is fully blocked after defense.")
    else:
        w = max(residual, key=lambda r: (attack_risk(r), _RANK[r["verdict"]]))
        aid = w["attack_id"]
        L.append(f"**{aid}** — {w['category']} / {severity_of(aid)} · "
                 f"verdict after defense **{w['verdict']}** "
                 f"(before: {u_by.get(aid, {}).get('verdict', '?')}) · "
                 f"risk contribution {attack_risk(w):.1f}")
        L.append("")
        L.append(f"{rationale_of(aid)} The defense's two screens do not stop it because "
                 f"the tool results are legitimate and no protected text reaches the "
                 f"reply — it needs an authorization check at the tool-call layer.")
    L.append("")
    return "\n".join(L)


def main() -> int:
    for p in ("undefended.json", "defended.json"):
        if not (RUNS / p).exists():
            print(f"missing runs/{p} - run the suite first.")
            return 2
    text = build()
    (RUNS / "export.md").write_text(text + "\n")
    print(text)
    print("\n---\nsaved -> runs/export.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
