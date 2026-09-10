"""
app.py - Streamlit UI for the LLM & AI Agent Security Testing Harness.

    streamlit run app.py

By default it just LOADS the saved runs/*.json (no API calls, $0). Flip
"Run live against Groq" in the sidebar to execute the suite.

------------------------------------------------------------------------------
HOW TO EXTEND (everything here is meant to be edited):
  - Add an attack: drop it in attacks/<category>.py -> it shows up automatically.
  - Change models: edit config.py (shown read-only in the sidebar).
  - Tune trials / defense sensitivity: sidebar sliders (live, no code change).
  - Restyle: the CSS block is right below; the badge() helper controls colours.
  - Layout: each tab is one render_*() function further down.
------------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd
import streamlit as st

RUNS = Path(__file__).parent / "runs"

# ---------------------------------------------------------------------------
# Page + styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="LLM Agent Security Harness",
    page_icon="\U0001F6E1",
    layout="wide",
)

st.markdown(
    """
    <style>
      .stApp { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
      .block-container { padding-top: 2.2rem; max-width: 1200px; }
      [data-testid="stToolbar"], [data-testid="stDecoration"], #MainMenu, footer { display: none; }
      h1, h2, h3 { letter-spacing: -0.01em; }
      .hero {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        color: #f8fafc; padding: 1.4rem 1.6rem; border-radius: 14px; margin-bottom: 1.4rem;
      }
      .hero h1 { color: #fff; margin: 0 0 .25rem 0; font-size: 1.55rem; }
      .hero p  { color: #cbd5e1; margin: 0; font-size: .95rem; }
      .card {
        border: 1px solid #e2e8f0; border-radius: 12px; padding: 1rem 1.15rem;
        background: #fff; margin-bottom: .8rem;
      }
      .badge {
        display: inline-block; padding: 2px 10px; border-radius: 999px;
        font-size: .78rem; font-weight: 600; line-height: 1.5;
      }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; }
      [data-testid="stMetricValue"] { font-size: 1.9rem; }
      .stTabs [data-baseweb="tab"] { font-weight: 600; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Colours / badges
# ---------------------------------------------------------------------------
_COLOR = {
    "low": "#2563eb", "medium": "#d97706", "high": "#dc2626", "unrated": "#64748b",
    "blocked": "#059669", "partial": "#d97706", "succeeded": "#dc2626", "error": "#64748b",
}


def badge(text: str, kind: str) -> str:
    c = _COLOR.get(kind, "#64748b")
    return (
        f'<span class="badge" style="background:{c}1a;color:{c};'
        f'border:1px solid {c}55">{text}</span>'
    )


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_saved(name: str) -> dict | None:
    p = RUNS / name
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


def current_data() -> tuple[dict | None, dict | None]:
    """Session results take priority over saved files."""
    undef = st.session_state.get("undef") or load_saved("undefended.json")
    defd = st.session_state.get("defd") or load_saved("defended.json")
    return undef, defd


# ---------------------------------------------------------------------------
# Live run
# ---------------------------------------------------------------------------
def run_live(mode: str, trials: int, threshold: float) -> None:
    """Execute the suite against Groq, updating the page as it goes."""
    from groq import Groq

    from attacks import ALL_ATTACKS
    from harness.compare import category_comparison
    from harness.defense import DefendedAgent, defense_actions
    from harness.false_positive_check import run_false_positive_check
    from harness.runner import run_attack
    from config import DEFENSE_MODEL, JUDGE_MODEL, TARGET_MODEL

    client = Groq(max_retries=5)
    do_undef = mode in ("Undefended only", "Both (before / after)")
    do_defd = mode in ("Defended only", "Both (before / after)")
    steps = len(ALL_ATTACKS) * (int(do_undef) + int(do_defd))
    bar = st.progress(0.0, "starting...")
    feed = st.container()
    done = 0

    def _tick(label: str, r: dict, defended: bool) -> None:
        nonlocal done
        done += 1
        bar.progress(done / steps, label)
        extra = ""
        if defended:
            act = defense_actions(r["transcript"])
            extra = (
                f" &nbsp; redact/withhold: "
                f"{act['tool_results_redacted']}/{act['final_output_withheld']}"
            )
        with feed:
            st.markdown(
                f"{'DEF' if defended else 'UND'} &nbsp; <span class='mono'>{r['attack_id']}</span> "
                f"{badge(r['severity'], r['severity'])} {badge(r['verdict'], r['verdict'])}{extra}",
                unsafe_allow_html=True,
            )

    undef_results, defd_results = [], []
    try:
        if do_undef:
            for i, a in enumerate(ALL_ATTACKS, 1):
                with st.spinner(
                    f"Undefended {i}/{len(ALL_ATTACKS)} - {a.attack_id} "
                    f"(agent + judge, {trials} trial(s))..."
                ):
                    r = run_attack(a, trials=trials, client=client)
                undef_results.append(r)
                _tick(f"undefended - {a.attack_id}", r, False)
        if do_defd:
            defense = DefendedAgent(threshold=threshold)
            for i, a in enumerate(ALL_ATTACKS, 1):
                with st.spinner(
                    f"Defended {i}/{len(ALL_ATTACKS)} - {a.attack_id} "
                    f"(input screen + agent + output screen + judge)..."
                ):
                    r = run_attack(a, trials=trials, client=client, defense=defense)
                defd_results.append(r)
                _tick(f"defended - {a.attack_id}", r, True)
    except Exception as exc:  # noqa: BLE001 - surface any Groq/quota error, keep partials
        st.error(f"Run stopped early: {type(exc).__name__}: {exc}")

    bar.empty()

    # persist + stash
    if undef_results:
        payload = {"target_model": TARGET_MODEL, "judge_model": JUDGE_MODEL,
                   "trials": trials, "attacks": undef_results, "benign": []}
        (RUNS / "undefended.json").write_text(json.dumps(payload, indent=2))
        st.session_state["undef"] = payload
    if defd_results:
        fp = {}
        with st.spinner("false-positive check on benign requests..."):
            try:
                fp = run_false_positive_check(trials=max(2, trials - 1), client=client,
                                              verbose=False)
            except Exception as exc:  # noqa: BLE001
                st.warning(f"FP check skipped: {exc}")
        payload = {
            "target_model": TARGET_MODEL, "judge_model": JUDGE_MODEL,
            "defense_model": DEFENSE_MODEL, "defense_flag_threshold": threshold,
            "trials": trials,
            "attacks": defd_results,
            "category_comparison": category_comparison(undef_results or [], defd_results),
            "false_positive": fp,
        }
        (RUNS / "defended.json").write_text(json.dumps(payload, indent=2))
        st.session_state["defd"] = payload

    st.success("Run complete.")


# ---------------------------------------------------------------------------
# Tab renderers
# ---------------------------------------------------------------------------
def render_overview(undef: dict | None, defd: dict | None) -> None:
    from severity import attack_risk, rationale_of, residual_risk, severity_of

    if not undef and not defd:
        st.info("No results yet. Load a saved run or use **Run suite** in the sidebar.")
        return

    u_atk = undef["attacks"] if undef else []
    d_atk = defd["attacks"] if defd else []

    ur = residual_risk(u_atk) if u_atk else None
    dr = residual_risk(d_atk) if d_atk else None
    c1, c2, c3 = st.columns(3)
    c1.metric("Residual risk - undefended",
              f"{ur['absolute']:.1f} / {ur['ceiling']}" if ur else "-")
    c2.metric("Residual risk - defended",
              f"{dr['absolute']:.1f} / {dr['ceiling']}" if dr else "-")
    if ur and dr:
        c3.metric("Reduction", f"{ur['absolute'] - dr['absolute']:.1f} pts",
                  delta=f"-{(ur['absolute'] - dr['absolute']) / ur['absolute'] * 100:.0f}%"
                  if ur["absolute"] else None,
                  delta_color="inverse")

    # --- most dangerous attack still getting through (prominent) ----------
    if d_atk:
        residual = [r for r in d_atk if r["verdict"] in ("succeeded", "partial")]
        if residual:
            worst = max(residual, key=lambda r: (attack_risk(r),
                                                 {"partial": 1, "succeeded": 2}[r["verdict"]]))
            aid = worst["attack_id"]
            box = "error" if worst["verdict"] == "succeeded" else "warning"
            getattr(st, box)(
                f"**Most dangerous attack still getting through: "
                f"`{aid}`**  \n"
                f"category `{worst['category']}` · severity **{severity_of(aid)}** · "
                f"verdict after defense **{worst['verdict']}** · "
                f"risk contribution {attack_risk(worst):.1f}  \n"
                f"{rationale_of(aid)}  \n"
                f"_Judge:_ {worst['judge_reasoning']}"
            )
        else:
            st.success("**No attack succeeds or partially succeeds after defense.**")

    st.markdown("#### Severity-weighted risk by category")
    cats = ["direct", "indirect", "tool_misuse", "exfiltration"]
    rows = []
    for c in cats:
        row = {"category": c}
        if u_atk:
            row["Undefended"] = residual_risk([r for r in u_atk if r["category"] == c])["pct"]
        if d_atk:
            row["Defended"] = residual_risk([r for r in d_atk if r["category"] == c])["pct"]
        rows.append(row)
    df = pd.DataFrame(rows).set_index("category")
    st.bar_chart(df, height=340, stack=False,
                 color=["#dc2626", "#059669"][: len(df.columns)])
    st.caption("0 = fully blocked, 100 = every attack in the category fully succeeds.")

    st.markdown("#### Verdict counts")
    def _counts(atk):
        d = {"blocked": 0, "partial": 0, "succeeded": 0, "error": 0}
        for r in atk:
            d[r["verdict"]] = d.get(r["verdict"], 0) + 1
        return d
    tbl = {}
    if u_atk:
        tbl["Undefended"] = _counts(u_atk)
    if d_atk:
        tbl["Defended"] = _counts(d_atk)
    st.dataframe(pd.DataFrame(tbl).T, use_container_width=True)


def render_attacks(undef: dict | None, defd: dict | None) -> None:
    from severity import rationale_of
    from target_agent import format_transcript
    from harness.defense import defense_actions

    if not undef and not defd:
        st.info("No results yet.")
        return

    u_by = {r["attack_id"]: r for r in (undef["attacks"] if undef else [])}
    d_by = {r["attack_id"]: r for r in (defd["attacks"] if defd else [])}
    all_ids = list(dict.fromkeys(list(u_by) + list(d_by)))

    cats = sorted({(u_by.get(i) or d_by.get(i))["category"] for i in all_ids})
    pick = st.multiselect("Filter by category", cats, default=cats)

    for aid in all_ids:
        base = u_by.get(aid) or d_by.get(aid)
        if base["category"] not in pick:
            continue
        u = u_by.get(aid)
        d = d_by.get(aid)
        with st.container(border=True):
            verdicts = ""
            if u:
                verdicts += f"before {badge(u['verdict'], u['verdict'])} "
            if d:
                verdicts += f"&rarr; after {badge(d['verdict'], d['verdict'])}"
            st.markdown(
                f"<span class='mono' style='font-weight:600'>{aid}</span> &nbsp; "
                f"{badge(base['category'], 'unrated')} "
                f"{badge(base['severity'], base['severity'])} &nbsp; {verdicts}",
                unsafe_allow_html=True,
            )
            st.caption(rationale_of(aid))
            if d:
                act = defense_actions(d["transcript"])
                st.markdown(
                    f"Defense &mdash; tool results redacted: "
                    f"**{act['tool_results_redacted']}**, final reply withheld: "
                    f"**{act['final_output_withheld']}**"
                )
            shown = d or u
            with st.expander("Judge reasoning"):
                if u:
                    st.markdown(f"**Undefended:** {u['judge_reasoning']}")
                if d:
                    st.markdown(f"**Defended:** {d['judge_reasoning']}")
            with st.expander("Transcript (worst trial)"):
                st.code(format_transcript(shown["transcript"]), language="text")


def render_benign(defd: dict | None) -> None:
    if not defd or not defd.get("false_positive"):
        st.info("No false-positive data. Run a defended suite to populate it.")
        return
    fp = defd["false_positive"]
    c1, c2 = st.columns(2)
    c1.metric("Benign still working normally",
              f"{fp.get('passed', '?')}/{fp.get('total', '?')}",
              delta=f"{fp.get('pct_still_working', '?')}%")
    c2.metric("False-positive rate", f"{fp.get('false_positive_rate_pct', '?')}%",
              delta_color="inverse")
    rows = [
        {
            "request": r["attack_id"],
            "passes": "yes" if r["passed"] else "NO",
            "works / trials": f"{r['works_normally_trials']}/{r['trials']}",
            "sample reply": " ".join(r.get("sample_reply", "").split())[:120],
        }
        for r in fp.get("rows", [])
    ]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_report() -> None:
    from report import generate_report

    u, d = RUNS / "undefended.json", RUNS / "defended.json"
    if not (u.exists() and d.exists()):
        st.info("Need both runs/undefended.json and runs/defended.json.")
        return
    md = generate_report(u, d)
    st.download_button("Download report.md", md, file_name="report.md",
                       mime="text/markdown")
    st.markdown(md)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def sidebar() -> dict:
    from config import (
        DEFENSE_FLAG_THRESHOLD, DEFENSE_MODEL, JUDGE_MODEL, TARGET_MODEL,
    )

    with st.sidebar:
        st.header("Configuration")
        st.text_input("Target model", TARGET_MODEL, disabled=True)
        st.text_input("Judge model", JUDGE_MODEL, disabled=True)
        st.text_input("Defense model", DEFENSE_MODEL, disabled=True)
        st.caption("Models live in `config.py`. Change there, then rerun.")

        st.divider()
        trials = st.slider("Trials per attack", 1, 5, 3,
                           help="Worst verdict across trials is reported.")
        threshold = st.slider("Defense flag threshold", 0.0, 1.0,
                              float(DEFENSE_FLAG_THRESHOLD), 0.05,
                              help="Min classifier confidence to redact / withhold.")

        st.divider()
        st.header("Run")
        mode = st.radio("Mode", ["Both (before / after)", "Undefended only",
                                 "Defended only"])
        live = st.toggle("Run live against Groq", value=False,
                         help="Off = just load saved runs/*.json ($0).")
        go = st.button("Run suite", type="primary", use_container_width=True)
        st.caption("$0 - Groq free tier. Daily token caps apply; a capped run "
                   "shows `error` rows instead of crashing.")

    return {"trials": trials, "threshold": threshold, "mode": mode,
            "live": live, "go": go}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    st.markdown(
        "<div class='hero'><h1>LLM &amp; AI Agent Security Testing Harness</h1>"
        "<p>Pre-deployment audit: attack a tool-using agent, score each attempt "
        "blocked / partial / succeeded, measure severity-weighted residual risk "
        "before and after a defense layer.</p></div>",
        unsafe_allow_html=True,
    )

    cfg = sidebar()

    if cfg["go"]:
        if cfg["live"]:
            with st.status("Running suite against Groq...", expanded=True):
                run_live(cfg["mode"], cfg["trials"], cfg["threshold"])
        else:
            st.toast("Live run is off - showing saved results.", icon="ℹ️")

    undef, defd = current_data()

    src = []
    if undef:
        src.append(f"undefended ({'session' if 'undef' in st.session_state else 'saved'}, "
                   f"target `{undef.get('target_model', '?')}`)")
    if defd:
        src.append(f"defended ({'session' if 'defd' in st.session_state else 'saved'})")
    st.caption("Data: " + (" &nbsp;|&nbsp; ".join(src) if src else "none loaded"))

    t_over, t_atk, t_benign, t_report = st.tabs(
        ["Overview", "Attacks", "Benign / FP", "Report"]
    )
    with t_over:
        render_overview(undef, defd)
    with t_atk:
        render_attacks(undef, defd)
    with t_benign:
        render_benign(defd)
    with t_report:
        render_report()


if __name__ == "__main__":
    main()
