"""Streamlit dashboard for evaluating candidate firewall rules."""
from __future__ import annotations

import hashlib
import io
import logging
from pathlib import Path

import pandas as pd
import streamlit as st

from core.explainer import explain
from core.llm import LLM, LLMError
from core.parser import parse_rule
from core.replay import ReplayResult, load_flows, replay
from data.generate_flows import generate

ROOT = Path(__file__).resolve().parent
DEFAULT_RULE = "Block TCP 443 from WiFi to Servers"
CARDS = {
    "flows_checked": "Flows checked", "matched": "Matched",
    "intended_blocked": "Intended blocked", "would_break": "Would break",
}
PALETTES = {"critical": ("#8f271b", "#fce8e3"), "review": ("#704407", "#fff0cc"), "ok": ("#1c6039", "#dcf2e3")}

st.set_page_config(page_title="Firewall impact | blast-radius", layout="wide")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")


def theme() -> None:
    """Set an original, compact firewall-console visual style."""
    st.markdown(
        """
        <style>
        .stApp { background: #f7f8fa; color: #252b32; }
        [data-testid="stHeader"] { background: #fff; border-bottom: 1px solid #e2e5e9; }
        [data-testid="stSidebar"] { background: #eff1f4; border-right: 1px solid #dce1e7; }
        [data-testid="stSidebar"] [data-testid="stHeading"] { color: #2a3138; }
        .stMainBlockContainer { max-width: 1320px; padding-top: 4.4rem; }
        .br-head { background: white; border: 1px solid #dfe3e8; border-top: 3px solid #dc532e;
                   border-radius: 5px; padding: 1.25rem 1.4rem; margin-bottom: .4rem; }
        .br-path { font-size: .78rem; color: #626b75; margin-bottom: .45rem; }
        .br-head h1 { font-size: clamp(1.55rem, 3vw, 2.3rem); margin: 0; padding: 0; line-height: 1.2; }
        .br-head p { margin: .45rem 0 0; color: #505b67; }
        .br-brand { border-left: 4px solid #dc532e; padding-left: .65rem; margin-bottom: .5rem; }
        .br-brand strong { font-size: 1.4rem; letter-spacing: -.035em; }
        [data-testid="stMetric"] { background: #fff; border: 1px solid #dfe3e8;
                                  border-radius: 5px; padding: .85rem 1rem; }
        [data-testid="stMetricValue"] { font-size: 1.8rem; font-weight: 650; }
        div[data-testid="stVerticalBlockBorderWrapper"] { background: #fff; }
        .stButton button[kind="primary"] { background: #b83b1c; border-color: #b83b1c; color: white; }
        .stButton button[kind="primary"]:hover { background: #963318; border-color: #963318; }
        </style>
        """,
        unsafe_allow_html=True,
    )


@st.cache_data(show_spinner=False)
def read_csv(content: bytes) -> pd.DataFrame:
    """Reuse the selected capture across button clicks."""
    return load_flows(io.BytesIO(content))


def capture() -> tuple[pd.DataFrame, str]:
    with st.sidebar:
        st.markdown('<div class="br-brand"><strong>blast-radius</strong></div>', unsafe_allow_html=True)
        st.subheader("Flow capture")
        paths = sorted((ROOT / "data").glob("*.csv"))
        options = [path.name for path in paths] or ["flows.csv"]
        name = st.selectbox("Local CSV", options)
        uploaded = st.file_uploader("Or upload a flows CSV", type="csv")
        if uploaded:
            content = uploaded.getvalue()
        else:
            path = ROOT / "data" / name
            if not path.exists():
                generate(path)
            content = path.read_bytes()
        flows = read_csv(content)
        st.metric("Total flows", f"{len(flows):,}")
        vlans = sorted(set(flows.src_vlan) | set(flows.dst_vlan))
        st.caption("VLANs · " + (", ".join(vlans) if vlans else "None"))
        st.caption("Demo mode · no API calls" if LLM().demo else "Live model mode")
    return flows, hashlib.sha256(content).hexdigest()


def severity_style(value: str) -> str:
    foreground, background = PALETTES.get(value, ("inherit", "transparent"))
    return f"color: {foreground}; background-color: {background}; font-weight: 650"


def flow_details(result: ReplayResult) -> None:
    broken = result.flows.loc[result.flows.category.eq("would_break")]
    if broken.empty:
        return
    with st.expander(f"Inspect {len(broken):,} individual broken flows"):
        st.dataframe(broken, hide_index=True, use_container_width=True)
        st.download_button("Download broken flows CSV", broken.to_csv(index=False), "broken-flows.csv", "text/csv")


def stats(analysis: dict) -> None:
    totals = analysis["usage"]
    with st.expander("LLM usage and traffic"):
        prompt, completion = totals["prompt_tokens"], totals["completion_tokens"]
        cost, latency = totals["estimated_cost"], totals["llm_latency_ms"]
        first, second, third = st.columns(3)
        first.metric("LLM calls", totals["llm_calls"])
        second.metric("LLM latency", f"{latency:,.1f} ms")
        third.metric("Estimated cost", f"{cost:.6f} credits" if cost is not None else "Unknown")
        st.write(f"Prompt tokens · {prompt if prompt is not None else 'Unknown'}  |  Completion tokens · {completion if completion is not None else 'Unknown'}")
        summary = analysis["result"].summary
        rows = totals["flow_rows_in_request"]
        label = "Simulated flow rows in LLM requests" if analysis["demo"] else "Flow rows in LLM requests"
        st.write(f"{label} · **{rows:,} aggregate rows / {summary['flows_checked']:,} total flows**")
        st.caption("Raw flow rows sent: 0. Demo usage is simulated." if analysis["demo"] else "Raw flow rows sent: 0.")
        if analysis["calls"]:
            st.dataframe(pd.DataFrame(analysis["calls"]), hide_index=True, use_container_width=True)


def results(flows: pd.DataFrame, analysis: dict) -> None:
    rule, result, report = analysis["rule"], analysis["result"], analysis["report"]
    for column, (key, label) in zip(st.columns(4), CARDS.items()):
        column.metric(label, f"{result.summary[key]:,}")
    with st.expander("Parsed rule JSON"):
        st.json(rule.to_dict())
    impact, proposal = st.tabs(["Broken flows", "Safer rule"])
    with impact:
        st.subheader("Predicted service impact")
        if report.groups.empty:
            st.success("No observed flows were classified as broken.")
        else:
            table = report.groups.drop(columns="id")
            st.dataframe(table.style.map(severity_style, subset=["severity"]), hide_index=True, use_container_width=True)
        flow_details(result)
        st.subheader("Impact explanation")
        st.write(report.explanation)
    with proposal:
        st.subheader("Suggested safer rule")
        if report.notice:
            st.info(report.notice)
        st.json(report.safer_rule.to_dict())
        if st.button("Re-run with safer rule", disabled=report.safer_rule == rule):
            analysis["after"] = replay(flows, report.safer_rule).summary
        if "after" in analysis:
            labels = CARDS | {"allowed_by_exception": "Allowed by exception"}
            comparison = pd.DataFrame([
                {"Metric": label, "Before": result.summary[key], "After": analysis["after"][key],
                 "Change": analysis["after"][key] - result.summary[key]}
                for key, label in labels.items()
            ])
            st.dataframe(comparison, hide_index=True, use_container_width=True)
    stats(analysis)


def main() -> None:
    """Render the dashboard and maintain analysis state for the selected capture."""
    theme()
    st.markdown(
        '<div class="br-head"><div class="br-path">Firewall / Change analysis</div>'
        '<h1>Firewall impact predictor</h1><p>Test a proposed rule against recent flows before applying it.</p></div>',
        unsafe_allow_html=True,
    )
    try:
        flows, capture_key = capture()
    except (OSError, ValueError) as exc:
        st.error(f"Could not load the flow capture. {exc}")
        return
    if st.session_state.get("capture_key") != capture_key:
        st.session_state.pop("analysis", None)
        st.session_state.capture_key = capture_key
    with st.container(border=True):
        with st.form("analysis_form"):
            text = st.text_area("Candidate firewall rule", value=DEFAULT_RULE, height=105, help="Enter plain English or paste a complete JSON rule.")
            submitted = st.form_submit_button("Analyze", type="primary")
    if submitted:
        st.session_state.pop("analysis", None)
        llm = LLM()
        try:
            with st.spinner("Replaying the candidate rule against the flow capture…"):
                rule = parse_rule(text, llm)
                result = replay(flows, rule)
                report = explain(rule, result, llm)
            st.session_state.analysis = {
                "rule": rule, "result": result, "report": report,
                "usage": llm.totals(), "calls": llm.calls, "demo": llm.demo,
            }
        except (ValueError, LLMError) as exc:
            st.error(str(exc))
    if "analysis" in st.session_state:
        results(flows, st.session_state.analysis)


if __name__ == "__main__":
    main()
