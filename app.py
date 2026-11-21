"""Streamlit dashboard for evaluating candidate firewall rules."""
from __future__ import annotations

import hashlib
import io
import logging
from html import escape
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from core.explainer import explain
from core.llm import LLM, LLMError
from core.parser import parse_rule
from core.replay import ReplayResult, load_flows, replay
from core.schema import VLANS
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


@st.cache_data(show_spinner=False)
def read_csv(content: bytes) -> pd.DataFrame:
    """Reuse the selected capture across button clicks."""
    return load_flows(io.BytesIO(content))


def capture() -> tuple[pd.DataFrame, str, str, str]:
    with st.sidebar:
        st.markdown('<div class="br-brand"><span class="br-mark">B</span><strong>blast-radius</strong></div>', unsafe_allow_html=True)
        page = st.radio("Navigation", ["Dashboard", "Capture details"], label_visibility="collapsed")
        st.caption("Offline demo" if LLM().demo else "Live models")
        with st.expander("Flow capture", expanded=True):
            options = ["flows.csv", *sorted(path.name for path in (ROOT / "data").glob("*.csv") if path.name != "flows.csv")]
            name = st.selectbox("Local CSV", options)
            uploaded = st.file_uploader("Upload a flows CSV", type="csv")
        if uploaded:
            content = uploaded.getvalue()
            name = uploaded.name
        else:
            path = ROOT / "data" / name
            if not path.exists():
                generate(path)
            content = path.read_bytes()
        flows = read_csv(content)
        st.metric("Total flows", f"{len(flows):,}")
        vlans = sorted(set(flows.src_vlan) | set(flows.dst_vlan))
        st.caption("VLANs · " + (", ".join(vlans) if vlans else "None"))
    return flows, hashlib.sha256(content).hexdigest(), name, page


def widget_title(title: str) -> None:
    """Display a heading for a fixed dashboard widget."""
    st.markdown(f'<h3 class="br-widget">{title}</h3>', unsafe_allow_html=True)


def capture_details(flows: pd.DataFrame, name: str) -> None:
    """Summarize observed VLANs alongside the simulator's named selectors."""
    st.subheader("Capture details")
    st.text(name)
    incoming = flows.dst_vlan.value_counts()
    outgoing = flows.src_vlan.value_counts()
    counts = pd.concat([outgoing.rename("Source flows"), incoming.rename("Destination flows")], axis=1)
    counts = counts.fillna(0).astype(int).rename_axis("VLAN").reset_index()
    counts.insert(1, "Rule selector CIDR", counts.VLAN.map(VLANS).fillna("Use an explicit CIDR"))
    st.dataframe(counts, hide_index=True, width="stretch")
    st.caption("Named rule selectors use these CIDRs. The capture labels describe the observed traffic.")


@st.cache_data(show_spinner=False)
def traffic_series(flows: pd.DataFrame) -> pd.DataFrame:
    """Roll up timestamped flows by UTC hour for the traffic widget."""
    timestamps = pd.to_datetime(flows.timestamp, errors="coerce", utc=True, format="mixed")
    valid = timestamps.notna()
    traffic = pd.DataFrame({"hour": timestamps[valid].dt.floor("h"), "bytes": flows.loc[valid, "bytes"].astype(float)})
    if traffic.empty:
        return traffic
    hourly = traffic.groupby("hour").bytes.sum()
    span_hours = (hourly.index.max() - hourly.index.min()) / pd.Timedelta(hours=1)
    interval = max(1, int(span_hours // 500) + 1)
    totals = hourly.resample(f"{interval}h", origin="start").sum()
    return totals.rename_axis("hour").reset_index().assign(interval_hours=interval)


def dashboard_widgets(flows: pd.DataFrame, result: ReplayResult | None) -> None:
    """Show a firewall outcome breakdown and an observed traffic timeline."""
    firewall, traffic = st.columns((1, 1.65))
    with firewall, st.container(border=True):
        widget_title("Firewall outcomes")
        if result is None:
            st.caption("Run an analysis to see the firewall outcome breakdown.")
        elif not result.summary["flows_checked"]:
            st.caption("The selected capture has no flow records.")
        else:
            counts = result.summary
            segments = {
                "Allowed by rule or unaffected": counts["flows_checked"] - counts["intended_blocked"] - counts["would_break"] - counts["allowed_by_exception"],
                "Intended blocked": counts["intended_blocked"],
                "Would break": counts["would_break"],
                "Allowed by exception": counts["allowed_by_exception"],
            }
            data = pd.DataFrame({"outcome": list(segments), "flows": list(segments.values())})
            colors = ["#a9afad", "#af522d", "#c9312b", "#4d805b"]
            chart = alt.Chart(data).mark_arc(innerRadius=53, outerRadius=78).encode(
                theta="flows:Q",
                color=alt.Color("outcome:N", title=None, scale=alt.Scale(
                    domain=list(segments), range=colors,
                ), legend=None),
                tooltip=[alt.Tooltip("outcome:N", title="Outcome"), alt.Tooltip("flows:Q", title="Flows", format=",")],
            ).properties(height=192, background="transparent").configure_view(stroke=None)
            st.altair_chart(chart, width="stretch", theme=None)
            legend = "".join(
                f'<li><span style="background:{color}" aria-hidden="true"></span>{escape(label)}</li>'
                for label, color in zip(segments, colors)
            )
            st.markdown(f'<ul class="br-outcome-legend" aria-label="Firewall outcome colors">{legend}</ul>',
                        unsafe_allow_html=True)
    with traffic, st.container(border=True):
        widget_title("Observed traffic")
        data = traffic_series(flows)
        if data.empty:
            st.caption("The capture has no readable timestamps.")
        else:
            data = data.assign(megabytes=data.bytes / 1_000_000)
            chart = alt.Chart(data).mark_area(
                color="#c85e39", opacity=.3, line={"color": "#a64424"},
            ).encode(
                x=alt.X("hour:T", title="Capture time (UTC)", scale=alt.Scale(type="utc")),
                y=alt.Y("megabytes:Q", title=f"MB per {data.interval_hours.iat[0]} h"),
                tooltip=[alt.Tooltip("hour:T", title="UTC time", timeUnit="utcyearmonthdatehours", format="%d %b %H:%M"),
                         alt.Tooltip("megabytes:Q", title="MB", format=",.1f")],
            ).properties(height=220)
            st.altair_chart(chart, width="stretch", theme=None)


def severity_style(value: str) -> str:
    foreground, background = PALETTES.get(value, ("inherit", "transparent"))
    return f"color: {foreground}; background-color: {background}; font-weight: 650"


def flow_details(result: ReplayResult) -> None:
    broken = result.flows.loc[result.flows.category.eq("would_break")]
    if broken.empty:
        return
    with st.expander(f"Inspect {len(broken):,} individual broken flows"):
        st.dataframe(broken, hide_index=True, width="stretch")
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
            st.dataframe(pd.DataFrame(analysis["calls"]), hide_index=True, width="stretch")


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
            st.dataframe(table.style.map(severity_style, subset=["severity"]), hide_index=True, width="stretch")
        flow_details(result)
        st.subheader("Impact explanation")
        st.write(report.explanation)
    with proposal:
        st.subheader("Suggested safer rule")
        if report.notice:
            st.info(report.notice)
        if report.shared_service_flows:
            st.warning(
                f"{report.shared_service_flows:,} at-risk flows share a destination, port, and protocol "
                "with traffic marked for blocking. The suggested rule keeps those blocks in place."
            )
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
            st.dataframe(comparison, hide_index=True, width="stretch")
    stats(analysis)


def main() -> None:
    """Render the dashboard and maintain analysis state for the selected capture."""
    st.markdown(f"<style>{(ROOT / 'dashboard.css').read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)
    try:
        flows, capture_key, name, page = capture()
    except (OSError, ValueError) as exc:
        st.error(f"Could not load the flow capture. {exc}")
        return
    if st.session_state.get("capture_key") != capture_key:
        st.session_state.pop("analysis", None)
        st.session_state.capture_key = capture_key
    if page == "Capture details":
        capture_details(flows, name)
        return
    st.markdown(
        '<div class="br-head"><div class="br-path">Firewall / Dashboard</div>'
        f'<h1>Firewall impact predictor</h1><p>{escape(name)} · {len(flows):,} observed flows</p></div>',
        unsafe_allow_html=True,
    )
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
        analysis = st.session_state.analysis
        dashboard_widgets(flows, analysis["result"])
        results(flows, analysis)
    else:
        dashboard_widgets(flows, None)


if __name__ == "__main__":
    main()
