# Blast Radius 🛡️💥

> **Pre-Deployment Firewall Blast Radius Analyzer & AI Remediation Engine**  
> *Simulate firewall policy changes against historical network flows before touching production.*

---

## 📌 Submission Highlights (Orbix Hackathon - Round 2)

- **Track / Event:** Orbix - 48-Hour Global Open Innovation Hackathon (Unstop)
- **Round:** Round 2 (Build & Implement)
- **Live Demo:** [Click here for Live Demo](https://your-deployment-url.streamlit.app) *(Deploy on Streamlit Community Cloud / HuggingFace)*
- **Demo Video (90s Pitch):** [Watch on YouTube / Google Drive](https://youtu.be/your-demo-video)
- **Code Repository:** [GitHub Repository (Public)](https://github.com/sarvanth-12/blast-radius.git)

---

## 🚨 Problem Statement: "The Firewall Dilemma"

Network administrators, SecOps, and DevOps teams routinely update firewall access control lists (ACLs) to block suspicious or unauthorized traffic (e.g., *“Block outbound TCP 443 from student WiFi to internal servers”*).

However, modern enterprise and campus environments share protocols and ports:
1. **Hidden Collateral Damage:** Internal business-critical services (ERP, Moodle, DNS, Printing) frequently communicate over standard ports like `TCP 443` or `TCP 80`.
2. **Outages & Rollback Panic:** A simple blanket block inadvertently shuts down employee payroll, exam portals, or high-throughput batch pipelines.
3. **No Safe Staging Environment:** Unlike software code, firewall policies rarely have a deterministic "staging test" against actual historical traffic logs before hitting production.

---

## 💡 Solution Overview

**Blast Radius** acts as a **pre-flight safety net** for network security:
1. **Rule Ingestion:** Accepts firewall rules written in plain English or structured JSON.
2. **Deterministic Replay:** Evaluates the candidate rule against thousands of recorded network flows ([data/flows.csv](data/flows.csv)) offline on-device.
3. **Impact Segmentation:** Splits outcomes into **Intended Blocks** (malicious/generic traffic) vs. **Critical Breakage** (at-risk business applications or high-throughput flows).
4. **AI-Powered Surgical Repair:** Proposes a verified **"Safer Rule"** with surgical exceptions (e.g., `except to 10.50.0.11/32 on TCP 443`) that restores critical services while preserving the intended security block.
5. **Zero-PII Privacy Architecture:** Exact client IPs and individual packet records never leave the local environment—only aggregated damage metadata is passed to the reasoning layer.

---

## 🏗️ System Architecture & Workflow

```text
  ┌─────────────────────────────────────────────────────────┐
  │  Operator Input: English Phrase or Structured JSON Rule │
  └────────────────────────────┬────────────────────────────┘
                               │
                               ▼
                    [ Lightweight Parser ]
                               │
                               ▼
                   ┌───────────────────────┐
                   │ Validated Rule Schema │
                   └───────────┬───────────┘
                               │
       ┌───────────────────────┴───────────────────────┐
       ▼                                               ▼
[ 20k NetFlow Records ] ──────────────► [ Replay Simulation Engine ]
                                                       │
                               ┌───────────────────────┴───────────────────────┐
                               ▼                                               ▼
                    [ Intended Blocks ]                            [ Collateral Breakage ]
                    (5,253 generic flows)                          (2,076 ERP/Moodle flows)
                               │                                               │
                               │                                               ▼
                               │                                   [ Damage Aggregator ]
                               │                                    (Zero-PII Groups)
                               │                                               │
                               │                                               ▼
                               │                                   [ AI Reasoning Layer ]
                               │                                   (GLM 5.2 / DeepSeek)
                               │                                               │
                               ▼                                               ▼
                    ┌─────────────────────────────────────────────────────────────────┐
                    │                    OPNsense-Inspired Console                    │
                    │   • Outcome Donut Charts    • Traffic Timeline Breakdown        │
                    │   • Broken Flow Inspector   • One-Click "Safer Rule" Remediation│
                    └─────────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

- **🗣️ Natural Language & JSON Rule Parsing:** Enter rules in intuitive English (e.g., `Block TCP 443 from WiFi to Servers`) or standard firewall JSON schema.
- **⚡ Deterministic Flow Replay:** Simulates 20,000+ historical NetFlow connections in sub-second time without affecting live production infrastructure.
- **🛡️ Business-Critical Awareness:** Automatically recognizes core services (ERP, Moodle, DNS, Printing) and large payloads (>1MB) to prevent operational downtime.
- **🔒 Zero-PII Aggregated AI Explainer:** Sends only anonymized impact summaries (VLAN, Port, Service) to the LLM; individual IP flows and hostnames remain strictly on-device.
- **🔄 One-Click Remediation & Comparison:** Automatically crafts surgical destination exceptions and lets the operator compare before/after blast radius side-by-side.
- **📊 Real-Time Telemetry & Cost Accounting:** Tracks LLM latency, token counts, and simulated costs in real time (fully functional offline in zero-cost Demo Mode).
- **🎨 OPNsense-Inspired Dashboard:** Clean, professional operations dashboard built with Streamlit and Altair.

---

## 🌐 Network & VLAN Configuration

| VLAN Name | CIDR Block | Description |
|:---|:---|:---|
| **Admin** | `10.10.0.0/24` | Management, IT, and administrative operations |
| **CyberLab** | `10.20.0.0/24` | Isolated testing and security lab environments |
| **Hostel** | `10.30.0.0/22` | Residential student network |
| **WiFi** | `10.40.0.0/22` | Campus-wide wireless user subnet |
| **Servers** | `10.50.0.0/24` | Core enterprise data center (ERP, Moodle, DB) |

---

## 🛠️ Tech Stack

- **Frontend & Dashboard:** [Streamlit](https://streamlit.io/) (v1.49+), Custom CSS (OPNsense UI inspiration)
- **Data Visualizations:** [Altair](https://altair-viz.github.io/) (v5.5+)
- **Data Processing:** [Pandas](https://pandas.pydata.org/) (v2.2+)
- **AI & Reasoning:** OpenAI-compatible API / Adaption Labs (`deepseek-v4-flash`, `glm-5.2`) + Zero-Cost Offline Demo Mock
- **Testing & Benchmarking:** [Pytest](https://docs.pytest.org/), Custom multi-rule benchmark suite
- **Runtime Environment:** Python 3.11+ / 3.12

---

## 🚀 Step-by-Step Local Setup

### Prerequisites
- Python 3.11 or Python 3.12
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/sarvanth-12/blast-radius.git
cd blast-radius
```

### 2. Create and Activate Virtual Environment
**On Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**On Windows (PowerShell):**
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Setup Environment File
```bash
# Linux / macOS
cp .env.example .env

# Windows (PowerShell)
Copy-Item .env.example .env
```
*(By default, `DEMO_MODE=true` is enabled in `.env`, allowing you to run full simulations and tests locally without any paid API keys).*

### 5. Generate Synthetic NetFlow Records (20,000 Flows)
```bash
python data/generate_flows.py
```

### 6. Launch the Application
```bash
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser.

---

## 🧪 Testing & Verification

Run the comprehensive unit test suite:
```bash
pytest -v
```
*(All 10 tests should pass cleanly without warnings).*

Run the 10-rule automated benchmark suite:
```bash
python benchmark.py
```
Outputs complete latency, token usage, and replay precision metrics to `benchmark_results.csv`.

---

## 🎬 60-Second Hackathon Demo Script (For Judges)

1. **Launch App:** Open `http://localhost:8501`.
2. **Run Analysis:** Notice the pre-filled candidate rule `Block TCP 443 from WiFi to Servers`. Click **Analyze**.
3. **Examine Impact:** 
   - Observe the **Firewall Outcomes** widget: 20,000 flows analyzed.
   - 5,253 flows correctly identified as **Intended Blocked** (general HTTPS).
   - 2,076 flows flagged in red as **Would Break** (ERP & Moodle critical applications).
4. **Inspect Raw Records:** Expand **"Inspect individual broken flows"** to inspect exact source/destination IPs that would suffer an outage.
5. **Apply Remediation:** Expand **"Safer rule"** and click **Re-run with safer rule**.
6. **Verify Resolution:** Watch **Would Break** drop to **0**, while all 5,253 intended blocks remain enforced!

---

## 👥 Team & Submission Info

- **Hackathon:** Orbix - 48-Hour Global Open Innovation Hackathon (Unstop)
- **Round:** Round 2 - Build & Implement
- **Lead Developer:** Sarvanth ([@sarvanth-12](https://github.com/sarvanth-12))
