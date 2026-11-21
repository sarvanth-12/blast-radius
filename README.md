# blast-radius

Replay a proposed firewall rule against recent network flows. See which observed connections would be blocked, identify business-impacting flows, and compare a suggested rule before applying anything.

## Run locally

Use Python 3.11. From the project folder, install the dependencies and launch the demo:

```sh
python -m pip install -r requirements.txt
python data/generate_flows.py
python -m streamlit run app.py
```

Demo mode is on by default. Copy the example environment file as described below to see simulated costs at the example rates. The generator writes 20,000 synthetic records to `data/flows.csv`. The sidebar lets you select another CSV in `data/` or upload one.

## Configure live models

Copy `.env.example` to `.env` with `Copy-Item .env.example .env` in PowerShell or `cp .env.example .env` on macOS/Linux. To use Adaption, set `DEMO_MODE=false` and fill in `ADAPTION_API_KEY`. The example includes Adaption’s OpenAI-compatible base URL and the two model IDs. Change the base URL and IDs in `.env` to use a different compatible provider.

| Environment variable | Model ID | Input credits / 1M | Output credits / 1M |
| --- | --- | ---: | ---: |
| `CHEAP_MODEL` | `deepseek-v4-flash` | 0.045 | 0.14 |
| `STRONG_MODEL` | `glm-5.2` | 1.40 | 4.40 |

The example uses Adaption's [standard token prices](https://docs.adaptionlabs.ai/inference-stacks/models/#pricing). Estimated cost uses the standard input price before any cache discount. Set the four `*_PRICE_PER_1M` variables to your actual rates if they differ. Streamlit displays provider-reported usage when available. Demo token counts are estimates, demo cost is simulated, and demo latency measures local execution.

## Architecture

```text
English rule --> Cheap parser --+
                               v
JSON rule ------------------> Validated rule
                               |
Flow CSV --------------------> Replay engine ----> Flow decisions and counts
                                     |                        |
                              Broken groups only              |
                                     v                        v
                              Strong explainer -------> Streamlit console
                                     |                        |
                                     +--> Safer rule --> Local comparison
```

The strong model sees the candidate rule plus grouped impact, including VLAN labels, port, application, row count, and byte total. Individual flow records, source addresses, and exact observed destination addresses stay local in the dashboard pipeline. A rule that the operator explicitly supplies can itself contain IP addresses. Endpoint-level repair uses the replay records on-device. The explainer's proposal is checked against the observed exceptions before display. The interface takes visual inspiration from the [OPNsense Dashboard](https://docs.opnsense.org/manual/dashboard.html).

## Replay semantics

Every CSV record represents traffic observed as allowed. This is a single-rule, stateless simulation. An `allow` marks a matching observed record allowed. A `block` denies matching records unless a destination/service exception applies. VLAN selectors match the configured CIDR. Empty `ports` means all destination ports. Exceptions apply within the parent rule. These historical predictions do not model ordered policies, stateful return traffic, NAT, or new traffic.

ERP, Moodle, Printing, and DNS are treated as business-critical. A blocked record with at least 1,000,000 bytes also counts as potential breakage. Remaining blocks count as intended blocks. A service name in rule input resolves to a port, so ERP, Moodle, and HTTPS can all match TCP 443. The generated capture uses dedicated destinations for those applications.

| VLAN | CIDR |
| --- | --- |
| Admin | 10.10.0.0/24 |
| CyberLab | 10.20.0.0/24 |
| Hostel | 10.30.0.0/22 |
| WiFi | 10.40.0.0/22 |
| Servers | 10.50.0.0/24 |

CSV columns are `timestamp,src_ip,dst_ip,src_vlan,dst_vlan,dst_port,proto,bytes,app_label`.

## Hackathon demo script

1. Open the dashboard with the generated capture. Keep `Block TCP 443 from WiFi to Servers` in the rule field and click **Analyze**.
2. Point out the split between intended HTTPS blocks and flagged ERP/Moodle breakage. Open **Inspect individual broken flows** to see the exact observed records.
3. Open **Safer rule** and click **Re-run with safer rule**. With the generated capture, the endpoint exceptions restore ERP and Moodle while preserving the generic HTTPS block. The comparison shows the before and after counts.
4. Open **LLM usage and traffic**. The strong-model prompt contains two aggregate flow groups for the demo rule. The capture contains 20,000 flow records.
5. Try structured JSON or another demo phrase such as `Block SMB from Hostel to Servers`. Demo English accepts action, source, destination, optional ports or a service, and optional `except to 10.50.0.11/32 on TCP 443` clauses.

Equivalent structured rule:

```json
{
  "action": "block",
  "src": "WiFi",
  "dst": "Servers",
  "ports": [443],
  "proto": "tcp",
  "exceptions": []
}
```

## Tests and benchmark

```sh
python -m pytest -q
python benchmark.py
```

The benchmark runs ten inputs through both paths and writes `benchmark_results.csv`. It compares the complete grouped keys and per-group counts to an independently specified replay rule. Elapsed time covers parsing, replay, explanation, and telemetry where applicable. The full-flow strategy sends the complete input CSV in live mode. Use synthetic data for that strategy. Provider errors, including context-window rejection, are recorded per case. The demo baseline returns canned findings based on the reference results, so its agreement is a wiring check. Use live mode for provider accuracy, actual token usage, and latency.
