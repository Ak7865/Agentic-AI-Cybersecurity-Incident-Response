# Agentic AI Cybersecurity Incident Response

This project is a local demonstration of an incident-response pipeline. It creates safe synthetic security telemetry, detects known attack patterns deterministically, asks a local Ollama model to investigate and propose a defense, validates that proposal with code, and records approved defenses on Hyperledger Fabric.

It is a controlled simulation. The attack simulator does not attack a real target, and propagation records a lifecycle transition instead of changing a firewall, IDS, endpoint, or production system.

## The Mental Model

The components have separate jobs:

```text
Synthetic telemetry
        |
        v
Deterministic detector
        |
        v
Ollama investigation and defense proposal
        |
        v
Rule normalizer and deterministic validator
        |
        +-- rejected --> incident is shown, but no Fabric defense is created
        |
        v
Fabric registration --> READY_FOR_PROPAGATION
        |
        v
Controlled propagation --> PROPAGATED
```

The important security rule is that the model can propose a rule, but it cannot authorize that rule. `ruleValidator.js` is the final approval gate.

## Project Layout

```text
.
|- Agentic AI/
|  `- agent.js                  Ollama calls, output normalization, rule proposal
|- Cyber Security/
|  |- attackSimulator.js         Safe synthetic telemetry generators
|  |- detector.js                Deterministic detection and MITRE mapping
|  `- ruleValidator.js           Deterministic rule-approval gate
|- data/
|  `- incidents.json             Persistent JSON storage for simulated incidents
|- server/
|  |- server.js                  Express API and workflow orchestrator
|  `- fabricClient.js            Fabric Gateway client
|- Frontend/
|  `- src/Dashboard.jsx          React dashboard with Matrix Terminal Simulator
`- Hyperledger Fabric/
   |- crypto/org1/               Local client certificate, private key, TLS CA
   `- chaincode/defenseRegistry/ Fabric chaincode project
```

## 1. Attack Simulator

`Cyber Security/attackSimulator.js` creates in-memory event data only. It does not open sockets, scan hosts, or send traffic to any external target.

| Scenario | Synthetic telemetry | Source | What the detector looks for |
| --- | --- | --- | --- |
| Brute Force | 12 `AUTHENTICATION_FAILURE` events | `192.168.1.50` | Repeated failed logins |
| Network Scan | Connection attempts across 15 ports | `192.168.1.60` | Many unique destination ports |
| Denial of Service | 100 `HTTP_REQUEST` events | `192.168.1.70` | High request volume in a short window |
| Suspicious PowerShell | `PROCESS_START` events | `192.168.1.80` | PowerShell and a suspicious process chain |

Every event has a UUID, timestamp, event type, source IP, target system, and scenario-specific fields. The simulator deliberately does not label the result as an attack; the detector must infer that from the evidence.

## 2. Detector

`Cyber Security/detector.js` is deterministic. It reads the events and evaluates these rules in this order:

| Detection | Condition | MITRE ATT&CK | Returned confidence |
| --- | --- | --- | --- |
| Brute Force | At least 5 authentication-failure events | `T1110` | 0.94 |
| Network Service Scanning | At least 10 unique destination ports | `T1046` | 0.93 |
| Network Denial of Service | At least 50 HTTP requests occurring within 15 seconds | `T1498` | 0.91 |
| Suspicious PowerShell | PowerShell execution, especially `winword.exe -> powershell.exe` | `T1059.001` | 0.89 |

When a rule matches, the detector returns the attack classification, MITRE technique, confidence, evidence list, and a reason. If nothing matches, it returns `detected: false`.

This is why the detection result is explainable and repeatable: it comes from event counts, ports, timestamps, and process relationships, not from a model guess.

## 3. Agentic AI

`Agentic AI/agent.js` calls the local Ollama API at `http://127.0.0.1:11434/api/chat`. By default it uses `qwen2.5:1.5b-instruct-q4_K_M`; both the endpoint and model can be overridden with `OLLAMA_ENDPOINT` and `OLLAMA_MODEL`.

The agent runs two stages:

1. **Threat investigation**: explains the detector result and produces investigation context.
2. **Adaptive defense generation**: proposes a defense rule for the detected technique.

Model output is not trusted as a stable API shape. The normalizer accepts several response forms and produces one canonical rule shape containing a server-generated rule ID, rule type, condition, action, explanation, severity, and reasoning. The server, not the model, is authoritative for the final rule ID.

Each Ollama stage has a 180-second timeout. On CPU-only machines, a response taking one to three minutes can be normal for the selected model.

## 4. Rule Validator

`Cyber Security/ruleValidator.js` decides whether Fabric registration is allowed. It performs four checks:

1. **Required fields**: a rule needs a type, condition object, action object, and explanation.
2. **Technique relevance**: the defense type must be approved for the detected MITRE technique and the attack type must match that technique.
3. **Evidence relevance**: the condition needs at least one technique-specific telemetry field, such as `failedAttempts` for brute force or `requestsPerSecond` for DoS, or `processChain` for PowerShell.
4. **Safety and conflict checks**: destructive actions such as `delete`, `wipe`, or `shutdown` are rejected; unrelated controls are rejected for sensitive technique combinations.

The validator accepts the canonical code-style names generated by the agent, including `authentication_rate_limit`, `network_scan_rate_limit`, and `http_rate_limit`. It normalizes underscores and hyphens before comparing rule types.

The result is either:

```json
{ "passed": true, "status": "VALIDATED", "errors": [] }
```

or a `REJECTED` result listing the failed checks. A rejected incident remains visible in the dashboard, but it is not registered on Fabric and cannot be propagated or integrity-verified.

## 5. Server and Incident Lifecycle

`server/server.js` exposes the API and coordinates the pipeline through `POST /api/attack/simulate`:

1. Select a simulator from the requested scenario.
2. Detect the attack from the resulting events.
3. Run the two-stage AI analysis.
4. Validate the generated defense rule.
5. Create an incident with a canonical `INC-...` ID.
6. When validation passes, register the defense on Fabric with that same ID.
7. Update the Fabric lifecycle to `READY_FOR_PROPAGATION`.
8. Persist the incident to the `data/incidents.json` file.
9. Return the incident to the React dashboard.

The application automatically persists incidents to a `data/incidents.json` JSON file, allowing incident history to survive backend restarts.

The main API endpoints are:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/attack/simulate` | Runs the complete simulation pipeline |
| `GET /api/incidents` | Returns the JSON-backed incident dashboard data |
| `POST /api/incidents/:incidentId/acknowledge` | Marks an incident as acknowledged |
| `GET /api/incidents/:incidentId/triage` | Returns a triage recommendation |
| `POST /api/incidents/:incidentId/verify-integrity` | Compares current and Fabric-recorded evidence hashes |
| `POST /api/incidents/:incidentId/propagate` | Simulates controlled propagation |
| `GET /api/fabric/defenses/:incidentId` | Reads one Fabric defense record |

## 6. Hyperledger Fabric

`server/fabricClient.js` connects to the local Fabric peer at `localhost:7051` using the Org1 certificate, private key, and TLS certificate in `Hyperledger Fabric/crypto/org1/`.

Before registration, it calculates a SHA-256 hash of the evidence array. It then calls the `defenseRegistry` chaincode with the incident ID, attack details, risk/confidence values, evidence hash, complete defense rule, validation status, and timestamp.

The Fabric lifecycle is:

```text
VALIDATED
    -> READY_FOR_PROPAGATION
    -> PROPAGATED
```

The same canonical incident ID is used to register the defense, read it, verify its evidence, and change its lifecycle status. The propagation route refuses to query Fabric unless the local incident says that the defense was successfully registered first.

## 7. Frontend Workflow & Matrix UI

The frontend is built with React 19 + Vite and features a custom **Matrix Hacker Aesthetic**.

**Key UI Components:**
1. **Interactive Terminal Simulator:** Instead of a standard dropdown, attacks are launched from an integrated Bash-like terminal window, complete with blinking cursors and simulated standard-out logs while the AI processes telemetry.
2. **Pipeline Tracker:** A visual step-by-step pipeline mapping the progression of telemetry analysis, AI evaluation, rule generation, and blockchain registration.
3. **Forensic Evidence Verifier:** Once the backend confirms `fabric.recorded: true`, the dashboard displays the Fabric evidence hash and two forensic actions:
    * **Verify Evidence:** Recomputes the evidence hash and compares it with Fabric. A match returns a dark neon `VERIFIED` badge.
    * **Simulate Tampering:** Modifies the evidence locally before verification, demonstrating the blockchain's tamper detection by returning a dark red `TAMPER_DETECTED` badge.
4. **Propagate Defense:** Enabled only when the lifecycle is `READY_FOR_PROPAGATION`. It reads the registered defense, records a simulated propagation result, and updates Fabric to `PROPAGATED`.

## Run Locally

Prerequisites:

- Node.js and the project dependencies installed.
- Ollama running locally with the configured model available.
- The required Fabric peer, channel `mychannel`, and `defenseRegistry` chaincode already running.
- The crypto files expected by `server/fabricClient.js` available under `Hyperledger Fabric/crypto/org1/`.

Install dependencies if needed:

```powershell
npm install
npm --prefix server install
npm --prefix Frontend install
```

Ensure Ollama and its model are available:

```powershell
ollama serve
ollama pull qwen2.5:1.5b-instruct-q4_K_M
```

Start the application from the project root:

```powershell
npm run dev
```

Open `http://localhost:5173`. The backend runs at `http://127.0.0.1:5000`.

## End-to-End Demo Checklist

1. On the dashboard, locate the Terminal Simulator (`root@sentinel:~#`).
2. Choose a scenario payload and click `./run_exploit.sh`.
3. Wait for both Ollama stages to finish.
4. Confirm the server logs show the same `INC-...` ID for registration and `READY_FOR_PROPAGATION`.
5. In the dashboard, click **Verify Evidence** and confirm `VERIFIED`.
6. Click **Simulate Tampering** and confirm `TAMPER_DETECTED`.
7. Click **Propagate Defense** and confirm the lifecycle becomes `PROPAGATED`.

Expected success logs include:

```text
[Fabric] Registering defense for INC-...
[Fabric] Defense registered: INC-...
[Fabric] INC-... status updated to READY_FOR_PROPAGATION
[Fabric] INC-... status updated to PROPAGATED
```

## Troubleshooting

| Symptom | Meaning and next step |
| --- | --- |
| The terminal pauses during an Ollama stage | The local model is still generating. Each stage has a 180-second timeout. |
| The dashboard shows `REJECTED` | Read the validation errors in the incident response. Fabric registration is intentionally skipped. |
| Integrity buttons are absent | The defense must be validated and successfully recorded on Fabric first. |
| Propagation is disabled | The Fabric lifecycle is not yet `READY_FOR_PROPAGATION`, or the rule was already propagated. |
| Fabric connection fails | Confirm the peer is listening at `localhost:7051`, `mychannel` and `defenseRegistry` exist, and the local crypto files are correct. |

## Current Boundaries

This project demonstrates the reasoning, approval, provenance, integrity, and lifecycle portions of incident response. It does not deploy an actual firewall rule or modify a live endpoint. A production version would need authenticated users, durable incident storage, operational monitoring, policy governance, audit retention, and real integrations with the organization’s enforcement tools.
