# Sentinel: Agentic AI Cybersecurity Incident Response

An advanced, adaptive cybersecurity dashboard and AI-driven incident response system. Sentinel utilizes a localized LLM (Ollama) to analyze simulated cyberattacks in real-time, generate automated defense rules, and record tamper-evident cryptographic provenance on a permissioned blockchain (Hyperledger Fabric).

## Features

- **Matrix Terminal Interface:** A sleek, hacker-themed UI with an interactive terminal simulator for executing attack payloads.
- **Agentic AI Defense:** Analyzes attacks using a localized Ollama AI model to generate highly contextual, adaptive defense rules (e.g., blocking malicious IPs, applying rate limits).
- **Hyperledger Fabric Provenance:** All defense rules, evidence hashes, and AI confidence scores are cryptographically hashed and registered on a permissioned Hyperledger Fabric blockchain to prevent tampering.
- **Forensic Evidence Verification:** Allows security analysts to instantly re-compute the SHA-256 fingerprint of current telemetry evidence and verify it against the immutable record on the blockchain. Features a built-in "Simulate Tampering" function to demonstrate tamper detection capabilities.
- **Automated Triage:** Provides instant, AI-generated step-by-step triage protocols for security operations teams.

## Tech Stack

- **Frontend:** React 19, Vite, custom CSS (Matrix aesthetic)
- **Backend:** Node.js, Express
- **Blockchain:** Hyperledger Fabric (WSL2 / Docker), Go (Chaincode)
- **AI Agent:** Ollama (Llama 3 or compatible models)

## Prerequisites

- **Windows Subsystem for Linux (WSL2)** with Ubuntu (or similar)
- **Docker Desktop** (with WSL2 integration enabled)
- **Node.js** (v18+)
- **Ollama** installed and running on `127.0.0.1:11434` with your preferred model pulled (e.g., `ollama run llama3`)

## Getting Started

### 1. Start the Hyperledger Fabric Network (WSL)

Open your WSL terminal and execute the setup script to initialize the Fabric network and deploy the `defenseRegistry` chaincode:

```bash
cd scripts
./setup-fabric.sh
```

### 2. Start the Backend API

Open a PowerShell or Command Prompt in the project root:

```powershell
cd server
npm install
npm run dev
```
The backend API will run on `http://localhost:5000`.

### 3. Start the Frontend Dashboard

Open a new PowerShell or Command Prompt in the project root:

```powershell
cd Frontend
npm install
npm run dev
```
The dashboard will be available at `http://localhost:5173`.

## Simulating Attacks

1. Navigate to `http://localhost:5173`.
2. Locate the **Terminal Attack Simulator** on the dashboard.
3. Select an attack vector (e.g., *Suspicious PowerShell*, *Network Service Scan*).
4. Click `./run_exploit.sh` to trigger the simulation.
5. Watch as the AI analyzes the telemetry, generates a defense rule, and registers the cryptographic evidence onto the Hyperledger Fabric blockchain.
6. Scroll down to **Forensic Verification** and click **Verify Evidence** to confirm the integrity of the recorded incident.

## License

MIT License
