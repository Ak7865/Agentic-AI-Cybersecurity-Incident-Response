import { useCallback, useEffect, useMemo, useState } from "react";
import "./Dashboard.css";

const API_URL = "http://127.0.0.1:5000/api";

const severityOptions = ["All", "Critical", "High", "Medium", "Low"];

const formatTimestamp = (value) => {
  if (!value) return "—";

  return new Intl.DateTimeFormat("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
};

const createFabricDefense = (incident) => {
  if (!incident?.fabric?.recorded) return null;

  return {
    incidentId: incident.fabric.incidentId || incident.id,
    evidenceHash: incident.fabric.evidenceHash,
    validationStatus: incident.fabric.validationStatus,
    lifecycleStatus: incident.fabric.lifecycleStatus,
    defenseRule: incident.defenseRule,
  };
};

function StatusDot({ active = true }) {
  return <span className={`status-dot ${active ? "active" : ""}`} />;
}

function Metric({ label, value, detail, critical = false }) {
  return (
    <article className={`metric-card ${critical ? "metric-critical" : ""}`}>
      <span className="metric-label">{label}</span>
      <strong>{value}</strong>
      <span className="metric-detail">{detail}</span>
    </article>
  );
}

function PipelineStep({ number, title, description, status = "complete" }) {
  return (
    <div className={`pipeline-step pipeline-${status}`}>
      <div className="pipeline-number">{number}</div>

      <div className="pipeline-content">
        <div className="pipeline-title-row">
          <strong>{title}</strong>

          <span className="pipeline-status">
            {status === "complete" ? "Complete" : status}
          </span>
        </div>

        <p>{description}</p>
      </div>
    </div>
  );
}

function Dashboard({ onNavigateToTerminal }) {
  const [dashboard, setDashboard] = useState(null);
  const [incident, setIncident] = useState(null);
  const [fabricDefense, setFabricDefense] = useState(null);

  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [attackScenario, setAttackScenario] = useState("bruteforce");
  const [severity, setSeverity] = useState("All");
  const attackScenarios = [
    {
      value: "bruteforce",
      label: "Brute Force",
      description: "Repeated authentication failures",
    },
    {
      value: "scan",
      label: "Network Service Scan",
      description: "Multiple service/port probes",
    },
    {
      value: "dos",
      label: "Denial of Service",
      description: "High-volume HTTP request burst",
    },
    {
      value: "process",
      label: "Suspicious PowerShell",
      description: "Unusual PowerShell process chain",
    },
  ];
  const [theme, setTheme] = useState(() =>
    window.matchMedia?.("(prefers-color-scheme: dark)")?.matches
      ? "dark"
      : "light",
  );

  const [acknowledgingId, setAcknowledgingId] = useState("");
  const [triage, setTriage] = useState(null);
  const [triageLoadingId, setTriageLoadingId] = useState("");

  /* =========================================================
     EVIDENCE INTEGRITY
     ========================================================= */

  const [integrityResult, setIntegrityResult] = useState(null);
  const [integrityLoading, setIntegrityLoading] = useState(false);
  const [propagationLoading, setPropagationLoading] = useState(false);
  const [propagationResult, setPropagationResult] = useState(null);

  const verifyEvidenceIntegrity = async (tamper = false) => {
    const incidentId =
      incident?.fabric?.incidentId ||
      incident?.id ||
      incident?.incidentId ||
      fabricDefense?.incidentId ||
      dashboard?.incidents?.[0]?.fabric?.incidentId ||
      dashboard?.incidents?.[0]?.id ||
      dashboard?.incidents?.[0]?.incidentId;
    if (!incidentId) {
      setIntegrityResult({
        success: false,
        status: "ERROR",
        reason: "No incident ID is available for integrity verification.",
      });

      return;
    }

    const url = `${API_URL}/incidents/${incidentId}/verify-integrity`;

    console.log("Integrity verification URL:", url);

    try {
      setIntegrityLoading(true);
      setIntegrityResult(null);

      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          tamper,
        }),
      });

      const contentType = response.headers.get("content-type") || "";

      /*
       * Do not blindly call response.json().
       *
       * If Vite/Express returns an HTML error page,
       * response.json() produces:
       *
       * Unexpected token '<', "<!DOCTYPE "... is not valid JSON
       */
      if (!contentType.includes("application/json")) {
        const text = await response.text();

        console.error("Integrity endpoint returned non-JSON response:", {
          status: response.status,
          url,
          contentType,
          body: text,
        });

        throw new Error(
          `Integrity API returned a non-JSON response ` +
            `(${response.status}). Check that the backend is running ` +
            `on http://localhost:5000.`,
        );
      }

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "Integrity verification failed.");
      }

      setIntegrityResult(data);
    } catch (requestError) {
      console.error("Integrity verification error:", requestError);

      setIntegrityResult({
        success: false,
        status: "ERROR",
        reason: requestError.message,
      });
    } finally {
      setIntegrityLoading(false);
    }
  };

  async function propagateDefense() {
    const incidentId =
      incident?.fabric?.incidentId ||
      incident?.id ||
      incident?.incidentId ||
      fabricDefense?.incidentId ||
      dashboard?.incidents?.[0]?.fabric?.incidentId ||
      dashboard?.incidents?.[0]?.id ||
      dashboard?.incidents?.[0]?.incidentId;
    if (!incidentId) {
      setPropagationResult({
        success: false,
        error: "No incident ID is available for defense propagation.",
      });
      return;
    }

    setPropagationLoading(true);
    setPropagationResult(null);

    try {
      const response = await fetch(
        `${API_URL}/incidents/${incidentId}/propagate`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({}),
        },
      );

      const contentType = response.headers.get("content-type") || "";

      const data = contentType.includes("application/json")
        ? await response.json()
        : null;

      if (!response.ok || !data) {
        throw new Error(
          data?.error || `Propagation API returned HTTP ${response.status}`,
        );
      }

      setPropagationResult(data);

      const fabricResponse = await fetch(
        `${API_URL}/fabric/defenses/${incidentId}`,
      );
      if (fabricResponse.ok) {
        const fabricData = await fabricResponse.json();
        if (fabricData.success) {
          setFabricDefense(fabricData.defense);
        }
      }
      await loadDashboard();
    } catch (error) {
      console.error("Defense propagation failed:", error);

      setPropagationResult({
        success: false,
        error: error.message,
      });
    } finally {
      setPropagationLoading(false);
    }
  }

  /* =========================================================
     LOAD DASHBOARD
     ========================================================= */

  const loadDashboard = useCallback(async () => {
    setIsLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_URL}/incidents`);

      if (!response.ok) {
        throw new Error("The security telemetry feed is unavailable.");
      }

      const data = await response.json();

      setDashboard(data);
      setIncident((activeIncident) =>
        activeIncident || data.incidents?.[0] || null,
      );
      setFabricDefense((activeFabricDefense) =>
        activeFabricDefense || createFabricDefense(data.incidents?.[0]),
      );
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  /* =========================================================
     SIMULATE ATTACK
     ========================================================= */

  const simulateAttack = async () => {
    setSimulationLoading(true);
    setError("");

    /*
     * New incident means the previous integrity result
     * must be cleared.
     */
    setIntegrityResult(null);

    try {
      const response = await fetch(`${API_URL}/attack/simulate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          scenario: attackScenario,
        }),
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "Attack simulation failed.");
      }

      setIncident(data.incident);

      /*
       * Get the corresponding Fabric record.
       */
      const fabricIncidentId =
        data.incident?.fabric?.incidentId || data.incident?.id;

      if (data.incident?.fabric?.recorded && fabricIncidentId) {
        setFabricDefense({
          incidentId: fabricIncidentId,
          evidenceHash: data.incident.fabric.evidenceHash,
          validationStatus: data.incident.fabric.validationStatus,
          lifecycleStatus: data.incident.fabric.lifecycleStatus,
          defenseRule: data.incident.defenseRule,
        });
      } else {
        setFabricDefense(null);
      }

      await loadDashboard();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSimulationLoading(false);
    }
  };

  /* =========================================================
     FILTER INCIDENTS
     ========================================================= */

  const visibleIncidents = useMemo(() => {
    if (!dashboard?.incidents) return [];

    return dashboard.incidents.filter(
      (item) => severity === "All" || item.severity === severity,
    );
  }, [dashboard, severity]);

  const generatedRules = useMemo(
    () =>
      (dashboard?.incidents || []).filter(
        (item) => item.defenseRule,
      ),
    [dashboard],
  );

  /* =========================================================
     ACKNOWLEDGE INCIDENT
     ========================================================= */

  const acknowledgeIncident = async (incidentId) => {
    setAcknowledgingId(incidentId);
    setError("");

    try {
      const response = await fetch(
        `${API_URL}/incidents/${incidentId}/acknowledge`,
        {
          method: "POST",
        },
      );

      if (!response.ok) {
        throw new Error("The incident could not be acknowledged.");
      }

      await loadDashboard();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setAcknowledgingId("");
    }
  };

  /* =========================================================
     TRIAGE
     ========================================================= */

  const reviewTriage = async (incidentId) => {
    setTriageLoadingId(incidentId);
    setError("");

    try {
      const response = await fetch(`${API_URL}/incidents/${incidentId}/triage`);

      if (!response.ok) {
        throw new Error("The agent could not prepare a triage recommendation.");
      }

      const { triage: recommendation } = await response.json();

      setTriage(recommendation);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setTriageLoadingId("");
    }
  };

  const selectIncident = (selectedIncident) => {
    setIncident(selectedIncident);
    setFabricDefense(createFabricDefense(selectedIncident));
    setIntegrityResult(null);
    setPropagationResult(null);
  };

  const summary = dashboard?.summary;

  const currentIncident = incident || dashboard?.incidents?.[0] || null;

  const fabricValidationStatus =
    fabricDefense?.validationStatus ??
    currentIncident?.fabric?.validationStatus ??
    "NOT_RECORDED";

  const fabricLifecycleStatus =
    propagationResult?.fabric?.lifecycleStatus ??
    fabricDefense?.lifecycleStatus ??
    currentIncident?.fabric?.lifecycleStatus ??
    "NOT_RECORDED";

  const canPropagate =
    fabricLifecycleStatus === "READY_FOR_PROPAGATION";

  const isPropagated =
    fabricLifecycleStatus === "PROPAGATED";

  const riskScore =
    currentIncident?.analysis?.riskScore ??
    (fabricDefense ? fabricDefense.riskScore : null);

  const confidence =
    currentIncident?.analysis?.confidence ??
    (fabricDefense ? fabricDefense.agentConfidence : null);

  return (
    <main className="app-shell">
      {/* =====================================================
          HEADER
          ===================================================== */}

      <header className="topbar">
        <div className="brand-block">
          <div className="brand-row">
            <span className="brand-mark">◆</span>

            <p className="product-mark">SENTINEL / AGENTIC DEFENSE</p>
          </div>

          <h1>Adaptive Cyber Defense Console</h1>

          <p className="subtitle">
            Agentic threat analysis, automated defense generation and
            tamper-evident response provenance.
          </p>
        </div>

        <div className="topbar-actions">
          <span className="system-status">
            <StatusDot />
            SYSTEM ONLINE
          </span>

          <span className="fabric-status">
            <StatusDot />
            FABRIC CONNECTED
          </span>

          <label className="theme-toggle">
            <span>Dark</span>

            <input
              type="checkbox"
              checked={theme === "dark"}
              onChange={(event) =>
                setTheme(event.target.checked ? "dark" : "light")
              }
            />

            <span className="toggle-track" />
          </label>
          <button
            className="button button-primary"
            onClick={onNavigateToTerminal}
            type="button"
          >
            Launch Attack Simulator
          </button>
        </div>
      </header>

      {/* =====================================================
          ERROR
          ===================================================== */}

      {error && (
        <section className="notice" role="alert">
          <div>
            <strong>System notification</strong>

            <p>{error}</p>
          </div>

          <button className="button" type="button" onClick={loadDashboard}>
            Retry
          </button>
        </section>
      )}

      {/* =====================================================
          METRICS
          ===================================================== */}

      <section className="metrics">
        <Metric
          label="OPEN INCIDENTS"
          value={summary?.openIncidents ?? "-"}
          detail="Security events requiring review"
        />

        <Metric
          label="CRITICAL INCIDENTS"
          value={summary?.criticalIncidents ?? "-"}
          detail="Priority response queue"
          critical
        />

        <Metric
          label="AI CONFIDENCE"
          value={confidence !== null ? `${Math.round(confidence * 100)}%` : "—"}
          detail="Latest agent assessment"
        />

        <Metric
          label="FABRIC RECORDS"
          value={fabricDefense ? "1" : "—"}
          detail="Tamper-evident defense records"
        />
      </section>


      {/* =====================================================
          LIVE INCIDENT
          ===================================================== */}

      {currentIncident && (
        <section className="hero-incident">
          <div className="hero-heading">
            <div>
              <p className="eyebrow">LATEST SECURITY INCIDENT</p>

              <h2>{currentIncident?.title || "Brute Force Attack"}</h2>

              <p className="hero-description">
                {currentIncident?.fabric?.recorded
                  ? "Agentic analysis completed and defense response registered on the permissioned blockchain."
                  : "Agentic analysis completed. Fabric registration is awaiting successful validation."}
              </p>
            </div>

            <div className="hero-badges">
              <span className="severity severity-critical">
                {currentIncident?.severity || "Critical"}
              </span>

              <span
                className={`status ${
                  canPropagate || isPropagated ? "status-ready" : ""
                }`}
              >
                {isPropagated
                  ? "PROPAGATED"
                  : canPropagate
                    ? "READY FOR PROPAGATION"
                    : "FABRIC REGISTRATION PENDING"}
              </span>
            </div>
          </div>

          <div className="incident-overview">
            <div>
              <span>Incident ID</span>

              <strong>
                {currentIncident?.id || currentIncident?.incidentId}
              </strong>
            </div>

            <div>
              <span>MITRE ATT&CK</span>

              <strong>
                {currentIncident?.attack?.technique?.id ||
                  fabricDefense?.mitreTechnique ||
                  "T1110"}
              </strong>

              <small>
                {currentIncident?.attack?.technique?.name || "Brute Force"}
              </small>
            </div>

            <div>
              <span>Source IP</span>

              <strong>
                {currentIncident?.attack?.sourceIp ||
                  fabricDefense?.sourceIp ||
                  "—"}
              </strong>
            </div>

            <div>
              <span>Target</span>

              <strong>
                {currentIncident?.attack?.targetSystem ||
                  fabricDefense?.targetSystem ||
                  "—"}
              </strong>
            </div>

            <div>
              <span>Risk score</span>

              <strong className="risk-value">
                {riskScore ?? "—"}
                <small>/100</small>
              </strong>
            </div>
          </div>
        </section>
      )}

      <div className="pipeline">
        <PipelineStep
          number="01"
          title="Threat detected"
          description={
            currentIncident?.analysis?.reason ||
            `Detected ${currentIncident?.title || "security threat"} from telemetry.`
          }
        />

        <PipelineStep
          number="02"
          title="MITRE classification"
          description={`Activity classified as ${
            currentIncident?.attack?.technique?.id || "—"
          } — ${
            currentIncident?.attack?.technique?.name || "Unknown technique"
          }.`}
        />

        <PipelineStep
          number="03"
          title="Agentic reasoning"
          description={`Evidence evaluated with ${Math.round(
            (confidence || 0) * 100,
          )}% confidence and risk score ${riskScore ?? "—"}.`}
        />

        <PipelineStep
          number="04"
          title="Defense generated"
          description={
            currentIncident?.defenseRule?.explanation ||
            currentIncident?.defenseRule?.type ||
            "Adaptive defense rule generated by the agentic analysis layer."
          }
        />

        <PipelineStep
          number="05"
          title="Rule validated"
          description={
            currentIncident?.validation?.passed
              ? "Syntax, conflict and safety checks passed."
              : "Defense rule validation requires review."
          }
        />

        <PipelineStep
          number="06"
          title="Fabric provenance"
          description={
            fabricDefense
              ? "Evidence hash and defense decision committed to Hyperledger Fabric."
              : "Defense provenance has not yet been recorded."
          }
        />

        <PipelineStep
          number="07"
          title="Ready for propagation"
          description={
            fabricDefense?.lifecycleStatus === "READY_FOR_PROPAGATION"
              ? "Validated defense is eligible for downstream enforcement."
              : fabricDefense?.lifecycleStatus === "PROPAGATED"
                ? "Validated defense has completed controlled propagation."
                : "Defense is progressing through the response lifecycle."
          }
        />
      </div>
      {/* =====================================================
          AI + DEFENSE
          ===================================================== */}

      {currentIncident && (
        <section className="analysis-grid">
          <article className="panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">AGENTIC AI</p>

                <h2>Threat reasoning</h2>
              </div>

              <span className="confidence-badge">
                {confidence !== null
                  ? `${Math.round(confidence * 100)}% confidence`
                  : "—"}
              </span>
            </div>

            <p className="analysis-reason">
              {currentIncident?.analysis?.reason ||
                "Threat analysis completed."}
            </p>

            <div className="reasoning-list">
              {(currentIncident?.analysis?.reasoning || []).map(
                (reason, index) => (
                  <div className="reasoning-item" key={reason}>
                    <span>{String(index + 1).padStart(2, "0")}</span>

                    <p>{reason}</p>
                  </div>
                ),
              )}
            </div>

            <div className="evidence-block">
              <h3>Evidence collected</h3>

              <ul>
                {(currentIncident?.analysis?.evidence || []).map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          </article>

          <article className="panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">AUTOMATED RESPONSE</p>

                <h2>Defense rule</h2>
              </div>

              <span className="validation-badge">VALIDATED</span>
            </div>

            <div className="rule-summary">
              <div>
                <span>Rule type</span>

                <strong>
                  {currentIncident?.defenseRule?.type ||
                    fabricDefense?.defenseRule?.type ||
                    "—"}
                </strong>
              </div>

              <div>
                <span>Trigger</span>

                <strong>
                  {currentIncident?.defenseRule?.condition?.failedAttempts
                    ? `${currentIncident?.defenseRule.condition.failedAttempts} failures / ${
                        currentIncident?.defenseRule.condition.windowSeconds ??
                        60
                      } sec`
                    : currentIncident?.defenseRule?.condition?.requestsPerSecond
                      ? `${currentIncident?.defenseRule.condition.requestsPerSecond} requests/sec`
                      : currentIncident?.defenseRule?.condition?.sourceIP
                        ? `Source IP ${currentIncident?.defenseRule.condition.sourceIP}`
                        : "Adaptive telemetry condition"}
                </strong>
              </div>

              <div>
                <span>Action</span>

                <strong>
                  {currentIncident?.defenseRule?.action?.type ||
                    "TEMPORARY_BLOCK"}
                </strong>
              </div>

              <div>
                <span>Duration</span>

                <strong>
                  {currentIncident?.defenseRule?.action?.durationSeconds ?? 300}{" "}
                  seconds
                </strong>
              </div>
            </div>

            <div className="validation-grid">
              {["syntax", "conflict", "safety"].map((check) => (
                <div key={check}>
                  <span className="check-icon">✓</span>

                  <span>{check.charAt(0).toUpperCase() + check.slice(1)}</span>
                </div>
              ))}
            </div>
          </article>
        </section>
      )}

      {/* =====================================================
          FABRIC PROVENANCE
          ===================================================== */}

      {fabricDefense && (
        <section className="panel fabric-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">BLOCKCHAIN PROVENANCE</p>

              <h2>Hyperledger Fabric record</h2>
            </div>

            <span className="fabric-recorded">
              <StatusDot />
              RECORDED
            </span>
          </div>

          <div className="fabric-grid">
            <div>
              <span>Network</span>
              <strong>mychannel</strong>
            </div>

            <div>
              <span>Chaincode</span>
              <strong>defenseRegistry</strong>
            </div>

            <div>
              <span>Validation</span>
              <strong>{fabricDefense.validationStatus}</strong>
            </div>

            <div>
              <span>Lifecycle</span>
              <strong>{fabricDefense.lifecycleStatus}</strong>
            </div>
          </div>

          <div className="hash-box">
            <span>Evidence SHA-256</span>

            <code>{fabricDefense.evidenceHash}</code>
          </div>

          <div className="ledger-message">
            <span className="ledger-icon">◆</span>

            <div>
              <strong>Defense provenance secured</strong>

              <p>
                The evidence fingerprint, AI confidence, risk score and
                generated defense rule are recorded against the incident on the
                permissioned ledger.
              </p>
            </div>
          </div>
        </section>
      )}

      {/* =====================================================
          EVIDENCE INTEGRITY
          ===================================================== */}

      {fabricDefense && (
        <section className="panel integrity-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">FORENSIC VERIFICATION</p>

              <h2>Evidence Integrity</h2>
            </div>

            <span
              className={`integrity-status ${
                integrityResult?.status === "VERIFIED"
                  ? "verified"
                  : integrityResult?.status === "TAMPER_DETECTED"
                    ? "tampered"
                    : ""
              }`}
            >
              {integrityResult?.status === "VERIFIED"
                ? "✓ VERIFIED"
                : integrityResult?.status === "TAMPER_DETECTED"
                  ? "⚠ TAMPER DETECTED"
                  : "NOT VERIFIED"}
            </span>
          </div>

          <p className="integrity-description">
            Recomputes the SHA-256 fingerprint of the evidence and compares it
            with the immutable evidence hash recorded on Hyperledger Fabric.
          </p>

          <div className="integrity-actions">
            <button
              className="button button-primary"
              type="button"
              onClick={() => verifyEvidenceIntegrity(false)}
              disabled={integrityLoading}
            >
              {integrityLoading ? "Verifying..." : "Verify Evidence"}
            </button>

            <button
              className="button button-quiet btn-danger-outline"
              type="button"
              onClick={() => verifyEvidenceIntegrity(true)}
              disabled={integrityLoading}
            >
              Simulate Tampering
            </button>
          </div>

          {integrityResult?.verification && (
            <div className="hash-comparison">
              <div className="hash-card">
                <span className="hash-label">Fabric Recorded SHA-256</span>

                <code>{integrityResult.verification.expectedHash}</code>
              </div>

              <div className="hash-card">
                <span className="hash-label">Current Evidence SHA-256</span>

                <code>{integrityResult.verification.computedHash}</code>
              </div>
            </div>
          )}

          {integrityResult?.reason && (
            <div
              className={`integrity-message ${
                integrityResult.status === "VERIFIED"
                  ? "success"
                  : integrityResult.status === "TAMPER_DETECTED"
                    ? "danger"
                    : "warning"
              }`}
            >
              <strong>
                {integrityResult.status === "VERIFIED"
                  ? "Evidence integrity confirmed"
                  : integrityResult.status === "TAMPER_DETECTED"
                    ? "Evidence tampering detected"
                    : "Verification error"}
              </strong>

              <p>{integrityResult.reason}</p>
            </div>
          )}

          {integrityResult?.evidence && (
            <div className="evidence-comparison">
              <div>
                <h3>Original Evidence</h3>

                <ul>
                  {integrityResult.evidence.original.map((item, index) => (
                    <li key={`original-${index}`}>{item}</li>
                  ))}
                </ul>
              </div>

              <div>
                <h3>Current Evidence</h3>

                <ul>
                  {integrityResult.evidence.current.map((item, index) => (
                    <li key={`current-${index}`}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </section>
      )}

      <section className="panel propagation-panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">ADAPTIVE DEFENSE</p>

            <h2>Defense propagation</h2>

            <p className="panel-description">
              Propagate the validated defense rule and record its lifecycle
              transition on Hyperledger Fabric.
            </p>
          </div>

          <span
            className={`propagation-state ${
              propagationResult?.success
                ? "propagation-state-success"
                : propagationResult?.success === false
                  ? "propagation-state-error"
                  : isPropagated
                    ? "propagation-state-success"
                  : canPropagate
                    ? "propagation-state-ready"
                    : ""
            }`}
          >
            <span className="propagation-state-dot" />

            {propagationResult?.success
              ? "PROPAGATED"
              : propagationResult?.success === false
                ? "FAILED"
                : isPropagated
                  ? "PROPAGATED"
                : canPropagate
                  ? "READY FOR PROPAGATION"
                  : "AWAITING FABRIC REGISTRATION"}
          </span>
        </div>

        {/* STATUS CARDS */}
        <div className="propagation-grid">
          {/* VALIDATION */}
          <article className="propagation-card">
            <div className="propagation-card-icon">✓</div>

            <div>
              <span className="propagation-card-label">Validation</span>

              <strong
                className={`propagation-card-value ${
                  fabricValidationStatus === "VALIDATED" ? "success" : "warning"
                }`}
              >
                {fabricValidationStatus}
              </strong>

              <small>Syntax, conflict and safety checks passed</small>
            </div>
          </article>

          {/* FABRIC LIFECYCLE */}
          <article className="propagation-card">
            <div className="propagation-card-icon lifecycle">↻</div>

            <div>
              <span className="propagation-card-label">Fabric lifecycle</span>

              <strong
                className={`propagation-card-value ${
                  propagationResult?.success ? "success" : "warning"
                }`}
              >
                {propagationResult?.fabric?.lifecycleStatus ||
                  fabricLifecycleStatus}
              </strong>

              <small>Recorded on the permissioned ledger</small>
            </div>
          </article>

          {/* DEFENSE RULE */}
          <article className="propagation-card">
            <div className="propagation-card-icon rule">◇</div>

            <div>
              <span className="propagation-card-label">Defense rule</span>

              <strong className="propagation-card-value rule-value">
                {currentIncident?.defenseRule?.type ||
                  currentIncident?.analysis?.defenseRule?.type ||
                  fabricDefense?.defenseRule?.type ||
                  "AUTHENTICATION_RATE_LIMIT"}
              </strong>

              <small>Generated from the agentic analysis</small>
            </div>
          </article>
        </div>

        {/* PROPAGATION ACTION */}
        {!propagationResult?.success && !isPropagated && (
          <div className="propagation-action-row">
            <div>
              <strong>Controlled enforcement</strong>

              <p>
                Apply the validated rule through the controlled propagation
                stage.
              </p>
            </div>

            <button
              type="button"
              className="button button-primary propagation-button"
              onClick={propagateDefense}
              disabled={
                propagationLoading ||
                !canPropagate
              }
            >
              {propagationLoading ? "Propagating..." : "Propagate Defense"}
            </button>
          </div>
        )}

        {/* SUCCESS RESULT */}
        {propagationResult?.success && (
          <div className="propagation-success">
            <div className="propagation-success-heading">
              <span className="propagation-success-icon">✓</span>

              <div>
                <strong>Defense successfully propagated</strong>

                <p>
                  The validated defense transitioned to <b>PROPAGATED</b> and
                  the lifecycle state was updated on Hyperledger Fabric.
                </p>
              </div>
            </div>

            {/* RESULT DETAILS */}
            <div className="propagation-details">
              <div>
                <span>Rule ID</span>

                <code>{propagationResult.propagation?.ruleId || "—"}</code>
              </div>

              <div>
                <span>Fabric lifecycle</span>

                <strong>
                  {propagationResult.fabric?.lifecycleStatus || "PROPAGATED"}
                </strong>
              </div>

              <div>
                <span>Propagation mode</span>

                <strong>
                  {propagationResult.propagation?.simulated
                    ? "Controlled Simulation"
                    : "Active"}
                </strong>
              </div>

              <div>
                <span>Propagated at</span>

                <strong>
                  {propagationResult.propagation?.propagatedAt
                    ? new Date(
                        propagationResult.propagation.propagatedAt,
                      ).toLocaleString()
                    : "—"}
                </strong>
              </div>
            </div>
          </div>
        )}

        {/* ERROR RESULT */}
        {propagationResult?.success === false && (
          <div className="propagation-error">
            <strong>Defense propagation failed</strong>

            <p>{propagationResult.error}</p>
          </div>
        )}
      </section>

      {/* =====================================================
          INCIDENT QUEUE
          ===================================================== */}

      <section className="panel workspace">
        <div className="section-heading">
          <div>
            <p className="eyebrow">DETECTION QUEUE</p>

            <h2>Recent incidents</h2>
          </div>

          <label className="filter-control">
            <span>Severity</span>

            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              {severityOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="incident-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Incident</th>
                <th>Severity</th>
                <th>MITRE</th>
                <th>Asset</th>
                <th>Observed</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>

            <tbody>
              {isLoading && !dashboard && (
                <tr>
                  <td colSpan="7" className="empty-row">
                    Loading telemetry...
                  </td>
                </tr>
              )}

              {!isLoading && visibleIncidents.length === 0 && (
                <tr>
                  <td colSpan="7" className="empty-row">
                    No incidents match this severity.
                  </td>
                </tr>
              )}

              {visibleIncidents.map((item) => (
                <tr key={item.id}>
                  <td>
                    <span className="incident-id">{item.id}</span>

                    <strong className="incident-title">{item.title}</strong>

                    <span className="incident-source">
                      Source {item.source}
                    </span>
                  </td>

                  <td>
                    <span
                      className={`severity severity-${item.severity.toLowerCase()}`}
                    >
                      {item.severity}
                    </span>
                  </td>

                  <td>
                    <span className="mitre-chip">
                      {item.attack?.technique?.id || "-"}
                    </span>
                  </td>

                  <td>{item.asset}</td>

                  <td className="timestamp">
                    {formatTimestamp(item.observedAt)}
                  </td>

                  <td>
                    <span
                      className={`status status-${item.status.toLowerCase()}`}
                    >
                      {item.status}
                    </span>
                  </td>

                  <td>
                    <div className="action-buttons">
                      <button
                        className="button button-quiet"
                        type="button"
                        onClick={() => reviewTriage(item.id)}
                        disabled={triageLoadingId === item.id}
                      >
                        {triageLoadingId === item.id
                          ? "Preparing..."
                          : "Triage"}
                      </button>

                      <button
                        className="button button-quiet"
                        type="button"
                        onClick={() => acknowledgeIncident(item.id)}
                        disabled={
                          item.status === "Acknowledged" ||
                          acknowledgingId === item.id
                        }
                      >
                        {acknowledgingId === item.id
                          ? "Saving..."
                          : "Acknowledge"}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel rule-history-panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">AGENT-GENERATED DEFENSES</p>

            <h2>Generated IDS rules</h2>
          </div>

          <span className="rule-history-count">
            {generatedRules.length} recorded
          </span>
        </div>

        <div className="rule-history-list">
          {generatedRules.length === 0 && (
            <p className="rule-history-empty">
              No generated defense rules are available yet.
            </p>
          )}

          {generatedRules.map((item) => (
            <article className="rule-history-item" key={item.id}>
              <div className="rule-history-heading">
                <div>
                  <span className="incident-id">{item.defenseRule.ruleId}</span>

                  <h3>{item.defenseRule.ruleName || "Adaptive IDS Rule"}</h3>
                </div>

                <button
                  className="button button-quiet"
                  type="button"
                  onClick={() => selectIncident(item)}
                >
                  View Rule
                </button>
              </div>

              <div className="rule-history-metadata">
                <div>
                  <span>Attack type</span>
                  <strong>{item.attack?.type || item.title}</strong>
                </div>

                <div>
                  <span>MITRE ATT&CK</span>
                  <strong>{item.attack?.technique?.id || "—"}</strong>
                </div>

                <div>
                  <span>Rule type</span>
                  <strong>{item.defenseRule.type || "—"}</strong>
                </div>

                <div>
                  <span>Fabric lifecycle</span>
                  <strong>
                    {item.fabric?.lifecycleStatus ||
                      item.validation?.status ||
                      "NOT_RECORDED"}
                  </strong>
                </div>
              </div>

              <div className="rule-history-reasoning">
                <span>Why this rule was generated</span>
                <p>
                  {item.defenseRule.reason ||
                    item.defenseRule.explanation ||
                    item.analysis?.reason ||
                    "No agent rationale is available for this rule."}
                </p>

                {item.analysis?.reasoning?.length > 0 && (
                  <ul>
                    {item.analysis.reasoning.slice(0, 3).map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                )}
              </div>
            </article>
          ))}
        </div>
      </section>

      {/* =====================================================
          TRIAGE
          ===================================================== */}

      <div>
        <span>Trigger</span>

        <strong>
          {currentIncident?.defenseRule?.condition?.failedAttempts
            ? `${currentIncident?.defenseRule.condition.failedAttempts} failures / ${
                currentIncident?.defenseRule.condition.windowSeconds ?? 60
              } sec`
            : currentIncident?.defenseRule?.condition?.requestsPerSecond
              ? `${currentIncident?.defenseRule.condition.requestsPerSecond} requests/sec`
              : currentIncident?.defenseRule?.condition?.sourceIP
                ? `Source IP ${currentIncident?.defenseRule.condition.sourceIP}`
                : "Adaptive telemetry condition"}
        </strong>
      </div>

      {/* =====================================================
          SYSTEM CONTEXT
          ===================================================== */}

      <section className="context-grid">
        <article className="panel context-panel">
          <p className="eyebrow">SYSTEM STATUS</p>

          <h2>Defense infrastructure</h2>

          <div className="source-list">
            <div>
              <span>Detection engine</span>

              <strong>ONLINE</strong>
            </div>

            <div>
              <span>Agentic analysis</span>

              <strong>ONLINE</strong>
            </div>

            <div>
              <span>Rule validator</span>

              <strong>ONLINE</strong>
            </div>

            <div>
              <span>Hyperledger Fabric</span>

              <strong>CONNECTED</strong>
            </div>
          </div>
        </article>

        <article className="panel context-panel">
          <p className="eyebrow">RESEARCH DEMONSTRATOR</p>

          <h2>Adaptive cyber defense</h2>

          <p className="context-copy">
            This controlled environment demonstrates a closed-loop security
            workflow in which detected threats are classified, investigated by
            an agentic reasoning layer, converted into defense rules, validated
            and recorded on a permissioned blockchain before propagation.
          </p>

          <p className="generated-at">
            Last telemetry refresh:{" "}
            {dashboard ? formatTimestamp(dashboard.generatedAt) : "Waiting"}
          </p>
        </article>
      </section>
    </main>
  );
}
            
export default Dashboard;
