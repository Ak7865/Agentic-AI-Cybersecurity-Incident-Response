import { useState } from "react";
import "./App.css";

function App() {
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(false);

  async function simulateAttack() {
    setLoading(true);

    try {
      const response = await fetch(
        "http://localhost:5000/api/attack/simulate",
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (data.success) {
        setIncident(data.incident);
      }
    } catch (error) {
      console.error(error);
      alert("Backend is not running.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>Agentic Cyber Defense</h1>
          <p>Controlled Cybersecurity Simulation</p>
        </div>

        <span className="status">
          ● SYSTEM ONLINE
        </span>
      </header>

      <main>
        <section className="simulation-card">
          <h2>Attack Simulation</h2>

          <p>
            Target System: <strong>SYSTEM-A</strong>
          </p>

          <p>
            Attack Type: <strong>Brute Force</strong>
          </p>

          <button
            onClick={simulateAttack}
            disabled={loading}
          >
            {loading
              ? "Simulating..."
              : "Simulate Brute Force Attack"}
          </button>
        </section>

        {incident && (
          <>
            <section className="card">
              <h2>Incident Detected</h2>

              <div className="grid">
                <div>
                  <label>Incident ID</label>
                  <strong>{incident.incidentId}</strong>
                </div>

                <div>
                  <label>Status</label>
                  <strong className="success">
                    {incident.status}
                  </strong>
                </div>

                <div>
                  <label>Attack</label>
                  <strong>
                    {incident.attack.type}
                  </strong>
                </div>

                <div>
                  <label>MITRE ATT&CK</label>
                  <strong>
                    {incident.attack.technique.id}
                  </strong>
                </div>

                <div>
                  <label>Source</label>
                  <strong>
                    {incident.attack.sourceIp}
                  </strong>
                </div>

                <div>
                  <label>Failed Attempts</label>
                  <strong>
                    {incident.attack.failedAttempts}
                  </strong>
                </div>
              </div>
            </section>

            <section className="card">
              <h2>AI Analysis</h2>

              <div className="confidence">
                Confidence:{" "}
                <strong>
                  {incident.analysis.confidence * 100}%
                </strong>
              </div>

              <p>
                {incident.analysis.reason}
              </p>

              <h3>Evidence</h3>

              <ul>
                {incident.analysis.evidence.map(
                  (item, index) => (
                    <li key={index}>{item}</li>
                  )
                )}
              </ul>
            </section>

            <section className="card">
              <h2>Defense Rule</h2>

              <pre>
                {JSON.stringify(
                  incident.defenseRule,
                  null,
                  2
                )}
              </pre>

              <div className="validation">
                <strong>
                  Validation:{" "}
                </strong>

                {incident.validation.status}
              </div>
            </section>

            <section className="card">
              <h2>Defense Distribution</h2>

              <div className="systems">
                <span>System A ✓</span>
                <span>System B ✓</span>
                <span>System C ✓</span>
                <span>System D ✓</span>
              </div>

              <p className="note">
                Distribution is simulated at this stage.
                Hyperledger Fabric integration will be
                added next.
              </p>
            </section>
          </>
        )}
      </main>
    </div>
  );
}

export default App;