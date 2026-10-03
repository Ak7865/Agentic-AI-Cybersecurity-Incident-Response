import { useState, useRef, useEffect } from "react";
import "./CmdSimulator.css";

const API_URL = "http://localhost:5000/api";

const attackScenarios = [
  { value: "auth", label: "Authentication Brute Force", cmd: "auth" },
  { value: "process", label: "Suspicious PowerShell Chain", cmd: "process" },
];

export default function CmdSimulator({ onExit }) {
  const [history, setHistory] = useState([
    "Microsoft Windows [Version 10.0.19045.3448]",
    "(c) Microsoft Corporation. All rights reserved.",
    "",
    "Type 'help' to see available commands."
  ]);
  const [input, setInput] = useState("");
  const [isSimulating, setIsSimulating] = useState(false);
  const endRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history]);

  const handleCommand = async (e) => {
    e.preventDefault();
    if (!input.trim()) {
      setHistory((prev) => [...prev, "C:\\Users\\Administrator>"]);
      return;
    }

    const cmd = input.trim();
    const newHistory = [...history, `C:\\Users\\Administrator>${cmd}`];
    setInput("");

    const args = cmd.toLowerCase().split(" ").filter(Boolean);
    const command = args[0];

    if (command === "help") {
      newHistory.push("");
      newHistory.push("Available Commands:");
      newHistory.push("  help              - Shows this help message");
      newHistory.push("  simulate --list   - Lists available attack simulations");
      newHistory.push("  simulate [id]     - Runs an attack simulation by ID (e.g., 'simulate process')");
      newHistory.push("  cls               - Clears the screen");
      newHistory.push("  exit              - Exits the command prompt and returns to Dashboard");
      newHistory.push("");
      setHistory(newHistory);
    } else if (command === "cls" || command === "clear") {
      setHistory([]);
    } else if (command === "exit") {
      onExit();
    } else if (command === "simulate") {
      if (args[1] === "--list") {
        newHistory.push("");
        newHistory.push("Available Attack Scenarios:");
        attackScenarios.forEach((s) => {
          newHistory.push(`  ${s.cmd.padEnd(10)} - ${s.label}`);
        });
        newHistory.push("");
        setHistory(newHistory);
      } else if (args[1]) {
        const scenario = attackScenarios.find((s) => s.cmd === args[1]);
        if (!scenario) {
          newHistory.push(`Unknown simulation ID: '${args[1]}'. Type 'simulate --list' to see available options.`);
          setHistory(newHistory);
        } else {
          setHistory(newHistory);
          await runSimulation(scenario.value);
        }
      } else {
        newHistory.push("Usage: simulate [id]. Type 'simulate --list' for options.");
        setHistory(newHistory);
      }
    } else {
      newHistory.push(`'${command}' is not recognized as an internal or external command,`);
      newHistory.push("operable program or batch file.");
      setHistory(newHistory);
    }
  };

  const runSimulation = async (scenarioValue) => {
    setIsSimulating(true);
    setHistory((prev) => [...prev, "", "[!] Initiating exploit sequence...", "[!] Injecting payload into target system..."]);

    try {
      const response = await fetch(`${API_URL}/attack/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario: scenarioValue }),
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "Attack simulation failed.");
      }

      setHistory((prev) => [
        ...prev,
        "[!] Simulation completed successfully.",
        "[!] Agentic response received.",
        "",
        "--- SIMULATION RESULT ---",
        `Incident ID : ${data.incident.id}`,
        `Severity    : ${data.incident.severity}`,
        `Attack Type : ${data.incident.attack.type}`,
        `Defense Rule: ${data.incident.defenseRule.ruleName}`,
        `Action      : ${data.incident.defenseRule.action.type}`,
        `Validation  : ${data.incident.validation.status}`,
        "-------------------------",
        ""
      ]);

    } catch (err) {
      setHistory((prev) => [...prev, `[ERROR] ${err.message}`, ""]);
    } finally {
      setIsSimulating(false);
      setTimeout(() => {
        inputRef.current?.focus();
      }, 100);
    }
  };

  return (
    <div className="cmd-window" onClick={() => inputRef.current?.focus()}>
      <div className="cmd-header">
        <img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggZmlsbD0iI2ZmZiIgZD0iTTAgMGgxNnYxNkgweiIvPjxwYXRoIGZpbGw9IiMwMDAiIGQ9Ik0xIDFoMTR2MTRIMXoiLz48cGF0aCBmaWxsPSIjY2NjIiBkPSJNMCAwaDE2djNIMHoiLz48L3N2Zz4=" alt="cmd icon" className="cmd-icon" />
        <span>Command Prompt</span>
        <div className="cmd-controls">
          <span>_</span>
          <span>□</span>
          <span>✕</span>
        </div>
      </div>
      <div className="cmd-body">
        {history.map((line, idx) => (
          <div key={idx} className="cmd-line">{line}</div>
        ))}
        {!isSimulating && (
          <form className="cmd-input-line" onSubmit={handleCommand}>
            <span className="cmd-prompt">C:\Users\Administrator&gt;</span>
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="cmd-input"
              autoFocus
              autoComplete="off"
              spellCheck="false"
            />
          </form>
        )}
        {isSimulating && (
          <div className="cmd-line">
            [!] Awaiting AI incident response... <span className="cmd-blink">_</span>
          </div>
        )}
        <div ref={endRef} />
      </div>
    </div>
  );
}
