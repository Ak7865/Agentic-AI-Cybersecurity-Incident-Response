import { useState } from "react";
import Dashboard from "./Dashboard.jsx";
import CmdSimulator from "./CmdSimulator.jsx";

function App() {
  const [currentView, setCurrentView] = useState("dashboard");

  if (currentView === "terminal") {
    return <CmdSimulator onExit={() => setCurrentView("dashboard")} />;
  }

  return <Dashboard onNavigateToTerminal={() => setCurrentView("terminal")} />;
}

export default App;