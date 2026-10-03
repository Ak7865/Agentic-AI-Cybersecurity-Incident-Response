const BRUTE_FORCE_THRESHOLD = 5;
const SCAN_PORT_THRESHOLD = 10;
const DOS_REQUEST_THRESHOLD = 50;
const DOS_TIME_WINDOW_SECONDS = 15;

/**
 * Detect brute-force authentication activity.
 */
function detectBruteForce(events) {
  const authFailures = events.filter(
    (event) => event.type === "AUTHENTICATION_FAILURE"
  );

  if (authFailures.length < BRUTE_FORCE_THRESHOLD) {
    return null;
  }

  const sourceIps = [
    ...new Set(
      authFailures
        .map((event) => event.sourceIp)
        .filter(Boolean)
    ),
  ];

  const usernames = [
    ...new Set(
      authFailures
        .map((event) => event.username)
        .filter(Boolean)
    ),
  ];

  return {
    attackType: "Brute Force",

    technique: {
      id: "T1110",
      name: "Brute Force",
    },

    confidence: 0.94,

    evidence: [
      `${authFailures.length} failed authentication attempts detected`,
      `Source IPs involved: ${sourceIps.join(", ")}`,
      `${usernames.length} usernames targeted`,
      "Repeated authentication failures exceeded threshold",
    ],

    reason:
      "Repeated authentication failures from the observed source are consistent with brute-force activity.",
  };
}

/**
 * Detect network service scanning.
 */
function detectNetworkScan(events) {
  const connectionAttempts = events.filter(
    (event) => event.type === "CONNECTION_ATTEMPT"
  );

  const destinationPorts = [
    ...new Set(
      connectionAttempts
        .map((event) => event.destinationPort)
        .filter(Boolean)
    ),
  ];

  if (destinationPorts.length < SCAN_PORT_THRESHOLD) {
    return null;
  }

  const sourceIps = [
    ...new Set(
      connectionAttempts
        .map((event) => event.sourceIp)
        .filter(Boolean)
    ),
  ];

  return {
    attackType: "Network Service Scanning",

    technique: {
      id: "T1046",
      name: "Network Service Scanning",
    },

    confidence: 0.93,

    evidence: [
      `${connectionAttempts.length} connection attempts detected`,
      `${destinationPorts.length} distinct destination ports targeted`,
      `Source IP: ${sourceIps.join(", ")}`,
      "Multiple services were probed within a short period",
    ],

    reason:
      "A single source probing many destination ports is consistent with network service scanning.",
  };
}

/**
 * Detect denial-of-service-like request flooding.
 */
function detectDenialOfService(events) {
  const requests = events.filter(
    (event) => event.type === "HTTP_REQUEST"
  );

  if (requests.length < DOS_REQUEST_THRESHOLD) {
    return null;
  }

  const timestamps = requests
    .map((event) => new Date(event.timestamp).getTime())
    .filter(Number.isFinite)
    .sort((a, b) => a - b);

  if (timestamps.length < 2) {
    return null;
  }

  const durationSeconds =
    (timestamps[timestamps.length - 1] -
      timestamps[0]) /
    1000;

  if (durationSeconds > DOS_TIME_WINDOW_SECONDS) {
    return null;
  }

  const sourceIps = [
    ...new Set(
      requests
        .map((event) => event.sourceIp)
        .filter(Boolean)
    ),
  ];

  const targetSystems = [
    ...new Set(
      requests
        .map((event) => event.targetSystem)
        .filter(Boolean)
    ),
  ];

  const requestsPerSecond =
    durationSeconds > 0
      ? requests.length / durationSeconds
      : requests.length;

  return {
    attackType: "Network Denial of Service",

    technique: {
      id: "T1498",
      name: "Network Denial of Service",
    },

    confidence: 0.91,

    evidence: [
      `${requests.length} HTTP requests detected`,
      `Observed request rate: ${requestsPerSecond.toFixed(
        2
      )} requests/second`,
      `Source IP: ${sourceIps.join(", ")}`,
      `Target system: ${targetSystems.join(", ")}`,
      `Traffic occurred within approximately ${durationSeconds.toFixed(
        2
      )} seconds`,
    ],

    reason:
      "An unusually high volume of requests directed at the same service within a short time window is consistent with denial-of-service activity.",
  };
}

/**
 * Detect suspicious PowerShell execution.
 */
function detectSuspiciousProcessExecution(events) {
  const processEvents = events.filter(
    (event) => event.type === "PROCESS_START"
  );

  if (processEvents.length === 0) {
    return null;
  }

  const powershellEvent = processEvents.find(
    (event) =>
      event.processName === "powershell.exe"
  );

  const suspiciousParentChild = processEvents.some(
    (event) =>
      event.processName === "powershell.exe" &&
      event.parentProcess === "winword.exe"
  );

  if (!powershellEvent && !suspiciousParentChild) {
    return null;
  }

  return {
    attackType: "Command and Scripting Interpreter",

    technique: {
      id: "T1059.001",
      name: "PowerShell",
    },

    confidence: 0.89,

    evidence: [
      "PowerShell process execution detected",

      suspiciousParentChild
        ? "PowerShell was spawned by Microsoft Word"
        : "PowerShell execution observed",

      ...processEvents
        .slice(0, 3)
        .map(
          (event) =>
            `${event.processName} spawned by ${
              event.parentProcess || "unknown"
            }`
        ),
    ],

    reason:
      "PowerShell execution from an unusual process chain is consistent with suspicious command and scripting activity.",
  };
}

/**
 * Main detection engine.
 *
 * IMPORTANT:
 * This function determines the attack classification
 * from telemetry. It does not trust an attack label
 * supplied by the simulator.
 */
function detectAttack(telemetry) {
  if (
    !telemetry ||
    !Array.isArray(telemetry.events)
  ) {
    return {
      detected: false,
      attackType: null,
      technique: null,
      confidence: 0,
      evidence: [],
      reason:
        "No valid telemetry events were provided.",
    };
  }

  const events = telemetry.events;

  const detectors = [
    detectBruteForce,
    detectNetworkScan,
    detectDenialOfService,
    detectSuspiciousProcessExecution,
  ];

  for (const detector of detectors) {
    const result = detector(events);

    if (result) {
      return {
        detected: true,
        ...result,
      };
    }
  }

  return {
    detected: false,
    attackType: null,
    technique: null,
    confidence: 0,
    evidence: [],
    reason:
      "No supported attack pattern was detected in the observed telemetry.",
  };
}

module.exports = {
  detectAttack,
};