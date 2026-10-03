const crypto = require("crypto");

function createEvent(type, data = {}, offsetSeconds = 0) {
  return {
    eventId: crypto.randomUUID(),
    timestamp: new Date(
      Date.now() + offsetSeconds * 1000
    ).toISOString(),
    type,
    ...data,
  };
}

/**
 * Brute-force authentication telemetry.
 *
 * IMPORTANT:
 * The simulator does NOT specify the attack type.
 * The detector must infer it from the events.
 */
function generateBruteForceTelemetry() {
  const sourceIp = "192.168.1.50";
  const targetSystem = "SYSTEM-A";

  const events = [];

  for (let i = 0; i < 12; i++) {
    events.push(
      createEvent(
        "AUTHENTICATION_FAILURE",
        {
          sourceIp,
          targetSystem,
          username: `test-user-${(i % 3) + 1}`,
        },
        i * 3
      )
    );
  }

  return {
    attackId: crypto.randomUUID(),
    sourceIp,
    targetSystem,
    events,
  };
}

/**
 * Network service scanning telemetry.
 *
 * One source attempts connections to many ports.
 */
function generateNetworkScanTelemetry() {
  const sourceIp = "192.168.1.60";
  const targetSystem = "SYSTEM-A";

  const ports = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    3389,
    8080,
  ];

  const events = ports.map((port, index) =>
    createEvent(
      "CONNECTION_ATTEMPT",
      {
        sourceIp,
        targetSystem,
        destinationPort: port,
        protocol: "TCP",
        connectionStatus: "REFUSED",
      },
      index
    )
  );

  return {
    attackId: crypto.randomUUID(),
    sourceIp,
    targetSystem,
    events,
  };
}

/**
 * Controlled DoS-like telemetry.
 *
 * This generates telemetry only.
 * It does NOT send traffic to an external/public target.
 */
function generateDosTelemetry() {
  const sourceIp = "192.168.1.70";
  const targetSystem = "SYSTEM-A";

  const events = [];

  for (let i = 0; i < 100; i++) {
    events.push(
      createEvent(
        "HTTP_REQUEST",
        {
          sourceIp,
          targetSystem,
          destinationPort: 80,
          method: "GET",
          path: "/",
          statusCode: 200,
        },
        i * 0.1
      )
    );
  }

  return {
    attackId: crypto.randomUUID(),
    sourceIp,
    targetSystem,
    events,
  };
}

/**
 * Suspicious process execution telemetry.
 */
function generateSuspiciousProcessTelemetry() {
  const sourceIp = "192.168.1.80";
  const targetSystem = "SYSTEM-A";

  const events = [
    createEvent("PROCESS_START", {
      sourceIp,
      targetSystem,
      processName: "powershell.exe",
      parentProcess: "winword.exe",
      commandLine: "powershell -enc <redacted>",
    }),

    createEvent("PROCESS_START", {
      sourceIp,
      targetSystem,
      processName: "cmd.exe",
      parentProcess: "powershell.exe",
      commandLine: "cmd.exe /c whoami",
    }),

    createEvent("PROCESS_START", {
      sourceIp,
      targetSystem,
      processName: "net.exe",
      parentProcess: "cmd.exe",
      commandLine: "net user",
    }),
  ];

  return {
    attackId: crypto.randomUUID(),
    sourceIp,
    targetSystem,
    events,
  };
}

/**
 * Default scenario.
 */
function generateAttackTelemetry() {
  return generateBruteForceTelemetry();
}

module.exports = {
  generateAttackTelemetry,
  generateBruteForceTelemetry,
  generateNetworkScanTelemetry,
  generateDosTelemetry,
  generateSuspiciousProcessTelemetry,
};