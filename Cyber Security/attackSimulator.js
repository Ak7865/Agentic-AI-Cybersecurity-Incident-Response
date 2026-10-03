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

function resolveContext(context = {}) {
  return {
    sourceIp:
      context.sourceIp || "192.168.1.50",
    targetSystem:
      context.targetSystem ||
      context.endpointId ||
      "SYSTEM-A",
    endpointId:
      context.endpointId ||
      context.targetSystem ||
      "SYSTEM-A",
    labId:
      context.labId || "LAB-01",
    collegeId:
      context.collegeId || "COLLEGE-01",
    instituteId:
      context.instituteId || "ASTU-NETWORK",
  };
}

/**
 * Brute-force authentication telemetry.
 *
 * IMPORTANT:
 * The simulator does NOT specify the attack type.
 * The detector must infer it from the events.
 */
function generateBruteForceTelemetry(context = {}) {
  const resolved =
    resolveContext(context);

  const sourceIp =
    resolved.sourceIp;

  const targetSystem =
    resolved.targetSystem;

  const events = [];

  for (let i = 0; i < 12; i++) {
    events.push(
      createEvent(
        "AUTHENTICATION_FAILURE",
        {
          sourceIp,
          targetSystem,
          endpointId:
            resolved.endpointId,
          labId:
            resolved.labId,
          collegeId:
            resolved.collegeId,
          instituteId:
            resolved.instituteId,
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
    endpointId:
      resolved.endpointId,
    labId:
      resolved.labId,
    collegeId:
      resolved.collegeId,
    instituteId:
      resolved.instituteId,
    events,
  };
}

/**
 * Network service scanning telemetry.
 *
 * One source attempts connections to many ports.
 */
function generateNetworkScanTelemetry(context = {}) {
  const resolved =
    resolveContext({
      sourceIp:
        context.sourceIp || "192.168.1.60",
      ...context,
    });

  const sourceIp =
    resolved.sourceIp;

  const targetSystem =
    resolved.targetSystem;

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
        endpointId:
          resolved.endpointId,
        labId:
          resolved.labId,
        collegeId:
          resolved.collegeId,
        instituteId:
          resolved.instituteId,
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
    endpointId:
      resolved.endpointId,
    labId:
      resolved.labId,
    collegeId:
      resolved.collegeId,
    instituteId:
      resolved.instituteId,
    events,
  };
}

/**
 * Controlled DoS-like telemetry.
 *
 * This generates telemetry only.
 * It does NOT send traffic to an external/public target.
 */
function generateDosTelemetry(context = {}) {
  const resolved =
    resolveContext({
      sourceIp:
        context.sourceIp || "192.168.1.70",
      ...context,
    });

  const sourceIp =
    resolved.sourceIp;

  const targetSystem =
    resolved.targetSystem;

  const events = [];

  for (let i = 0; i < 100; i++) {
    events.push(
      createEvent(
        "HTTP_REQUEST",
        {
          sourceIp,
          targetSystem,
          endpointId:
            resolved.endpointId,
          labId:
            resolved.labId,
          collegeId:
            resolved.collegeId,
          instituteId:
            resolved.instituteId,
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
    endpointId:
      resolved.endpointId,
    labId:
      resolved.labId,
    collegeId:
      resolved.collegeId,
    instituteId:
      resolved.instituteId,
    events,
  };
}

/**
 * Suspicious process execution telemetry.
 */
function generateSuspiciousProcessTelemetry(context = {}) {
  const resolved =
    resolveContext({
      sourceIp:
        context.sourceIp || "192.168.1.80",
      ...context,
    });

  const sourceIp =
    resolved.sourceIp;

  const targetSystem =
    resolved.targetSystem;

  const events = [
    createEvent("PROCESS_START", {
      sourceIp,
      targetSystem,
      endpointId:
        resolved.endpointId,
      labId:
        resolved.labId,
      collegeId:
        resolved.collegeId,
      instituteId:
        resolved.instituteId,
      processName: "powershell.exe",
      parentProcess: "winword.exe",
      commandLine: "powershell -enc <redacted>",
    }),

    createEvent("PROCESS_START", {
      sourceIp,
      targetSystem,
      endpointId:
        resolved.endpointId,
      labId:
        resolved.labId,
      collegeId:
        resolved.collegeId,
      instituteId:
        resolved.instituteId,
      processName: "cmd.exe",
      parentProcess: "powershell.exe",
      commandLine: "cmd.exe /c whoami",
    }),

    createEvent("PROCESS_START", {
      sourceIp,
      targetSystem,
      endpointId:
        resolved.endpointId,
      labId:
        resolved.labId,
      collegeId:
        resolved.collegeId,
      instituteId:
        resolved.instituteId,
      processName: "net.exe",
      parentProcess: "cmd.exe",
      commandLine: "net user",
    }),
  ];

  return {
    attackId: crypto.randomUUID(),
    sourceIp,
    targetSystem,
    endpointId:
      resolved.endpointId,
    labId:
      resolved.labId,
    collegeId:
      resolved.collegeId,
    instituteId:
      resolved.instituteId,
    events,
  };
}

/**
 * Default scenario.
 */
function generateAttackTelemetry(context = {}) {
  return generateBruteForceTelemetry(
    context
  );
}

module.exports = {
  generateAttackTelemetry,
  generateBruteForceTelemetry,
  generateNetworkScanTelemetry,
  generateDosTelemetry,
  generateSuspiciousProcessTelemetry,
};