const TECHNIQUE_RULES = {
  T1110: {
    attackType: "Brute Force",
    allowedDefenseTypes: [
      "authentication rate limiting",
      "authentication throttling",
      "temporary source blocking",
      "source blocking",
      "rate limiting",
    ],
    requiredConditionHints: [
      "failedAttempts",
      "sourceIP",
      "windowSeconds",
    ],
  },

  T1046: {
    attackType: "Network Service Scanning",
    allowedDefenseTypes: [
      "connection rate limiting",
      "scan rate limiting",
      "network scan rate limit",
      "temporary source blocking",
      "source blocking",
      "connection threshold",
    ],
    requiredConditionHints: [
      "destinationPorts",
      "sourceIP",
      "connectionAttempts",
    ],
  },

  T1498: {
    attackType: "Network Denial of Service",
    allowedDefenseTypes: [
      "request rate limiting",
      "http rate limit",
      "traffic throttling",
      "temporary source blocking",
      "source blocking",
      "request threshold",
    ],
    requiredConditionHints: [
      "requestsPerSecond",
      "requestCount",
      "sourceIP",
      "windowSeconds",
    ],
  },

  "T1059.001": {
    attackType: "Command and Scripting Interpreter",
    allowedDefenseTypes: [
      "suspicious process restriction",
      "process chain restriction",
      "powershell execution restriction",
      "temporary execution restriction",
      "process execution restriction",
    ],
    requiredConditionHints: [
      "processes",
      "processName",
      "parentProcess",
      "commandLine",
    ],
  },
};

function normalize(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ");
}

function validateRequiredFields(rule, errors) {
  if (!rule || typeof rule !== "object") {
    errors.push("Defense rule is missing or is not an object.");
    return;
  }

  if (!rule.type || typeof rule.type !== "string") {
    errors.push("Defense rule type is required.");
  }

  if (!rule.condition || typeof rule.condition !== "object") {
    errors.push("Defense rule condition is required.");
  }

  if (!rule.action || typeof rule.action !== "object") {
    errors.push("Defense rule action is required.");
  }

  if (!rule.explanation || typeof rule.explanation !== "string") {
    errors.push("Defense rule explanation is required.");
  }
}

function validateTechniqueRelevance(rule, techniqueId, attackType, errors) {
  const specification = TECHNIQUE_RULES[techniqueId];

  if (!specification) {
    errors.push(
      `No deterministic defense policy exists for MITRE technique ${techniqueId}.`
    );
    return;
  }

  if (
    specification.attackType &&
    normalize(specification.attackType) !== normalize(attackType)
  ) {
    errors.push(
      `Attack type does not match MITRE technique ${techniqueId}.`
    );
  }

  const defenseType = normalize(rule.type);

  const relevant = specification.allowedDefenseTypes.some(
    (allowed) =>
      defenseType.includes(normalize(allowed)) ||
      normalize(allowed).includes(defenseType)
  );

  if (!relevant) {
    errors.push(
      `Defense type "${rule.type}" is not approved for ${techniqueId}.`
    );
  }
}

function validateCondition(rule, techniqueId, errors) {
  const condition = rule.condition || {};
  const conditionKeys = Object.keys(condition).map(normalize);

  const specification = TECHNIQUE_RULES[techniqueId];

  if (!specification) return;

  const hasRelevantCondition = specification.requiredConditionHints.some(
    (hint) => conditionKeys.includes(normalize(hint))
  );

  if (!hasRelevantCondition) {
    errors.push(
      `Defense condition does not contain telemetry fields relevant to ${techniqueId}.`
    );
  }
}

function validateSafety(rule, errors) {
  const serialized = JSON.stringify(rule).toLowerCase();

  const forbiddenActions = [
    "delete",
    "destroy",
    "format",
    "shutdown",
    "wipe",
    "terminate system",
    "disable security",
  ];

  for (const action of forbiddenActions) {
    if (serialized.includes(action)) {
      errors.push(
        `Unsafe action detected in generated defense rule: "${action}".`
      );
    }
  }
}

function validateConflicts(rule, techniqueId, errors) {
  const type = normalize(rule.type);
  const serialized = JSON.stringify(rule).toLowerCase();

  // T1059.001 must not accidentally produce authentication controls.
  if (
    techniqueId === "T1059.001" &&
    (
      type.includes("authentication") ||
      serialized.includes("authentication rate")
    )
  ) {
    errors.push(
      "PowerShell defense incorrectly contains authentication controls."
    );
  }

  // T1110 should not generate PowerShell/process controls.
  if (
    techniqueId === "T1110" &&
    (
      type.includes("powershell") ||
      type.includes("process execution")
    )
  ) {
    errors.push(
      "Brute-force defense contains unrelated process-execution controls."
    );
  }
}

function validateRule(rule, context = {}) {
  const {
    techniqueId,
    attackType,
  } = context;

  const errors = [];

  validateRequiredFields(rule, errors);

  if (rule && typeof rule === "object") {
    validateTechniqueRelevance(
      rule,
      techniqueId,
      attackType,
      errors
    );

    validateCondition(
      rule,
      techniqueId,
      errors
    );

    validateSafety(
      rule,
      errors
    );

    validateConflicts(
      rule,
      techniqueId,
      errors
    );
  }

  return {
    passed: errors.length === 0,

    status:
      errors.length === 0
        ? "VALIDATED"
        : "REJECTED",

    checks: {
      syntax:
        errors.length === 0 ||
        !errors.some((error) =>
          error.toLowerCase().includes("required")
        ),

      relevance:
        errors.length === 0 ||
        !errors.some((error) =>
          error.toLowerCase().includes("not approved") ||
          error.toLowerCase().includes("does not match")
        ),

      safety:
        errors.length === 0 ||
        !errors.some((error) =>
          error.toLowerCase().includes("unsafe")
        ),

      conflict:
        errors.length === 0 ||
        !errors.some((error) =>
          error.toLowerCase().includes("unrelated") ||
          error.toLowerCase().includes("incorrectly")
        ),
    },

    errors,
  };
}

module.exports = {
  validateRule,
};
