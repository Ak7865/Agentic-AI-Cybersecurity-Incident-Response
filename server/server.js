const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const {
  generateAttackTelemetry,
  generateBruteForceTelemetry,
  generateNetworkScanTelemetry,
  generateDosTelemetry,
  generateSuspiciousProcessTelemetry,
} = require("../Cyber Security/attackSimulator");

const {
  detectAttack,
} = require("../Cyber Security/detector");

const {
  validateRule,
} = require("../Cyber Security/ruleValidator");

const {
  analyzeThreat,
} = require("../Agentic AI/agent");

const {
  connectToFabric,
  registerDefense,
  updateDefenseStatus,
  getDefense,
  getAllDefenses,
  hashEvidence,
  closeFabricConnection,
  CHANNEL_NAME,
  CHAINCODE_NAME,
  OWNER_ORG_MSP,
  PRIVATE_EVIDENCE_COLLECTION,
} = require("./fabricClient");

const app = express();

const PORT = 5000;

const DEFAULT_ACCESS_POLICY = {
  ownerOrgMSP:
    OWNER_ORG_MSP,

  allowedOrgs:
    (process.env.FABRIC_ALLOWED_ORGS || "Org1MSP,Org2MSP,Org3MSP,Org4MSP")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),

  allowedRoles:
    (process.env.FABRIC_ALLOWED_ROLES || "analyst,responder,auditor,admin")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),

  requiredApprovals:
    (process.env.FABRIC_REQUIRED_APPROVAL_ORGS || "Org1MSP,Org3MSP")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
};

const PROPAGATION_SCOPES = {
  LAB_ONLY:
    "LAB_ONLY",
  COLLEGE_WIDE:
    "COLLEGE_WIDE",
  ASTU_WIDE:
    "ASTU_WIDE",
};

const PROPAGATION_SCOPE_ORDER = [
  PROPAGATION_SCOPES.LAB_ONLY,
  PROPAGATION_SCOPES.COLLEGE_WIDE,
  PROPAGATION_SCOPES.ASTU_WIDE,
];

const PROPAGATION_APPROVALS = {
  SOC_COMPLIANCE:
    "SOC_COMPLIANCE",
  ASTU_GOVERNANCE:
    "ASTU_GOVERNANCE",
};

const PROPAGATION_ROLLOUT_POLICY = {
  canarySampleSize:
    Number(
      process.env.PROPAGATION_CANARY_SAMPLE_SIZE ||
        3
    ),
  falsePositiveRollbackThreshold:
    Number(
      process.env.PROPAGATION_FALSE_POSITIVE_ROLLBACK_THRESHOLD ||
        0.12
    ),
  defaultTtlSeconds:
    Number(
      process.env.PROPAGATION_DEFAULT_TTL_SECONDS ||
        86400
    ),
};

function createAstuHierarchy() {
  const hierarchy = {
    instituteId:
      "ASTU-NETWORK",
    instituteName:
      "ASTU",
    colleges: [],
  };

  for (let collegeIndex = 1; collegeIndex <= 8; collegeIndex++) {
    const collegeId = `COLLEGE-${String(collegeIndex).padStart(2, "0")}`;
    const college = {
      collegeId,
      collegeName:
        collegeIndex === 1
          ? "Home College"
          : `ASTU Affiliated College ${collegeIndex}`,
      labs: [],
    };

    for (let labIndex = 1; labIndex <= 5; labIndex++) {
      const labId = `${collegeId}-LAB-${String(labIndex).padStart(2, "0")}`;
      const lab = {
        labId,
        labName: `Lab ${labIndex}`,
        endpoints: [],
      };

      for (let endpointIndex = 1; endpointIndex <= 20; endpointIndex++) {
        lab.endpoints.push({
          endpointId: `${labId}-PC-${String(endpointIndex).padStart(2, "0")}`,
          hostname: `pc-${collegeIndex}-${labIndex}-${endpointIndex}`,
          os: "Windows",
        });
      }

      college.labs.push(lab);
    }

    hierarchy.colleges.push(college);
  }

  return hierarchy;
}

const ASSET_HIERARCHY =
  createAstuHierarchy();

function buildEndpointLookup(hierarchy) {
  const lookup = {};

  for (const college of hierarchy.colleges) {
    for (const lab of college.labs) {
      for (const endpoint of lab.endpoints) {
        lookup[endpoint.endpointId] = {
          instituteId:
            hierarchy.instituteId,
          collegeId:
            college.collegeId,
          labId:
            lab.labId,
          endpointId:
            endpoint.endpointId,
          endpointName:
            endpoint.hostname,
        };
      }
    }
  }

  return lookup;
}

const ENDPOINT_LOOKUP =
  buildEndpointLookup(ASSET_HIERARCHY);

function getDefaultEndpointContext() {
  const firstCollege =
    ASSET_HIERARCHY.colleges[0];
  const firstLab =
    firstCollege.labs[0];
  const firstEndpoint =
    firstLab.endpoints[0];

  return {
    instituteId:
      ASSET_HIERARCHY.instituteId,
    collegeId:
      firstCollege.collegeId,
    labId:
      firstLab.labId,
    endpointId:
      firstEndpoint.endpointId,
    endpointName:
      firstEndpoint.hostname,
  };
}

function resolveEndpointContext(requestBody = {}) {
  const requestedEndpointId =
    requestBody.endpointId;

  if (
    requestedEndpointId &&
    ENDPOINT_LOOKUP[requestedEndpointId]
  ) {
    return ENDPOINT_LOOKUP[requestedEndpointId];
  }

  const defaultContext =
    getDefaultEndpointContext();

  const scopedCollegeId =
    requestBody.collegeId ||
    defaultContext.collegeId;

  const scopedLabId =
    requestBody.labId ||
    defaultContext.labId;

  const scopedCollege =
    ASSET_HIERARCHY.colleges.find(
      (college) =>
        college.collegeId ===
        scopedCollegeId
    );

  if (scopedCollege) {
    const scopedLab =
      scopedCollege.labs.find(
        (lab) => lab.labId === scopedLabId
      );
    if (
      scopedLab &&
      Array.isArray(scopedLab.endpoints) &&
      scopedLab.endpoints.length > 0
    ) {
      const endpoint =
        scopedLab.endpoints[0];
      return {
        instituteId:
          ASSET_HIERARCHY.instituteId,
        collegeId:
          scopedCollege.collegeId,
        labId:
          scopedLab.labId,
        endpointId:
          endpoint.endpointId,
        endpointName:
          endpoint.hostname,
      };
    }
  }

  return defaultContext;
}

function getTargetsForScope(scope, hierarchyContext) {
  const targets = [];

  if (!hierarchyContext) {
    return targets;
  }

  for (const college of ASSET_HIERARCHY.colleges) {
    for (const lab of college.labs) {
      for (const endpoint of lab.endpoints) {
        const target = {
          endpointId:
            endpoint.endpointId,
          hostname:
            endpoint.hostname,
          collegeId:
            college.collegeId,
          labId:
            lab.labId,
        };

        if (
          scope ===
            PROPAGATION_SCOPES.LAB_ONLY &&
          target.labId === hierarchyContext.labId
        ) {
          targets.push(target);
        } else if (
          scope ===
            PROPAGATION_SCOPES.COLLEGE_WIDE &&
          target.collegeId ===
            hierarchyContext.collegeId
        ) {
          targets.push(target);
        } else if (
          scope ===
          PROPAGATION_SCOPES.ASTU_WIDE
        ) {
          targets.push(target);
        }
      }
    }
  }

  return targets;
}

function getRuleVersion(incident) {
  return (
    incident?.propagationPolicy?.ruleVersion ||
    1
  );
}

function createPropagationPolicy(incident) {
  return {
    ruleVersion:
      getRuleVersion(incident),
    ruleTtlSeconds:
      PROPAGATION_ROLLOUT_POLICY.defaultTtlSeconds,
    canarySampleSize:
      PROPAGATION_ROLLOUT_POLICY.canarySampleSize,
    rollbackThreshold:
      PROPAGATION_ROLLOUT_POLICY.falsePositiveRollbackThreshold,
    currentScope:
      "NONE",
    deployedScopes:
      [],
    approvals: {
      [PROPAGATION_APPROVALS.SOC_COMPLIANCE]: {
        requiredOrgs: [
          "Org1MSP",
          "Org3MSP",
        ],
        approvals:
          [],
      },
      [PROPAGATION_APPROVALS.ASTU_GOVERNANCE]: {
        requiredOrgs: [
          "Org4MSP",
        ],
        approvals:
          [],
      },
    },
    auditTrail:
      [],
    endpointRolloutResults:
      [],
  };
}

function getNextScope(currentScope) {
  const currentIndex =
    PROPAGATION_SCOPE_ORDER.indexOf(
      currentScope
    );
  if (currentIndex < 0) {
    return PROPAGATION_SCOPE_ORDER[0];
  }
  if (
    currentIndex + 1 >=
    PROPAGATION_SCOPE_ORDER.length
  ) {
    return null;
  }
  return PROPAGATION_SCOPE_ORDER[currentIndex + 1];
}

function isApprovalSatisfied(approvalGate) {
  const approvedOrgs = new Set(
    approvalGate.approvals.map(
      (entry) => entry.orgMSP
    )
  );
  return approvalGate.requiredOrgs.every(
    (org) => approvedOrgs.has(org)
  );
}

function getRequiredApproval(scope) {
  if (
    scope ===
    PROPAGATION_SCOPES.COLLEGE_WIDE
  ) {
    return PROPAGATION_APPROVALS.SOC_COMPLIANCE;
  }
  if (
    scope ===
    PROPAGATION_SCOPES.ASTU_WIDE
  ) {
    return PROPAGATION_APPROVALS.ASTU_GOVERNANCE;
  }
  return null;
}

function normalizeScope(scopeInput, incident) {
  const input = String(scopeInput || "")
    .trim()
    .toUpperCase();
  if (
    input &&
    PROPAGATION_SCOPE_ORDER.includes(input)
  ) {
    return input;
  }

  if (!incident?.propagationPolicy) {
    return PROPAGATION_SCOPES.LAB_ONLY;
  }

  return (
    getNextScope(
      incident.propagationPolicy.currentScope
    ) ||
    PROPAGATION_SCOPES.ASTU_WIDE
  );
}

app.use(cors());
app.use(express.json());

/*
|--------------------------------------------------------------------------
| In-memory incident storage
|--------------------------------------------------------------------------
|
| Incident lifecycle remains in memory for the MVP.
|
| Defense validation and audit provenance are recorded
| on Hyperledger Fabric.
|
|--------------------------------------------------------------------------
*/

const DATA_DIR = path.join(__dirname, "../data");
const INCIDENTS_FILE = path.join(DATA_DIR, "incidents.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

let incidents = [];
try {
  if (fs.existsSync(INCIDENTS_FILE)) {
    const data = fs.readFileSync(INCIDENTS_FILE, "utf-8");
    incidents = JSON.parse(data);
    console.log(`[Persistence] Loaded ${incidents.length} incidents from disk`);
  }
} catch (error) {
  console.error("[Persistence] Error loading incidents:", error.message);
}

function saveIncidents() {
  try {
    fs.writeFileSync(INCIDENTS_FILE, JSON.stringify(incidents, null, 2), "utf-8");
  } catch (error) {
    console.error("[Persistence] Error saving incidents:", error.message);
  }
}

/*
|--------------------------------------------------------------------------
| Health
|--------------------------------------------------------------------------
|
| GET /api/health
|--------------------------------------------------------------------------
*/

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "Agentic Cyber Defense Backend",
  });
});

app.get("/api/assets/hierarchy", (req, res) => {
  res.json({
    success: true,
    hierarchy:
      ASSET_HIERARCHY,
    scopes:
      PROPAGATION_SCOPE_ORDER,
    approvalGates:
      PROPAGATION_APPROVALS,
  });
});

/*
|--------------------------------------------------------------------------
| Simulate Attack
|--------------------------------------------------------------------------
|
| POST /api/attack/simulate
|
| Pipeline:
|
| Synthetic Attack
|       ↓
| Detection
|       ↓
| Real Agentic AI / Ollama
|       ↓
| Threat Investigation
|       ↓
| Defense Generation
|       ↓
| Defense Critique
|       ↓
| Deterministic Rule Validation
|       ↓
| Incident
|       ↓
| Evidence Hash
|       ↓
| Hyperledger Fabric
|       ↓
| READY_FOR_PROPAGATION
|
|--------------------------------------------------------------------------
*/

app.post("/api/attack/simulate", async (req, res) => {
  function generateSelectedTelemetry(scenario, context) {
  switch (scenario) {
    case "bruteforce":
      return generateBruteForceTelemetry(
        context
      );

    case "scan":
      return generateNetworkScanTelemetry(
        context
      );

    case "dos":
      return generateDosTelemetry(
        context
      );

    case "process":
      return generateSuspiciousProcessTelemetry(
        context
      );

    default:
      return generateAttackTelemetry(
        context
      );
  }
}
  try {
    /*
    |--------------------------------------------------------------------------
    | 1. Generate controlled synthetic attack
    |--------------------------------------------------------------------------
    */

    const scenario = req.body.scenario || "bruteforce";
    const endpointContext =
      resolveEndpointContext(
        req.body || {}
      );
    const attack = generateSelectedTelemetry(
      scenario,
      endpointContext
    );

    /*
    |--------------------------------------------------------------------------
    | 2. Detect attack
    |--------------------------------------------------------------------------
    */

    const detection = detectAttack(attack);

    if (!detection.detected) {
      return res.json({
        success: true,
        detected: false,
        message: "No attack detected.",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | 3. Real Agentic AI analysis
    |--------------------------------------------------------------------------
    |
    | IMPORTANT:
    | analyzeThreat() now communicates with Ollama and is asynchronous.
    |
    */

    console.log(
      `[Agent] Starting AI investigation for ${attack.attackId}...`
    );

    const agentResult = await analyzeThreat(
      attack,
      detection
    );

    console.log(
      `[Agent] Investigation completed using ${
        agentResult.agent?.model || "unknown model"
      }`
    );

    /*
    |--------------------------------------------------------------------------
    | 4. Validate agent-generated defense rule
    |--------------------------------------------------------------------------
    |
    | The LLM does NOT directly authorize the defense.
    |
    | Deterministic validation remains the security gate.
    |
    */

    const validation = validateRule(
      agentResult.defenseRule,
      {
        techniqueId:
          detection.technique?.id,

        attackType:
          detection.attackType,
      }
    
      
    );
    agentResult.validation=validation;

    /*
    |--------------------------------------------------------------------------
    | 5. Determine incident severity
    |--------------------------------------------------------------------------
    */

    let severity = "Low";

    if (agentResult.riskScore >= 80) {
      severity = "Critical";
    } else if (agentResult.riskScore >= 60) {
      severity = "High";
    } else if (agentResult.riskScore >= 40) {
      severity = "Medium";
    }

    /*
    |--------------------------------------------------------------------------
    | 6. Create incident
    |--------------------------------------------------------------------------
    */

    const incidentTimestamp =
      new Date().toISOString();

    const fabricIncidentId = `INC-${Date.now()}`;

    const incident = {
      /*
      |--------------------------------------------------------------------------
      | Dashboard fields
      |--------------------------------------------------------------------------
      */

      id: fabricIncidentId,

      title:
        agentResult.classification,

      source:
        attack.sourceIp,

      severity,

      tactic:
        agentResult.technique.name,

      asset:
        endpointContext.endpointId,

      hierarchy: {
        endpointId:
          endpointContext.endpointId,
        endpointName:
          endpointContext.endpointName,
        labId:
          endpointContext.labId,
        collegeId:
          endpointContext.collegeId,
        instituteId:
          endpointContext.instituteId,
      },

      observedAt:
        incidentTimestamp,

      status: "Open",

      /*
      |--------------------------------------------------------------------------
      | Detailed attack information
      |--------------------------------------------------------------------------
      */

      attack: {
        id:
          attack.attackId,

        type:
          agentResult.classification,

        technique:
          agentResult.technique,

        sourceIp:
          attack.sourceIp,

        targetSystem:
          endpointContext.endpointId,

        hierarchy:
          {
            endpointId:
              endpointContext.endpointId,
            endpointName:
              endpointContext.endpointName,
            labId:
              endpointContext.labId,
            collegeId:
              endpointContext.collegeId,
            instituteId:
              endpointContext.instituteId,
          },

        failedAttempts:
          attack.events.filter(
            (event) =>
              event.type ===
              "AUTHENTICATION_FAILURE"
          ).length || undefined,
        

        events:
          attack.events,
      },

      /*
      |--------------------------------------------------------------------------
      | Agent analysis
      |--------------------------------------------------------------------------
      */

      analysis: {
        confidence:
          agentResult.confidence,

        riskScore:
          agentResult.riskScore,

        reason:
          agentResult.reason,

        evidence:
          agentResult.evidence,

        reasoning:
          agentResult.reasoning,

        /*
        | Real AI agent metadata
        */

        agent:
          agentResult.agent,

        /*
        | Defense critique produced by the
        | second-stage review agent
        */

        agentReview:
          agentResult.agentReview,
      },

      /*
      |--------------------------------------------------------------------------
      | Agent-generated defense rule
      |--------------------------------------------------------------------------
      */

      defenseRule:
        agentResult.defenseRule,

      /*
      |--------------------------------------------------------------------------
      | Validation result
      |--------------------------------------------------------------------------
      */

      validation,

      /*
      |--------------------------------------------------------------------------
      | Fabric audit information
      |--------------------------------------------------------------------------
      */

      fabric: {
        incidentId: fabricIncidentId,

        recorded: false,

        network:
          CHANNEL_NAME,

        chaincode:
          CHAINCODE_NAME,

        ownerOrgMSP:
          DEFAULT_ACCESS_POLICY.ownerOrgMSP,

        accessPolicy:
          {
            allowedOrgs: [
              ...DEFAULT_ACCESS_POLICY.allowedOrgs,
            ],
            allowedRoles: [
              ...DEFAULT_ACCESS_POLICY.allowedRoles,
            ],
            requiredApprovals: [
              ...DEFAULT_ACCESS_POLICY.requiredApprovals,
            ],
          },

        evidenceHash:
          null,

        validationStatus:
          validation.status,

        lifecycleStatus:
          null,

        error:
          null,
      },

      /*
      |--------------------------------------------------------------------------
      | Incident lifecycle
      |--------------------------------------------------------------------------
      */

      state:
        "OPEN",

      acknowledged:
        false,

      triaged:
        false,

      propagationPolicy:
        createPropagationPolicy(),

      /*
      |--------------------------------------------------------------------------
      | Internal timestamp
      |--------------------------------------------------------------------------
      */

      timestamp:
        incidentTimestamp,
    };

    /*
    |--------------------------------------------------------------------------
    | 7. Record validated defense on Hyperledger Fabric
    |--------------------------------------------------------------------------
    */

    if (
      validation.passed &&
      agentResult.defenseRule
    ) {
      try {
        console.log(
          `[Fabric] Registering defense for ${fabricIncidentId}...`
        );

        const fabricResult =
          await registerDefense({
            incidentId:
              fabricIncidentId,

            attackType:
              agentResult.classification,

            mitreTechnique:
              agentResult.technique.id,

            sourceIP:
              attack.sourceIp,

            targetSystem:
              endpointContext.endpointId,

            riskScore:
              agentResult.riskScore,

            agentConfidence:
              agentResult.confidence,

            evidence:
              agentResult.evidence,

            defenseRule:
              agentResult.defenseRule,

            validationStatus:
              validation.status,

            timestamp:
              incident.timestamp,

            ownerOrgMSP:
              DEFAULT_ACCESS_POLICY.ownerOrgMSP,

            accessPolicy:
              {
                allowedOrgs: [
                  ...DEFAULT_ACCESS_POLICY.allowedOrgs,
                ],
                allowedRoles: [
                  ...DEFAULT_ACCESS_POLICY.allowedRoles,
                ],
                requiredApprovals: [
                  ...DEFAULT_ACCESS_POLICY.requiredApprovals,
                ],
              },

            evidencePrivateMetadata:
              {
                collection:
                  PRIVATE_EVIDENCE_COLLECTION,
                storageType:
                  "off-chain-secure-storage",
                storageReference:
                  `evidence://${fabricIncidentId}`,
                evidenceItemCount:
                  Array.isArray(agentResult.evidence)
                    ? agentResult.evidence.length
                    : 0,
              },
          });

        /*
        |--------------------------------------------------------------------------
        | Store Fabric audit information
        |--------------------------------------------------------------------------
        */

        incident.fabric = {
          incidentId: fabricIncidentId,

          recorded:
            true,

          network:
            CHANNEL_NAME,

          chaincode:
            CHAINCODE_NAME,

          ownerOrgMSP:
            DEFAULT_ACCESS_POLICY.ownerOrgMSP,

          accessPolicy:
            {
              allowedOrgs: [
                ...DEFAULT_ACCESS_POLICY.allowedOrgs,
              ],
              allowedRoles: [
                ...DEFAULT_ACCESS_POLICY.allowedRoles,
              ],
              requiredApprovals: [
                ...DEFAULT_ACCESS_POLICY.requiredApprovals,
              ],
            },

          evidenceHash:
            fabricResult.evidenceHash,

          transactionIds:
            {
              registerDefense:
                fabricResult.transactionId,
              privateEvidenceAnchor:
                fabricResult.privateEvidenceTransactionId,
            },

          validationStatus:
            validation.status,

          lifecycleStatus:
            "VALIDATED",

          error:
            null,
        };

        /*
        |--------------------------------------------------------------------------
        | Mark validated defense as ready for propagation
        |--------------------------------------------------------------------------
        |
        | This does NOT mean the rule has actually been deployed
        | to a firewall, endpoint, IDS, or other enforcement system.
        |
        |--------------------------------------------------------------------------
        */

        const statusResult =
          await updateDefenseStatus(
            fabricIncidentId,
            "READY_FOR_PROPAGATION"
          );

        incident.fabric.lifecycleStatus =
          statusResult.status;

        incident.fabric.transactionIds =
          incident.fabric.transactionIds || {};

        incident.fabric.transactionIds.setReadyForPropagation =
          statusResult.transactionId;

        console.log(
          `[Fabric] ${fabricIncidentId} is READY_FOR_PROPAGATION`
        );
      } catch (fabricError) {
        /*
        |--------------------------------------------------------------------------
        | Fabric failure handling
        |--------------------------------------------------------------------------
        |
        | The security incident is retained even if the audit
        | layer is temporarily unavailable.
        |
        |--------------------------------------------------------------------------
        */

        console.error(
          `[Fabric] Failed to record ${incident.id}:`,
          fabricError
        );

        incident.fabric = {
          incidentId: fabricIncidentId,

          recorded:
            false,

          network:
            CHANNEL_NAME,

          chaincode:
            CHAINCODE_NAME,

          ownerOrgMSP:
            DEFAULT_ACCESS_POLICY.ownerOrgMSP,

          accessPolicy:
            {
              allowedOrgs: [
                ...DEFAULT_ACCESS_POLICY.allowedOrgs,
              ],
              allowedRoles: [
                ...DEFAULT_ACCESS_POLICY.allowedRoles,
              ],
              requiredApprovals: [
                ...DEFAULT_ACCESS_POLICY.requiredApprovals,
              ],
            },

          evidenceHash:
            null,

          validationStatus:
            validation.status,

          lifecycleStatus:
            null,

          error:
            fabricError.message,
        };
      }
    }

    /*
    |--------------------------------------------------------------------------
    | 8. Store incident
    |--------------------------------------------------------------------------
    */

    incidents.unshift(incident);
    saveIncidents();

    /*
    |--------------------------------------------------------------------------
    | 9. Return result
    |--------------------------------------------------------------------------
    */

    res.status(201).json({
      success: true,
      incident,
    });
  } catch (error) {
    console.error(
      "Attack simulation error:",
      error
    );

    res.status(500).json({
      success: false,
      error:
        "Attack simulation failed",

      details:
        error.message,
    });
  }
});

/*
|--------------------------------------------------------------------------
| Get all incidents
|--------------------------------------------------------------------------
|
| GET /api/incidents
|
|--------------------------------------------------------------------------
*/

app.get("/api/incidents", (req, res) => {
  /*
  |--------------------------------------------------------------------------
  | Calculate summary
  |--------------------------------------------------------------------------
  */

  const openIncidents =
    incidents.filter(
      (incident) =>
        incident.state === "OPEN"
    );

  const criticalIncidents =
    incidents.filter(
      (incident) =>
        incident.severity === "Critical"
    );

  /*
  |--------------------------------------------------------------------------
  | Response
  |--------------------------------------------------------------------------
  */

  const response = {
    generatedAt:
      new Date().toISOString(),

    summary: {
      openIncidents:
        openIncidents.length,

      criticalIncidents:
        criticalIncidents.length,

      eventsPerMinute:
        incidents.length,

      monitoredAssets:
        4,
    },

    incidents,
  };

  res.json(response);
});

/*
|--------------------------------------------------------------------------
| Get latest incident
|--------------------------------------------------------------------------
|
| GET /api/incident/latest
|
|--------------------------------------------------------------------------
*/

app.get(
  "/api/incident/latest",
  (req, res) => {
    res.json({
      success: true,

      incident:
        incidents.length > 0
          ? incidents[0]
          : null,
    });
  }
);

/*
|--------------------------------------------------------------------------
| Acknowledge incident
|--------------------------------------------------------------------------
|
| POST /api/incidents/:incidentId/acknowledge
|
|--------------------------------------------------------------------------
*/

app.post(
  "/api/incidents/:incidentId/acknowledge",
  (req, res) => {
    const {
      incidentId,
    } = req.params;

    /*
    |--------------------------------------------------------------------------
    | Find incident
    |--------------------------------------------------------------------------
    */

    const incident =
      incidents.find(
        (item) =>
          item.id === incidentId
      );

    if (!incident) {
      return res.status(404).json({
        success: false,
        error:
          "Incident not found",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Update lifecycle
    |--------------------------------------------------------------------------
    */

    incident.acknowledged =
      true;

    incident.status =
      "Acknowledged";

    incident.state =
      "ACKNOWLEDGED";

    saveIncidents();

    /*
    |--------------------------------------------------------------------------
    | Response
    |--------------------------------------------------------------------------
    */

    res.json({
      success: true,
      incident,
    });
  }
);

/*
|--------------------------------------------------------------------------
| Agent Triage
|--------------------------------------------------------------------------
|
| GET /api/incidents/:incidentId/triage
|
|--------------------------------------------------------------------------
*/

app.get(
  "/api/incidents/:incidentId/triage",
  (req, res) => {
    const {
      incidentId,
    } = req.params;

    /*
    |--------------------------------------------------------------------------
    | Find incident
    |--------------------------------------------------------------------------
    */

    const incident =
      incidents.find(
        (item) =>
          item.id === incidentId
      );

    if (!incident) {
      return res.status(404).json({
        success: false,
        error:
          "Incident not found",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Mark as triaged
    |--------------------------------------------------------------------------
    */

    incident.triaged =
      true;
    saveIncidents();

    /*
    |--------------------------------------------------------------------------
    | Agent recommendation
    |--------------------------------------------------------------------------
    */

    const triage = {
      agent:
        "Cyber Defense Agent",

      mode:
        "Recommendation",

      riskScore:
        incident.analysis.riskScore,

      confidence:
        Math.round(
          incident.analysis.confidence *
            100
        ),

      disposition:
        "Investigate",

      /*
      |--------------------------------------------------------------------------
      | Why the agent reached this conclusion
      |--------------------------------------------------------------------------
      */

      rationale: [
        ...incident.analysis.reasoning,

        `MITRE ATT&CK technique identified: ${incident.attack.technique.id} - ${incident.attack.technique.name}`,

        `Risk score calculated as ${incident.analysis.riskScore}/100.`,

        "The proposed defense rule passed syntax, conflict, and safety validation.",

        incident.fabric.recorded
          ? "The validated defense was recorded on Hyperledger Fabric."
          : "The defense could not currently be recorded on the audit layer.",
      ],

      /*
      |--------------------------------------------------------------------------
      | Recommended analyst actions
      |--------------------------------------------------------------------------
      */

      recommendedActions: [
        "Review the source IP and authentication activity.",

        "Apply the validated authentication rate-limit rule.",

        "Monitor the affected system for repeated authentication failures.",

        "Record the validated defense decision in the audit layer.",
      ],

      /*
      |--------------------------------------------------------------------------
      | Detailed information
      |--------------------------------------------------------------------------
      */

      attackType:
        incident.attack.type,

      technique:
        incident.attack.technique,

      reason:
        incident.analysis.reason,

      evidence:
        incident.analysis.evidence,

      defenseRule:
        incident.defenseRule,

      validation:
        incident.validation,

      fabric:
        incident.fabric,

      /*
      |--------------------------------------------------------------------------
      | Real agent information
      |--------------------------------------------------------------------------
      */

      agent:
        incident.analysis.agent,

      agentReview:
        incident.analysis.agentReview,
    };

    /*
    |--------------------------------------------------------------------------
    | Return triage
    |--------------------------------------------------------------------------
    */

    res.json({
      success: true,
      triage,
    });
  }
);

/*
|--------------------------------------------------------------------------
| Get Fabric defense record
|--------------------------------------------------------------------------
|
| GET /api/fabric/defenses/:incidentId
|
|--------------------------------------------------------------------------
*/

app.get(
  "/api/fabric/defenses/:incidentId",
  async (req, res) => {
    try {
      const defense =
        await getDefense(
          req.params.incidentId
        );

      res.json({
        success: true,
        defense,
      });
    } catch (error) {
      console.error(
        "Fabric query error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          "Failed to query Fabric",
        details:
          error.message,
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Get all Fabric defense records
|--------------------------------------------------------------------------
|
| GET /api/fabric/defenses
|
|--------------------------------------------------------------------------
*/

app.get(
  "/api/fabric/defenses",
  async (req, res) => {
    try {
      const defenses =
        await getAllDefenses();

      res.json({
        success: true,
        count:
          defenses.length,
        defenses,
      });
    } catch (error) {
      console.error(
        "Fabric registry query error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          "Failed to query Fabric registry",
        details:
          error.message,
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Verify Evidence Integrity
|--------------------------------------------------------------------------
|
| POST /api/incidents/:incidentId/verify-integrity
|
|--------------------------------------------------------------------------
*/

app.post(
  "/api/incidents/:incidentId/verify-integrity",
  async (req, res) => {
    try {
      const {
        incidentId,
      } = req.params;

      const {
        tamper = false,
      } = req.body || {};

      const incident =
        incidents.find(
          (item) =>
            item.id === incidentId
        );

      if (!incident) {
        return res.status(404).json({
          success: false,
          error:
            "Incident not found",
        });
      }

      if (
        !incident.analysis?.evidence
      ) {
        return res.status(400).json({
          success: false,
          error:
            "No evidence available for this incident",
        });
      }

      const fabricIncidentId =
        incident.fabric?.incidentId || incident.id;

      if (!incident.fabric?.recorded) {
        return res.status(409).json({
          success: false,
          incidentId: fabricIncidentId,
          error:
            "Evidence integrity cannot be verified because the defense was not registered on Hyperledger Fabric.",
          details:
            incident.fabric?.error ||
            "The defense must be registered before its evidence can be verified.",
        });
      }

      /*
      |--------------------------------------------------------------------------
      | Original evidence
      |--------------------------------------------------------------------------
      */

      const originalEvidence =
        [
          ...incident.analysis.evidence,
        ];

      /*
      |--------------------------------------------------------------------------
      | Current evidence
      |--------------------------------------------------------------------------
      */

      const currentEvidence =
        [
          ...originalEvidence,
        ];

      /*
      |--------------------------------------------------------------------------
      | Controlled tampering simulation
      |--------------------------------------------------------------------------
      |
      | This does NOT modify the incident or Fabric record.
      |
      |--------------------------------------------------------------------------
      */

      if (tamper) {
        currentEvidence[0] =
          `${currentEvidence[0]} [MODIFIED]`;
      }

      /*
      |--------------------------------------------------------------------------
      | Compute current evidence hash
      |--------------------------------------------------------------------------
      */

      const computedHash =
        hashEvidence(
          currentEvidence
        );

      /*
      |--------------------------------------------------------------------------
      | Read authoritative hash from Fabric
      |--------------------------------------------------------------------------
      */

      const fabricRecord =
        await getDefense(
          fabricIncidentId
        );

      const expectedHash =
        fabricRecord.evidenceHash;

      /*
      |--------------------------------------------------------------------------
      | Compare hashes
      |--------------------------------------------------------------------------
      */

      const verified =
        computedHash ===
        expectedHash;

      res.json({
        success: true,

        incidentId,

        status:
          verified
            ? "VERIFIED"
            : "TAMPER_DETECTED",

        verification: {
          verified,

          tampered:
            !verified,

          expectedHash,

          computedHash,
        },

        evidence: {
          original:
            originalEvidence,

          current:
            currentEvidence,
        },

        reason:
          verified
            ? "The current evidence produces the same SHA-256 hash recorded on Hyperledger Fabric."
            : "The current evidence produces a different SHA-256 hash from the value recorded on Hyperledger Fabric. The evidence has been modified or corrupted.",
      });
    } catch (error) {
      console.error(
        "Integrity verification error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message,
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Propagation Approvals
|--------------------------------------------------------------------------
|
| POST /api/incidents/:incidentId/propagation/approve
|
|--------------------------------------------------------------------------
*/

app.post(
  "/api/incidents/:incidentId/propagation/approve",
  async (req, res) => {
    try {
      const { incidentId } =
        req.params;

      const {
        approvalGate,
        orgMSP = "Org1MSP",
        role = "admin",
        approver = "automated-workflow",
      } = req.body || {};

      if (
        !Object.values(PROPAGATION_APPROVALS).includes(
          approvalGate
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid approval gate. Use SOC_COMPLIANCE or ASTU_GOVERNANCE.",
        });
      }

      const incident =
        incidents.find(
          (item) =>
            item.id === incidentId
        );

      if (!incident) {
        return res.status(404).json({
          success: false,
          error:
            "Incident not found",
        });
      }

      incident.propagationPolicy =
        incident.propagationPolicy ||
        createPropagationPolicy(incident);

      const gateState =
        incident.propagationPolicy
          .approvals[approvalGate];

      const alreadyApproved =
        gateState.approvals.some(
          (entry) =>
            entry.orgMSP === orgMSP
        );

      if (alreadyApproved) {
        return res.status(409).json({
          success: false,
          error: `${orgMSP} has already approved ${approvalGate}.`,
        });
      }

      const approvedAt =
        new Date().toISOString();

      gateState.approvals.push({
        orgMSP,
        role,
        approver,
        approvedAt,
      });

      let auditTxId = null;

      if (incident.fabric?.recorded) {
        const statusAudit =
          await updateDefenseStatus(
            incident.fabric.incidentId,
            `APPROVED_${approvalGate}_${orgMSP}`
          );
        auditTxId =
          statusAudit.transactionId;

        await updateDefenseStatus(
          incident.fabric.incidentId,
          "READY_FOR_PROPAGATION"
        );
      }

      const gateApproved =
        isApprovalSatisfied(gateState);

      incident.propagationPolicy.auditTrail.push(
        {
          type:
            "APPROVAL_RECORDED",
          approvalGate,
          orgMSP,
          role,
          approver,
          approvedAt,
          gateApproved,
          fabricTransactionId:
            auditTxId,
        }
      );

      saveIncidents();

      return res.json({
        success: true,
        incidentId,
        approvalGate,
        gateApproved,
        gateState,
      });
    } catch (error) {
      console.error(
        "Propagation approval error:",
        error
      );
      return res.status(500).json({
        success: false,
        error:
          error.message,
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Defense Propagation
|--------------------------------------------------------------------------
|
| POST /api/incidents/:incidentId/propagate
|
|--------------------------------------------------------------------------
*/

app.post(
  "/api/incidents/:incidentId/propagate",
  async (req, res) => {
    try {
      const { incidentId } =
        req.params;
      const incident =
        incidents.find(
          (item) =>
            item.id === incidentId
        );

      if (!incident) {
        return res.status(404).json({
          success: false,
          error:
            "Incident not found",
        });
      }

      const fabricIncidentId =
        incident.fabric?.incidentId || incident.id;

      if (!incident.fabric?.recorded) {
        return res.status(409).json({
          success: false,
          incidentId: fabricIncidentId,
          error:
            "Defense propagation is unavailable because the defense was not registered on Hyperledger Fabric.",
          details:
            incident.fabric?.error ||
            "The defense must be registered before it can be propagated.",
        });
      }

      const fabricRecord =
        await getDefense(
          fabricIncidentId
        );

      if (!fabricRecord) {
        return res.status(404).json({
          success: false,
          error:
            "Defense record not found on Hyperledger Fabric",
        });
      }

      if (
        fabricRecord.validationStatus !==
        "VALIDATED"
      ) {
        return res.status(409).json({
          success: false,

          error:
            "Defense rule cannot be propagated because it has not been validated.",

          validationStatus:
            fabricRecord.validationStatus,
        });
      }

      if (
        fabricRecord.lifecycleStatus !==
          "READY_FOR_PROPAGATION" &&
        fabricRecord.lifecycleStatus !==
          "PROPAGATED"
      ) {
        return res.status(409).json({
          success: false,

          error:
            "Defense rule is not currently ready for propagation.",

          lifecycleStatus:
            fabricRecord.lifecycleStatus,
        });
      }

      incident.propagationPolicy =
        incident.propagationPolicy ||
        createPropagationPolicy(incident);

      const targetScope =
        normalizeScope(
          req.body?.scope,
          incident
        );

      if (!targetScope) {
        return res.status(409).json({
          success: false,
          error:
            "No additional propagation scope is available.",
        });
      }

      const requiredApprovalGate =
        getRequiredApproval(
          targetScope
        );

      if (requiredApprovalGate) {
        const gateState =
          incident.propagationPolicy
            .approvals[
            requiredApprovalGate
          ];
        if (
          !gateState ||
          !isApprovalSatisfied(
            gateState
          )
        ) {
          return res.status(409).json({
            success: false,
            error:
              `Propagation to ${targetScope} requires ${requiredApprovalGate} approval.`,
            requiredApprovalGate,
            gateState,
          });
        }
      }

      const hierarchyContext =
        incident.hierarchy ||
        resolveEndpointContext({
          endpointId:
            incident.asset,
        });

      const targets =
        getTargetsForScope(
          targetScope,
          hierarchyContext
        );

      if (!targets.length) {
        return res.status(404).json({
          success: false,
          error:
            "No endpoints matched the requested scope.",
          targetScope,
        });
      }

      const canaryCount = Math.min(
        incident.propagationPolicy
          .canarySampleSize || 1,
        targets.length
      );

      const canaryTargets =
        targets.slice(0, canaryCount);

      const now =
        new Date().toISOString();

      const falsePositiveRate =
        Number(
          req.body?.falsePositiveRate ??
            0.01
        );
      const rollbackTriggered =
        Boolean(req.body?.forceRollback) ||
        falsePositiveRate >
          incident
            .propagationPolicy
            .rollbackThreshold;

      const endpointRollout = {
        scope:
          targetScope,
        status:
          rollbackTriggered
            ? "ROLLED_BACK"
            : "DEPLOYED",
        simulated:
          true,
        canaryTargets:
          canaryTargets.map(
            (item) =>
              item.endpointId
          ),
        targetCount:
          targets.length,
        rolledOutAt:
          now,
        falsePositiveRate,
        rollbackThreshold:
          incident
            .propagationPolicy
            .rollbackThreshold,
        fanOut:
          {
            orchestrators: [
              "WAZUH_MANAGER",
              "SURICATA_MANAGER",
              "SNORT_MANAGER",
              "SYSMON_COLLECTOR",
            ],
            rolloutMode:
              rollbackTriggered
                ? "CANARY_ROLLBACK"
                : "CANARY_THEN_FULL",
          },
        endpointResults:
          targets.map(
            (endpoint, index) => ({
              endpointId:
                endpoint.endpointId,
              collegeId:
                endpoint.collegeId,
              labId:
                endpoint.labId,
              stage:
                index < canaryCount
                  ? "CANARY"
                  : "FULL",
              status:
                rollbackTriggered &&
                index >= canaryCount
                  ? "SKIPPED_DUE_TO_ROLLBACK"
                  : "UPDATED",
              reason:
                rollbackTriggered &&
                index >= canaryCount
                  ? "False positive threshold exceeded"
                  : "Rule distributed by central IDS orchestrators",
            })
          ),
      };

      incident.propagationPolicy
        .endpointRolloutResults.push(
          endpointRollout
        );

      incident.propagationPolicy.currentScope =
        targetScope;

      if (!rollbackTriggered) {
        incident.propagationPolicy.deployedScopes =
          Array.from(
            new Set([
              ...incident.propagationPolicy
                .deployedScopes,
              targetScope,
            ])
          );
      }

      const scopeAuditStatus =
        rollbackTriggered
          ? `ROLLBACK_${targetScope}`
          : `PROPAGATED_${targetScope}`;

      const scopeAuditResult =
        await updateDefenseStatus(
          fabricIncidentId,
          scopeAuditStatus
        );

      let lifecycleResult = null;
      if (
        !rollbackTriggered &&
        targetScope ===
          PROPAGATION_SCOPES.ASTU_WIDE
      ) {
        lifecycleResult =
          await updateDefenseStatus(
            fabricIncidentId,
            "PROPAGATED"
          );
      } else {
        lifecycleResult =
          await updateDefenseStatus(
            fabricIncidentId,
            "READY_FOR_PROPAGATION"
          );
      }

      const auditEvent = {
        type:
          "SCOPE_PROPAGATION",
        scope:
          targetScope,
        status:
          endpointRollout.status,
        recordedAt:
          now,
        scopeAuditTxId:
          scopeAuditResult.transactionId,
        lifecycleTxId:
          lifecycleResult.transactionId,
        targetCount:
          targets.length,
        canaryCount,
        falsePositiveRate,
      };

      incident.propagationPolicy.auditTrail.push(
        auditEvent
      );

      incident.fabric.lifecycleStatus =
        lifecycleResult.status;

      incident.fabric.transactionIds =
        incident.fabric.transactionIds || {};

      incident.fabric.transactionIds[
        `scope_${targetScope}_${Date.now()}`
      ] =
        scopeAuditResult.transactionId;

      incident.fabric.transactionIds[
        `lifecycle_${targetScope}_${Date.now()}`
      ] =
        lifecycleResult.transactionId;

      const propagation = {
        status:
          endpointRollout.status,
        scope:
          targetScope,
        simulated:
          true,
        propagatedAt:
          now,
        ruleId:
          fabricRecord
            .defenseRule
            ?.ruleId || null,
        ruleType:
          fabricRecord
            .defenseRule
            ?.type || null,
        action:
          fabricRecord
            .defenseRule
            ?.action || null,
        ruleVersion:
          incident.propagationPolicy
            .ruleVersion,
        ttlSeconds:
          incident.propagationPolicy
            .ruleTtlSeconds,
        targetCount:
          endpointRollout.targetCount,
        canaryCount,
        rollbackTriggered,
        falsePositiveRate,
      };

      incident.propagation =
        propagation;

      saveIncidents();

      res.json({
        success: true,
        incidentId: fabricIncidentId,
        message:
          rollbackTriggered
            ? "Canary rollback triggered; full rollout halted."
            : "Defense rule successfully propagated for requested scope.",
        propagation,
        propagationPolicy:
          incident.propagationPolicy,
        endpointRollout,
        fabric: {
          lifecycleStatus:
            incident.fabric.lifecycleStatus,
          transactionIds:
            incident.fabric.transactionIds,
        },
      });
    } catch (error) {
      console.error(
        "Defense propagation error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message,
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Start server
|--------------------------------------------------------------------------
*/

const server =
  app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `Cyber Defense Backend running on http://127.0.0.1:${PORT}`
      );

       console.log(
      `Ollama Agent Model: ${
        process.env.OLLAMA_MODEL ||
        "qwen2.5:1.5b-instruct-q4_K_M"
      }`
      );

      console.log(
        `Ollama Endpoint: ${
          process.env.OLLAMA_URL ||
           "http://127.0.0.1:11434/api/chat"
        }`
      );
    }
  );

/*
|--------------------------------------------------------------------------
| Graceful shutdown
|--------------------------------------------------------------------------
*/

async function shutdown() {
  console.log(
    "\nShutting down Cyber Defense Backend..."
  );

  try {
    await closeFabricConnection();
  } catch (error) {
    console.error(
      "Fabric connection close error:",
      error.message
    );
  }

  server.close(() => {
    console.log(
      "Cyber Defense Backend stopped."
    );

    process.exit(0);
  });
}

process.on(
  "SIGINT",
  shutdown
);

process.on(
  "SIGTERM",
  shutdown
);
