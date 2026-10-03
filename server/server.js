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
} = require("./fabricClient");

const app = express();

const PORT = 5000;

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
  function generateSelectedTelemetry(scenario) {
  switch (scenario) {
    case "bruteforce":
      return generateBruteForceTelemetry();

    case "scan":
      return generateNetworkScanTelemetry();

    case "dos":
      return generateDosTelemetry();

    case "process":
      return generateSuspiciousProcessTelemetry();

    default:
      return generateAttackTelemetry();
  }
}
  try {
    /*
    |--------------------------------------------------------------------------
    | 1. Generate controlled synthetic attack
    |--------------------------------------------------------------------------
    */

    const scenario = req.body.scenario || "bruteforce";
    const attack = generateSelectedTelemetry(scenario);

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
        attack.targetSystem,

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
          attack.targetSystem,

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
          "mychannel",

        chaincode:
          "defenseRegistry",

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
              attack.targetSystem,

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
            "mychannel",

          chaincode:
            "defenseRegistry",

          evidenceHash:
            fabricResult.evidenceHash,

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
            "mychannel",

          chaincode:
            "defenseRegistry",

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

      /*
      |--------------------------------------------------------------------------
      | Read authoritative defense record from Fabric
      |--------------------------------------------------------------------------
      */

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

      /*
      |--------------------------------------------------------------------------
      | Propagation is allowed only after validation
      |--------------------------------------------------------------------------
      */

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

      /*
      |--------------------------------------------------------------------------
      | Propagation is allowed only after Fabric lifecycle approval
      |--------------------------------------------------------------------------
      */

      if (
        fabricRecord.lifecycleStatus !==
        "READY_FOR_PROPAGATION"
      ) {
        return res.status(409).json({
          success: false,

          error:
            "Defense rule is not currently ready for propagation.",

          lifecycleStatus:
            fabricRecord.lifecycleStatus,
        });
      }

      /*
      |--------------------------------------------------------------------------
      | Controlled propagation simulation
      |--------------------------------------------------------------------------
      |
      | In a production deployment this stage would call
      | an enforcement mechanism such as a firewall,
      | IDS/IPS, endpoint security platform, etc.
      |
      | For this MVP we only record that the generated
      | defense rule was successfully propagated.
      |
      |--------------------------------------------------------------------------
      */

      const propagation = {
        status:
          "PROPAGATED",

        simulated:
          true,

        propagatedAt:
          new Date().toISOString(),

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
      };

      /*
      |--------------------------------------------------------------------------
      | Record lifecycle transition on Fabric
      |--------------------------------------------------------------------------
      */

      await updateDefenseStatus(
        fabricIncidentId,
        "PROPAGATED"
      );

      /*
      |--------------------------------------------------------------------------
      | Keep local incident state synchronized
      |--------------------------------------------------------------------------
      */

      incident.propagation =
        propagation;

      incident.fabric.lifecycleStatus =
        "PROPAGATED";
      saveIncidents();

      /*
      |--------------------------------------------------------------------------
      | Response
      |--------------------------------------------------------------------------
      */

      res.json({
        success: true,

        incidentId: fabricIncidentId,

        message:
          "Defense rule successfully propagated.",

        propagation,

        fabric: {
          lifecycleStatus:
            "PROPAGATED",
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
