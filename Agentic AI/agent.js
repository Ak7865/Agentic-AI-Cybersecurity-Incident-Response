const OLLAMA_ENDPOINT =
    process.env.OLLAMA_ENDPOINT ||
    "http://127.0.0.1:11434/api/chat";

const OLLAMA_MODEL =
    process.env.OLLAMA_MODEL ||
    "qwen2.5:1.5b-instruct-q4_K_M";

const OLLAMA_TIMEOUT_MS = 180000;


/*
|--------------------------------------------------------------------------
| Ollama
|--------------------------------------------------------------------------
*/

async function callOllama(messages, stageName) {
    const startedAt = Date.now();

    console.log(`[Agent] ${stageName}: Calling Ollama...`);

    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort();
    }, OLLAMA_TIMEOUT_MS);

    const maxTokens =
        stageName === "Stage 1" ? 180 : 320;

    try {
        const response = await fetch(OLLAMA_ENDPOINT, {
            method: "POST",

            headers: {
                "Content-Type": "application/json",
            },

            body: JSON.stringify({
                model: OLLAMA_MODEL,
                messages,

                stream: false,

                format: "json",

                keep_alive: "10m",

                options: {
                    temperature: 0.1,
                    top_p: 0.8,
                    num_ctx: 2048,
                    num_predict: maxTokens,
                    num_thread: 4,
                },
            }),

            signal: controller.signal,
        });

        if (!response.ok) {
            const errorText = await response.text();

            throw new Error(
                `Ollama returned HTTP ${response.status}: ${errorText}`
            );
        }

        const data = await response.json();

        if (!data.message || !data.message.content) {
            throw new Error("Ollama returned an empty response");
        }

        let parsed;

        try {
            parsed = JSON.parse(data.message.content);
        } catch (error) {
            throw new Error(
                `Ollama returned invalid JSON: ${data.message.content}`
            );
        }

        const elapsed = Date.now() - startedAt;

        console.log(
            `[Agent] ${stageName}: Ollama response parsed in ${elapsed}ms`
        );

        console.log(
            `[Agent] ${stageName}: Ollama response received`
        );

        return parsed;

    } catch (error) {
        if (error.name === "AbortError") {
            throw new Error(
                `Ollama request timed out after ${OLLAMA_TIMEOUT_MS / 1000}s`
            );
        }

        throw error;

    } finally {
        clearTimeout(timeout);
    }
}


/*
|--------------------------------------------------------------------------
| Stage 1 — Threat Investigation
|--------------------------------------------------------------------------
*/

async function investigateThreat(attack, detection) {
    console.log("[Agent] Stage 1: Threat investigation...");

    const systemPrompt = `
You are a cybersecurity threat investigation agent.

The deterministic security detector has already identified the attack.

IMPORTANT:

- The detector's attack classification is authoritative.
- The detector's MITRE ATT&CK technique is authoritative.
- NEVER replace, change, reinterpret, or invent the attack classification.
- NEVER replace, change, reinterpret, or invent the MITRE technique.
- Do not perform MITRE classification yourself.
- Do not invent evidence.
- Base your reasoning only on the supplied telemetry.

Your task is to analyze the supplied evidence and provide:

1. risk score from 0 to 100
2. investigation confidence from 0 to 1
3. concise reasoning
4. important evidence observations

Return ONLY valid JSON.

Required JSON format:

{
  "confidence": 0.0,
  "riskScore": 0,
  "reason": "string",
  "reasoning": [
    "string"
  ],
  "evidence": [
    "string"
  ]
}
`;

    const telemetry = {
        sourceIp: attack.sourceIp,
        targetSystem: attack.targetSystem,
        failedAttempts: attack.failedAttempts,

        usernames: [
            ...new Set(
                attack.events
                    .map((event) => event.username)
                    .filter(Boolean)
            ),
        ],
    };

    const userPrompt = `
DETERMINISTIC DETECTOR DECISION

Attack Type:

${detection.attackType}

MITRE ATT&CK:

${detection.technique.id} - ${detection.technique.name}

Detector Confidence:

${detection.confidence}

Detector Evidence:

${JSON.stringify(detection.evidence, null, 2)}

Detector Reason:

${detection.reason}

OBSERVED ATTACK TELEMETRY

${JSON.stringify(telemetry, null, 2)}

Analyze the evidence.

Do not change the detector classification or MITRE technique.

Do not create additional attack categories.

Return only the requested JSON object.
`;

    const result = await callOllama(
        [
            {
                role: "system",
                content: systemPrompt,
            },
            {
                role: "user",
                content: userPrompt,
            },
        ],
        "Stage 1"
    );

    const confidence = Number(result.confidence);
    const riskScore = Number(result.riskScore);

    return {
        classification: detection.attackType,

        technique: {
            id: detection.technique.id,
            name: detection.technique.name,
        },

        confidence: Number.isFinite(confidence)
            ? Math.max(0, Math.min(1, confidence))
            : detection.confidence,

        riskScore: Number.isFinite(riskScore)
            ? Math.max(0, Math.min(100, Math.round(riskScore)))
            : 50,

        reason:
            typeof result.reason === "string"
                ? result.reason
                : detection.reason,

        reasoning: Array.isArray(result.reasoning)
            ? result.reasoning
            : [],

        evidence: Array.isArray(result.evidence)
            ? result.evidence
            : detection.evidence,
    };
}


/*
|--------------------------------------------------------------------------
| Normalize Stage 2 Output
|--------------------------------------------------------------------------
|
| Qwen 1.5B sometimes produces an older IDS-style schema:
|
| {
|   rule_id,
|   description,
|   action,
|   rule_text
| }
|
| Convert that response into our canonical schema.
|--------------------------------------------------------------------------
*/

function normalizeDefenseRule(
    result,
    detection,
    attack
) {
    /*
    |--------------------------------------------------------------------------
    | Canonical schema
    |--------------------------------------------------------------------------
    */

    if (
        result &&
        result.defenseRule &&
        typeof result.defenseRule === "object"
    ) {
        return {
            ruleName:
                typeof result.ruleName === "string" &&
                result.ruleName.trim()
                    ? result.ruleName.trim()
                    : "Adaptive IDS Defense Rule",

            defenseRule: result.defenseRule,

            severity:
                typeof result.severity === "string"
                    ? result.severity.toUpperCase()
                    : "MEDIUM",

            reason:
                typeof result.reason === "string"
                    ? result.reason
                    : result.defenseRule.explanation || "",

            review:
                result.review &&
                typeof result.review === "object"
                    ? result.review
                    : {
                          approved: true,
                          risk: "LOW",
                          issues: [],
                          recommendations: [],
                          reason:
                              "Defense rule passed structural normalization.",
                      },

            ruleId:
                typeof result.ruleId === "string"
                    ? result.ruleId.trim()
                    : "",
        };
    }


    /*
    |--------------------------------------------------------------------------
    | Alternate "rule" schema
    |--------------------------------------------------------------------------
    |
    | Current Qwen response:
    |
    | {
    |   "rule": {
    |      "name": "...",
    |      "description": "...",
    |      "action": "block",
    |      "conditions": [...],
    |      "response": {...}
    |   }
    | }
    |
    */

    if (
        result &&
        result.rule &&
        typeof result.rule === "object"
    ) {
        console.log(
            "[Agent] Stage 2: Normalizing Qwen rule schema"
        );


        const modelRule = result.rule;


        /*
        |--------------------------------------------------------------------------
        | Rule name
        |--------------------------------------------------------------------------
        */

        const ruleName =
            typeof modelRule.name === "string" &&
            modelRule.name.trim()
                ? modelRule.name.trim()
                : `Adaptive ${detection.attackType} Defense`;


        /*
        |--------------------------------------------------------------------------
        | Conditions
        |--------------------------------------------------------------------------
        */

        const condition = {};


        if (Array.isArray(modelRule.conditions)) {
            condition.conditions = modelRule.conditions;
        }


        /*
        |--------------------------------------------------------------------------
        | Add authoritative telemetry
        |--------------------------------------------------------------------------
        */

        if (attack.sourceIp) {
            condition.sourceIp = attack.sourceIp;
        }

        if (attack.targetSystem) {
            condition.targetSystem = attack.targetSystem;
        }


        /*
        |--------------------------------------------------------------------------
        | Technique-specific condition
        |--------------------------------------------------------------------------
        */

        if (detection.technique.id === "T1110") {
            condition.failedAttempts = 5;
            condition.windowSeconds = 60;
        }


        if (detection.technique.id === "T1046") {
            condition.connectionAttempts = 10;
            condition.windowSeconds = 15;
        }


        if (detection.technique.id === "T1498") {
            condition.requestThreshold = 50;
            condition.windowSeconds = 15;
        }


        if (detection.technique.id === "T1059.001") {
            condition.processNames = [
                "powershell.exe",
                "cmd.exe",
                "net.exe",
            ];
        }


        /*
        |--------------------------------------------------------------------------
        | Action
        |--------------------------------------------------------------------------
        */

        let action = {};


        if (
            modelRule.response &&
            typeof modelRule.response === "object"
        ) {
            action = {
                ...modelRule.response,
            };
        } else if (
            modelRule.action &&
            typeof modelRule.action === "object"
        ) {
            action = {
                ...modelRule.action,
            };
        } else if (
            typeof modelRule.action === "string"
        ) {
            action = {
                type: modelRule.action,
            };
        }


        /*
        |--------------------------------------------------------------------------
        | Ensure action type exists
        |--------------------------------------------------------------------------
        */

        if (
            !action.type &&
            typeof modelRule.action === "string"
        ) {
            action.type = modelRule.action;
        }


        /*
        |--------------------------------------------------------------------------
        | Explanation
        |--------------------------------------------------------------------------
        */

        let explanation = "";

        if (
            typeof modelRule.description === "string"
        ) {
            explanation = modelRule.description.trim();
        }

        if (
            !explanation &&
            typeof modelRule.rule_text === "string"
        ) {
            explanation = modelRule.rule_text.trim();
        }

        if (
            !explanation &&
            typeof modelRule.response?.reason === "string"
        ) {
            explanation =
                modelRule.response.reason.trim();
        }

        if (!explanation) {
            explanation =
                `Adaptive defense generated for ${detection.attackType}.`;
        }


        /*
        |--------------------------------------------------------------------------
        | Technique-specific defense type
        |--------------------------------------------------------------------------
        */

        let defenseType = "adaptive_ids_rule";


        switch (detection.technique.id) {
            case "T1110":
                defenseType = "authentication_rate_limit";
                break;

            case "T1046":
                defenseType = "network_scan_rate_limit";
                break;

            case "T1498":
                defenseType = "http_rate_limit";
                break;

            case "T1059.001":
                defenseType =
                    "powershell_process_restriction";
                break;
        }


        /*
        |--------------------------------------------------------------------------
        | Severity
        |--------------------------------------------------------------------------
        */

        const severity =
            detection.confidence >= 0.9
                ? "HIGH"
                : "MEDIUM";


        /*
        |--------------------------------------------------------------------------
        | Review
        |--------------------------------------------------------------------------
        */

        const review = {
            approved: true,

            risk: "LOW",

            issues: [],

            recommendations: [
                "Validate the generated defense rule before production deployment.",
            ],

            reason:
                "The model response was normalized into the canonical defense-rule schema.",
        };


        /*
        |--------------------------------------------------------------------------
        | Return canonical structure
        |--------------------------------------------------------------------------
        */

        return {
            ruleName,

            defenseRule: {
                type: defenseType,

                condition,

                action,

                explanation,
            },

            severity,

            reason: explanation,

            review,

            ruleId:
                typeof modelRule.id === "string"
                    ? modelRule.id.trim()
                    : "",
        };
    }


    /*
    |--------------------------------------------------------------------------
    | Legacy IDS schema
    |--------------------------------------------------------------------------
    |
    | Example:
    |
    | {
    |   "rule_id": "...",
    |   "description": "...",
    |   "action": {...},
    |   "rule_text": "..."
    | }
    |
    */

    if (
        result &&
        typeof result === "object" &&
        (
            result.rule_id ||
            result.description ||
            result.rule_text
        )
    ) {
        console.log(
            "[Agent] Stage 2: Normalizing legacy IDS rule schema"
        );


        const condition = {
            sourceIp:
                attack.sourceIp || "unknown",

            targetSystem:
                attack.targetSystem || "unknown",
        };


        if (detection.technique.id === "T1110") {
            condition.failedAttempts = 5;
            condition.windowSeconds = 60;
        }


        if (detection.technique.id === "T1046") {
            condition.connectionAttempts = 10;
            condition.windowSeconds = 15;
        }


        if (detection.technique.id === "T1498") {
            condition.requestThreshold = 50;
            condition.windowSeconds = 15;
        }


        if (detection.technique.id === "T1059.001") {
            condition.processNames = [
                "powershell.exe",
                "cmd.exe",
                "net.exe",
            ];
        }


        let action = {};


        if (
            result.action &&
            typeof result.action === "object"
        ) {
            action = result.action;
        } else {
            action = {
                type:
                    typeof result.action === "string"
                        ? result.action
                        : "temporary_restriction",
            };
        }


        const explanation =
            typeof result.description === "string"
                ? result.description
                : typeof result.rule_text === "string"
                    ? result.rule_text
                    : "Adaptive defense generated from observed attack telemetry.";


        let defenseType =
            "adaptive_ids_rule";


        switch (detection.technique.id) {
            case "T1110":
                defenseType =
                    "authentication_rate_limit";
                break;

            case "T1046":
                defenseType =
                    "network_scan_rate_limit";
                break;

            case "T1498":
                defenseType =
                    "http_rate_limit";
                break;

            case "T1059.001":
                defenseType =
                    "powershell_process_restriction";
                break;
        }


        return {
            ruleName:
                typeof result.description === "string"
                    ? result.description
                    : `Adaptive ${detection.attackType} Defense`,

            defenseRule: {
                type: defenseType,

                condition,

                action,

                explanation,
            },

            severity:
                detection.confidence >= 0.9
                    ? "HIGH"
                    : "MEDIUM",

            reason: explanation,

            review: {
                approved: true,
                risk: "LOW",
                issues: [],
                recommendations: [
                    "Validate the generated rule before production deployment.",
                ],
                reason:
                    "Legacy IDS response normalized into the canonical defense-rule schema.",
            },

            ruleId:
                typeof result.rule_id === "string"
                    ? result.rule_id.trim()
                    : "",
        };
    }


    /*
    |--------------------------------------------------------------------------
    | Unknown schema
    |--------------------------------------------------------------------------
    */

    return null;
}


/*
|--------------------------------------------------------------------------
| Stage 2 — Agent Generated Adaptive IDS Defense
|--------------------------------------------------------------------------
*/

async function generateAdaptiveDefense(
    attack,
    detection,
    investigation
) {
    console.log(
        "[Agent] Stage 2: Adaptive defense generation..."
    );

    const investigationSummary = {
        riskScore: investigation.riskScore,

        confidence: investigation.confidence,

        reason: investigation.reason,

        reasoning: investigation.reasoning,

        keyEvidence: Array.isArray(investigation.evidence)
            ? investigation.evidence.slice(0, 3)
            : [],
    };


    /*
    |--------------------------------------------------------------------------
    | System Prompt
    |--------------------------------------------------------------------------
    */

    const systemPrompt = `
You are an adaptive cybersecurity defense and IDS rule generation agent.

The deterministic detector has already identified the attack.

The detector classification and MITRE ATT&CK technique are AUTHORITATIVE.

You MUST NOT change them.

Your task is to generate ONE safe, targeted and reversible defense rule.

IMPORTANT:

Return ONLY JSON.

Do NOT return Markdown.

Do NOT return code fences.

Do NOT return a "rule" object.

Do NOT return Suricata syntax.

Do NOT return Snort syntax.

Do NOT return firewall CLI commands.

Do NOT return shell commands.

Do NOT return SQL.

Do NOT create destructive actions.

Do NOT delete data.

Do NOT shut down systems.

Do NOT modify unrelated services.

The defense must directly mitigate the detected behavior.

TECHNIQUE GUIDANCE:

T1110 - Brute Force:
- authentication rate limiting
- authentication throttling
- temporary source blocking

T1046 - Network Service Scanning:
- connection-attempt thresholding
- scan-rate limiting
- temporary source blocking

T1498 - Network Denial of Service:
- HTTP/request rate limiting
- traffic throttling
- temporary source restriction

T1059.001 - PowerShell:
- suspicious PowerShell execution restriction
- PowerShell process-chain restriction
- temporary execution restriction
- suspicious parent-child process blocking

IMPORTANT:

Do NOT use authentication defenses for PowerShell.

Do NOT use PowerShell defenses for network scanning.

Do NOT use network scanning defenses for brute force.

The generated attack type MUST exactly match the supplied attack type.

The generated MITRE technique MUST exactly match the supplied MITRE technique.

Return EXACTLY these top-level fields:

ruleId
ruleName
attack
defenseRule
severity
reason
review

Return EXACTLY this structure:

{
  "ruleId": "AG-IDS-T1110-001",
  "ruleName": "Adaptive Brute Force Protection",
  "attack": {
    "type": "Brute Force",
    "mitreTechnique": "T1110"
  },
  "defenseRule": {
    "type": "authentication_rate_limit",
    "condition": {
      "failedAttempts": 5,
      "windowSeconds": 60
    },
    "action": {
      "type": "temporary_source_block",
      "durationSeconds": 300
    },
    "explanation": "Temporarily restrict a source after repeated authentication failures."
  },
  "severity": "HIGH",
  "reason": "The observed authentication failures are consistent with brute-force activity.",
  "review": {
    "approved": true,
    "risk": "LOW",
    "issues": [],
    "recommendations": [],
    "reason": "The proposed defense directly mitigates the detected behavior."
  }
}

The example above is ONLY a structural example.

Use the actual attack, MITRE technique and telemetry supplied by the user.

Return ONLY the JSON object.
`;


    /*
    |--------------------------------------------------------------------------
    | User Prompt
    |--------------------------------------------------------------------------
    */

    const userPrompt = `
AUTHORITATIVE DETECTION

Attack Type:

${detection.attackType}

MITRE ATT&CK:

${detection.technique.id} - ${detection.technique.name}

Source IP:

${attack.sourceIp}

Target System:

${attack.targetSystem}

Observed Failed Attempts:

${attack.failedAttempts ?? 0}

DETECTOR EVIDENCE:

${JSON.stringify(detection.evidence, null, 2)}

DETECTOR REASON:

${detection.reason}

INVESTIGATION:

${JSON.stringify(investigationSummary, null, 2)}

OBSERVED TELEMETRY:

${JSON.stringify(
    attack.events?.slice(0, 12) || [],
    null,
    2
)}

TASK:

Generate ONE adaptive defense rule specifically for:

Attack:
${detection.attackType}

MITRE:
${detection.technique.id} - ${detection.technique.name}

The attack type MUST be:

${detection.attackType}

The MITRE technique MUST be:

${detection.technique.id}

The rule must directly mitigate the observed behavior.

Return only JSON.
`;


    const result = await callOllama(
        [
            {
                role: "system",
                content: systemPrompt,
            },

            {
                role: "user",
                content: userPrompt,
            },
        ],
        "Stage 2"
    );


    console.log(
        "[Agent] RAW STAGE 2 RESULT:",
        JSON.stringify(result, null, 2)
    );


    /*
    |--------------------------------------------------------------------------
    | Normalize Agent Output
    |--------------------------------------------------------------------------
    */

    const normalized = normalizeDefenseRule(
        result,
        detection,
        attack
    );


    if (!normalized) {
        throw new Error(
            "Agent did not produce a recognizable defense rule format"
        );
    }


    /*
    |--------------------------------------------------------------------------
    | Validate Rule ID
    |--------------------------------------------------------------------------
    */

    let ruleId =
        typeof normalized.ruleId === "string"
            ? normalized.ruleId.trim()
            : "";


    /*
    |--------------------------------------------------------------------------
    | Always make the server authoritative for the rule ID
    |--------------------------------------------------------------------------
    */

    ruleId =
        `AG-IDS-${detection.technique.id}-${Date.now()}`;


    /*
    |--------------------------------------------------------------------------
    | Validate Attack Association
    |--------------------------------------------------------------------------
    */

    const attackAssociation = {
        type: detection.attackType,

        mitreTechnique: detection.technique.id,
    };


    /*
    |--------------------------------------------------------------------------
    | Validate Rule Name
    |--------------------------------------------------------------------------
    */

    const ruleName =
        typeof normalized.ruleName === "string" &&
        normalized.ruleName.trim()
            ? normalized.ruleName.trim()
            : "Adaptive IDS Defense Rule";


    /*
    |--------------------------------------------------------------------------
    | Validate Severity
    |--------------------------------------------------------------------------
    */

    const allowedSeverity = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ];


    const severity =
        typeof normalized.severity === "string" &&
        allowedSeverity.includes(
            normalized.severity.toUpperCase()
        )
            ? normalized.severity.toUpperCase()
            : "MEDIUM";


    /*
    |--------------------------------------------------------------------------
    | Construct Final Defense Rule
    |--------------------------------------------------------------------------
    */

    const generatedRule =
        normalized.defenseRule &&
        typeof normalized.defenseRule === "object"
            ? normalized.defenseRule
            : {};


    const defenseRule = {
        ruleId,

        ruleName,

        attack: attackAssociation,

        type:
            typeof generatedRule.type === "string" &&
            generatedRule.type.trim()
                ? generatedRule.type.trim()
                : "adaptive_ids_rule",

        condition:
            generatedRule.condition &&
            typeof generatedRule.condition === "object" &&
            !Array.isArray(generatedRule.condition)
                ? generatedRule.condition
                : {},

        action:
            generatedRule.action &&
            typeof generatedRule.action === "object"
                ? generatedRule.action
                : {},

        explanation:
            typeof generatedRule.explanation === "string"
                ? generatedRule.explanation.trim()
                : "",

        severity,

        reason:
            typeof normalized.reason === "string"
                ? normalized.reason.trim()
                : typeof generatedRule.explanation === "string"
                    ? generatedRule.explanation.trim()
                    : "",
    };


    /*
    |--------------------------------------------------------------------------
    | Review
    |--------------------------------------------------------------------------
    */

    const reviewSource =
        normalized.review &&
        typeof normalized.review === "object"
            ? normalized.review
            : {};


    const review = {
        approved:
            reviewSource.approved === true,

        risk:
            typeof reviewSource.risk === "string"
                ? reviewSource.risk.toUpperCase()
                : "UNKNOWN",

        issues:
            Array.isArray(reviewSource.issues)
                ? reviewSource.issues
                : [],

        recommendations:
            Array.isArray(reviewSource.recommendations)
                ? reviewSource.recommendations
                : [],

        reason:
            typeof reviewSource.reason === "string"
                ? reviewSource.reason
                : "",
    };


    /*
    |--------------------------------------------------------------------------
    | Final Semantic Safety Checks
    |--------------------------------------------------------------------------
    */

    const defenseType =
        defenseRule.type.toLowerCase();

    const defenseExplanation =
        defenseRule.explanation.toLowerCase();


    /*
    |--------------------------------------------------------------------------
    | PowerShell must not receive authentication defense
    |--------------------------------------------------------------------------
    */

    if (
        detection.technique.id === "T1059.001" &&
        (
            defenseType.includes("authentication") ||
            defenseType.includes("login")
        )
    ) {
        throw new Error(
            "Generated defense is incompatible with PowerShell technique T1059.001"
        );
    }


    /*
    |--------------------------------------------------------------------------
    | Brute Force must use authentication-related mitigation
    |--------------------------------------------------------------------------
    */

    if (
        detection.technique.id === "T1110" &&
        !(
            defenseType.includes("authentication") ||
            defenseType.includes("rate") ||
            defenseType.includes("block") ||
            defenseType.includes("throttle")
        )
    ) {
        throw new Error(
            "Generated defense does not appear to mitigate Brute Force technique T1110"
        );
    }


    /*
    |--------------------------------------------------------------------------
    | Network Scan must use connection/scan mitigation
    |--------------------------------------------------------------------------
    */

    if (
        detection.technique.id === "T1046" &&
        !(
            defenseType.includes("connection") ||
            defenseType.includes("scan") ||
            defenseType.includes("rate") ||
            defenseType.includes("block") ||
            defenseType.includes("throttle")
        )
    ) {
        throw new Error(
            "Generated defense does not appear to mitigate Network Service Scanning T1046"
        );
    }


    /*
    |--------------------------------------------------------------------------
    | DoS must use traffic/request mitigation
    |--------------------------------------------------------------------------
    */

    if (
        detection.technique.id === "T1498" &&
        !(
            defenseType.includes("http") ||
            defenseType.includes("request") ||
            defenseType.includes("traffic") ||
            defenseType.includes("rate") ||
            defenseType.includes("throttle") ||
            defenseType.includes("block")
        )
    ) {
        throw new Error(
            "Generated defense does not appear to mitigate Network DoS T1498"
        );
    }


    /*
    |--------------------------------------------------------------------------
    | Log Generated Rule
    |--------------------------------------------------------------------------
    */

    console.log(
        `[Agent] Generated IDS Rule: ${defenseRule.ruleId}`
    );

    console.log(
        `[Agent] Rule Name: ${defenseRule.ruleName}`
    );

    console.log(
        `[Agent] Attack: ${defenseRule.attack.type}`
    );

    console.log(
        `[Agent] MITRE: ${defenseRule.attack.mitreTechnique}`
    );

    console.log(
        `[Agent] Severity: ${defenseRule.severity}`
    );

    console.log(
        `[Agent] Defense Type: ${defenseRule.type}`
    );

    console.log(
        `[Agent] Reason: ${defenseRule.reason}`
    );

    console.log(
        `[Agent] Agent Review Approved: ${review.approved}`
    );


    return {
        defenseRule,
        review,
    };
}


/*
|--------------------------------------------------------------------------
| Complete Agent Investigation
|--------------------------------------------------------------------------
*/

async function analyzeThreat(attack, detection) {
    console.log(
        `[Agent] Starting investigation for ${attack.attackId}...`
    );


    if (!detection || !detection.detected) {
        throw new Error(
            "Agent cannot investigate an undetected attack"
        );
    }


    if (
        !detection.technique ||
        !detection.technique.id ||
        !detection.technique.name
    ) {
        throw new Error(
            "Detector did not provide an authoritative MITRE technique"
        );
    }


    /*
    |--------------------------------------------------------------------------
    | Stage 1
    |--------------------------------------------------------------------------
    */

    const investigation = await investigateThreat(
        attack,
        detection
    );


    investigation.classification =
        detection.attackType;


    investigation.technique = {
        id: detection.technique.id,
        name: detection.technique.name,
    };


    /*
    |--------------------------------------------------------------------------
    | Stage 2
    |--------------------------------------------------------------------------
    */

    const defense = await generateAdaptiveDefense(
        attack,
        detection,
        investigation
    );


    /*
    |--------------------------------------------------------------------------
    | Final Agent Result
    |--------------------------------------------------------------------------
    */

    return {
        classification: detection.attackType,

        technique: {
            id: detection.technique.id,
            name: detection.technique.name,
        },

        confidence: investigation.confidence,

        riskScore: investigation.riskScore,

        reason: investigation.reason,

        reasoning: investigation.reasoning,

        evidence: investigation.evidence,

        defenseRule: defense.defenseRule,

        agentReview: defense.review,

        agent: {
            provider: "ollama",

            model: OLLAMA_MODEL,

            stages: [
                "THREAT_INVESTIGATION",
                "ADAPTIVE_DEFENSE",
            ],

            defenseApproved:
                defense.review.approved === true,
        },
    };
}


/*
|--------------------------------------------------------------------------
| Exports
|--------------------------------------------------------------------------
*/

module.exports = {
    analyzeThreat,
    investigateThreat,
    generateAdaptiveDefense,
};