const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const grpc = require("@grpc/grpc-js");

const {
  connect,
  signers,
} = require("@hyperledger/fabric-gateway");

const FABRIC_DIR = path.join(
  __dirname, 
  "..", 
  "Hyperledger Fabric"
);

const CRYPTO_DIR = path.join(
  FABRIC_DIR,
  "crypto",
  "org1"
);

const CHANNEL_NAME =
  process.env.FABRIC_CHANNEL_NAME ||
  "main-incident-channel";

const CHAINCODE_NAME =
  process.env.FABRIC_CHAINCODE_NAME ||
  "defenseRegistry";

const OWNER_ORG_MSP =
  process.env.FABRIC_OWNER_ORG_MSP ||
  "Org1MSP";

const DEFAULT_ALLOWED_ORGS =
  process.env.FABRIC_ALLOWED_ORGS ||
  "Org1MSP,Org2MSP,Org3MSP,Org4MSP";

const DEFAULT_ALLOWED_ROLES =
  process.env.FABRIC_ALLOWED_ROLES ||
  "analyst,responder,auditor,admin";

const DEFAULT_REQUIRED_APPROVAL_ORGS =
  process.env.FABRIC_REQUIRED_APPROVAL_ORGS ||
  "Org1MSP,Org3MSP";

const PRIVATE_EVIDENCE_COLLECTION =
  process.env.FABRIC_PRIVATE_EVIDENCE_COLLECTION ||
  "incidentEvidencePrivateCollection";

const PEER_ENDPOINT = "localhost:7051";
const PEER_HOST_ALIAS = "peer0.org1.example.com";

const CERTIFICATE_PATH = path.join(
  CRYPTO_DIR,
  "admin-cert.pem"
);

const PRIVATE_KEY_PATH = path.join(
  CRYPTO_DIR,
  "admin-key.pem"
);

const TLS_CERT_PATH = path.join(
  CRYPTO_DIR,
  "peer-tls-ca.crt"
);

let gateway = null;
let contract = null;

function connectToFabric() {
  if (gateway && contract) {
    return contract;
  }

  console.log("[Fabric] Loading crypto material...");

  const certificate = fs.readFileSync(
    CERTIFICATE_PATH
  );

  const privateKeyPem = fs.readFileSync(
    PRIVATE_KEY_PATH
  );

  const tlsRootCert = fs.readFileSync(
    TLS_CERT_PATH
  );

  const client = new grpc.Client(
    PEER_ENDPOINT,
    grpc.credentials.createSsl(tlsRootCert),
    {
      "grpc.ssl_target_name_override": PEER_HOST_ALIAS,
      "grpc.default_authority": PEER_HOST_ALIAS,
    }
  );

  gateway = connect({
    client,

    identity: {
      mspId: "Org1MSP",
      credentials: certificate,
    },

    signer: signers.newPrivateKeySigner(
      crypto.createPrivateKey(privateKeyPem)
    ),
  });

  const network =
    gateway.getNetwork(CHANNEL_NAME);

  contract =
    network.getContract(CHAINCODE_NAME);

  console.log(
    `[Fabric] Connected to ${CHANNEL_NAME}/${CHAINCODE_NAME}`
  );

  return contract;
}

function hashEvidence(evidence) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(evidence))
    .digest("hex");
}

function parseCsvList(input) {
  return String(input || "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

async function registerDefense({
  incidentId,
  attackType,
  mitreTechnique,
  sourceIP,
  targetSystem,
  riskScore,
  agentConfidence,
  evidence,
  defenseRule,
  validationStatus,
  timestamp,
  ownerOrgMSP = OWNER_ORG_MSP,
  accessPolicy = {},
  evidencePrivateMetadata = null,
}) {
  const fabricContract =
    connectToFabric();

  const evidenceHash =
    hashEvidence(evidence);

  const allowedOrgs =
    accessPolicy.allowedOrgs ||
    parseCsvList(DEFAULT_ALLOWED_ORGS);

  const allowedRoles =
    accessPolicy.allowedRoles ||
    parseCsvList(DEFAULT_ALLOWED_ROLES);

  const requiredApprovals =
    accessPolicy.requiredApprovals ||
    parseCsvList(DEFAULT_REQUIRED_APPROVAL_ORGS);

  console.log(
    `[Fabric] Registering defense for ${incidentId}...`
  );

  const registerDefenseTx =
    fabricContract.createTransaction(
      "RegisterDefense"
    );

  const result =
    await registerDefenseTx.submit(
      incidentId,
      attackType,
      mitreTechnique,
      sourceIP,
      targetSystem,
      String(riskScore),
      String(agentConfidence),
      evidenceHash,
      JSON.stringify(defenseRule),
      validationStatus,
      timestamp,
      ownerOrgMSP,
      JSON.stringify(allowedOrgs),
      JSON.stringify(allowedRoles),
      JSON.stringify(requiredApprovals)
    );

  const registerTxId =
    registerDefenseTx.getTransactionId();

  let privateEvidenceTxId = null;

  if (evidencePrivateMetadata) {
    const privateMetadata =
      JSON.stringify({
        ...evidencePrivateMetadata,
        evidenceHash,
        incidentId,
      });

    const privateEvidenceTx =
      fabricContract.createTransaction(
        "AnchorPrivateEvidence"
      );

    await privateEvidenceTx.submit(
      incidentId,
      evidencePrivateMetadata.collection ||
        PRIVATE_EVIDENCE_COLLECTION,
      privateMetadata
    );

    privateEvidenceTxId =
      privateEvidenceTx.getTransactionId();
  }

  console.log(
    `[Fabric] Defense registered: ${incidentId}`
  );

  return {
    success: true,
    incidentId,
    evidenceHash,
    transactionId: registerTxId,
    privateEvidenceTransactionId: privateEvidenceTxId,
    result: result.toString(),
  };
}

async function getDefense(incidentId) {
  const fabricContract =
    connectToFabric();

  const result =
    await fabricContract.evaluateTransaction(
      "GetDefense",
      incidentId
    );

  return JSON.parse(
    Buffer.from(result).toString("utf8")
  );
}

async function updateDefenseStatus(
  incidentId,
  status
) {
  const fabricContract =
    connectToFabric();

  const statusTransaction =
    fabricContract.createTransaction(
      "UpdateDefenseStatus"
    );

  await statusTransaction.submit(
    incidentId,
    status
  );

  const transactionId =
    statusTransaction.getTransactionId();

  console.log(
    `[Fabric] ${incidentId} status updated to ${status}`
  );

  return {
    success: true,
    incidentId,
    status,
    transactionId,
  };
}

async function getAllDefenses() {
  const fabricContract =
    connectToFabric();

  const result =
    await fabricContract.evaluateTransaction(
      "GetAllDefenses"
    );

  return JSON.parse(
    Buffer.from(result).toString("utf8")
  );
}

function closeFabricConnection() {
  if (gateway) {
    gateway.close();
  }

  gateway = null;
  contract = null;

  console.log(
    "[Fabric] Connection closed"
  );
}

module.exports = {
  connectToFabric,
  registerDefense,
  getDefense,
  updateDefenseStatus,
  getAllDefenses,
  hashEvidence,
  closeFabricConnection,
  CHANNEL_NAME,
  CHAINCODE_NAME,
  OWNER_ORG_MSP,
  PRIVATE_EVIDENCE_COLLECTION,
};