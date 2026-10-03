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

const CHANNEL_NAME = "mychannel";
const CHAINCODE_NAME = "defenseRegistry";

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
}) {
  const fabricContract =
    connectToFabric();

  const evidenceHash =
    hashEvidence(evidence);

  console.log(
    `[Fabric] Registering defense for ${incidentId}...`
  );

  const result =
    await fabricContract.submitTransaction(
      "RegisterDefense",

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
      timestamp
    );

  console.log(
    `[Fabric] Defense registered: ${incidentId}`
  );

  return {
    success: true,
    incidentId,
    evidenceHash,
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

  await fabricContract.submitTransaction(
    "UpdateDefenseStatus",
    incidentId,
    status
  );

  console.log(
    `[Fabric] ${incidentId} status updated to ${status}`
  );

  return {
    success: true,
    incidentId,
    status,
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
};