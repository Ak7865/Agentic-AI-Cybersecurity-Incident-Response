#!/bin/bash
set -e

echo "==========================================================="
echo " Agentic AI Cybersecurity Incident Response "
echo " Hyperledger Fabric Setup Script (WSL/Linux)"
echo "==========================================================="

if [ -z "$FABRIC_SAMPLES_DIR" ]; then
    FABRIC_SAMPLES_DIR="$HOME/fabric-samples"
fi

if [ ! -d "$FABRIC_SAMPLES_DIR/test-network" ]; then
    echo "Error: fabric-samples not found at $FABRIC_SAMPLES_DIR"
    echo "Please download it first: curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh && bash install-fabric.sh"
    exit 1
fi

PROJECT_ROOT=$(pwd)
CC_NAME="defenseRegistry"
CC_SRC_PATH="$PROJECT_ROOT/Hyperledger Fabric/chaincode/$CC_NAME"

echo "[1] Starting Fabric test network and creating mychannel..."
cd "$FABRIC_SAMPLES_DIR/test-network"

# Only start if not already running
if ! docker ps | grep -q "peer0.org1.example.com"; then
    ./network.sh up createChannel -c mychannel -ca
else
    echo "Fabric network appears to be running already."
    # If the channel doesn't exist, we can't easily script it without more logic, but we'll assume standard test-network setup.
fi

echo "[2] Deploying defenseRegistry chaincode..."
# We only deploy if not already deployed. If it fails due to already being deployed, we ignore the error.
./network.sh deployCC -ccn $CC_NAME -ccp "$CC_SRC_PATH" -ccl go -c mychannel || echo "Chaincode might already be deployed or failed. Check logs."

echo "[3] Extracting runtime crypto material for the Node.js backend..."
CRYPTO_TARGET="$PROJECT_ROOT/Hyperledger Fabric/crypto/org1"
mkdir -p "$CRYPTO_TARGET"

cp "${FABRIC_SAMPLES_DIR}/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/"*.pem "$CRYPTO_TARGET/admin-cert.pem"
cp "${FABRIC_SAMPLES_DIR}/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/"* "$CRYPTO_TARGET/admin-key.pem"
cp "${FABRIC_SAMPLES_DIR}/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" "$CRYPTO_TARGET/peer-tls-ca.crt"

echo "==========================================================="
echo " Setup complete! Crypto material copied to $CRYPTO_TARGET"
echo " You can now run 'npm run dev' on your Windows host."
echo "==========================================================="
