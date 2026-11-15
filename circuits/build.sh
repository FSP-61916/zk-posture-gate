#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Compile posture.circom and run the whole Groth16 setup.
#
#   npm run setup:circuit        (from the project root)
#
# You need the circom 2.x compiler. On Windows download the release binary from
# https://github.com/iden3/circom/releases (circom-windows-amd64.exe) and point
# CIRCOM_BIN at it, e.g.  $env:CIRCOM_BIN = "C:\tools\circom.exe"
# On Linux the binary used below was downloaded to tools/bin/circom.
#
# Outputs (all git-ignored, rebuilt from this script):
#   build/posture.r1cs              constraint system
#   build/posture_js/posture.wasm   witness generator   (agent needs this)
#   build/posture_final.zkey        proving key         (agent needs this)
#   build/verification_key.json     verifying key       (verifier needs this)
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

CIRCOM="${CIRCOM_BIN:-../tools/bin/circom}"
SNARKJS="${SNARKJS_BIN:-../node_modules/.bin/snarkjs}"
PTAU_POWER="${PTAU_POWER:-12}"   # 2^12 = 4096 constraints of head-room

if [ ! -x "$CIRCOM" ] && ! command -v "$CIRCOM" >/dev/null 2>&1; then
  echo "ERROR: circom not found at '$CIRCOM'. Set CIRCOM_BIN to your circom binary." >&2
  exit 1
fi

mkdir -p build
rm -f build/posture.r1cs build/posture.sym build/posture_0000.zkey build/posture_0001.zkey

echo "== [1/8] compile =="
"$CIRCOM" posture.circom --r1cs --wasm --sym -o build -l ../node_modules
"$SNARKJS" r1cs info build/posture.r1cs

echo "== [2/8] powers of tau (phase 1, power $PTAU_POWER) =="
"$SNARKJS" powersoftau new bn128 "$PTAU_POWER" build/pot_0000.ptau -v

echo "== [3/8] phase-1 contribution =="
"$SNARKJS" powersoftau contribute build/pot_0000.ptau build/pot_0001.ptau \
  --name="ZK Posture Gate phase-1 contribution" \
  -e="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" -v

echo "== [4/8] prepare phase 2 =="
"$SNARKJS" powersoftau prepare phase2 build/pot_0001.ptau build/pot_final.ptau -v

echo "== [5/8] groth16 setup (phase 2, initial) =="
"$SNARKJS" groth16 setup build/posture.r1cs build/pot_final.ptau build/posture_0000.zkey

echo "== [6/8] phase-2 contribution =="
"$SNARKJS" zkey contribute build/posture_0000.zkey build/posture_final.zkey \
  --name="ZK Posture Gate phase-2 contribution" \
  -e="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

echo "== [7/8] export verification key =="
"$SNARKJS" zkey export verificationkey build/posture_final.zkey build/verification_key.json

echo "== [8/8] verify the exported key matches the circuit =="
"$SNARKJS" zkey verify build/posture.r1cs build/pot_final.ptau build/posture_final.zkey

echo
echo "Done. Artifacts in circuits/build/"
echo "Next: node scripts/demo-endtoend.js   (runs a full proof/verify round trip)"
