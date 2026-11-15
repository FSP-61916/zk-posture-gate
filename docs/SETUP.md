# Setup

Everything below was run on this development machine (Linux, Node 26.13.0) to
produce the artifacts in this repo. The Windows-specific steps are marked and
are **UNVERIFIED** until run on a Windows machine.

---

## 1. Check what you have

```powershell
node -v
npm -v
```

Real output here:

```
v26.13.0
11.20.0
```

The project requires Node.js 20 or newer (`"engines": { "node": ">=20.0.0" }`).

---

## 2. Install dependencies (pinned)

```powershell
npm ci
```

`npm ci` installs exactly what `package-lock.json` says. Do not use
`npm install` for the demo machine; it can silently drift.

Versions are listed in [VERSIONS.md](VERSIONS.md).

---

## 3. Get circom 2.x

`circom` is a Rust binary, not an npm package, so it is not installed by
`npm ci`.

1. Open https://github.com/iden3/circom/releases in a **browser**.
2. Download the asset for your OS:
   - Windows: `circom-windows-amd64.exe`
   - Linux: `circom-linux-amd64`
3. Put it somewhere permanent, e.g. `C:\tools\circom.exe`.
4. Tell the build script where it is:

```powershell
$env:CIRCOM_BIN = "C:\tools\circom.exe"
circom --version
```

Real output here (Linux binary, v2.1.9):

```
circom compiler 2.1.9
```

On this repository the binary lives at `tools/bin/circom` (git-ignored).

---

## 4. Compile the circuit and run the trusted setup

```powershell
npm run setup:circuit
```

That is a wrapper for `circuits/build.sh`, which runs:

| Step | Command | Why |
|---|---|---|
| 1 | `circom posture.circom --r1cs --wasm --sym -l ../node_modules` | Compile. `-l` finds `circomlib`. |
| 2 | `snarkjs powersoftau new bn128 12 pot_0000.ptau` | Phase 1, 2^12 = 4096 constraints of head-room. |
| 3 | `snarkjs powersoftau contribute ... -e <32 random bytes>` | One phase-1 contribution. |
| 4 | `snarkjs powersoftau prepare phase2 ...` | Prepare for Groth16. |
| 5 | `snarkjs groth16 setup posture.r1cs pot_final.ptau posture_0000.zkey` | Per-circuit phase 2. |
| 6 | `snarkjs zkey contribute ...` | One phase-2 contribution. |
| 7 | `snarkjs zkey export verificationkey ...` | Produces `verification_key.json`. |
| 8 | `snarkjs zkey verify ...` | Confirms key ↔ circuit match. |

Real output on this machine (trimmed):

```
== [1/8] compile ==
template instances: 6
non-linear constraints: 125
linear constraints: 0
public inputs: 5
private inputs: 4
public outputs: 2
wires: 126
== [8/8] verify the exported key matches the circuit ==
[INFO]  snarkJS: ZKey Ok!
Done. Artifacts in circuits/build/
```

**This setup is per-circuit and was run by us for the demo.** It is not a
ceremony with independent participants. Anyone who runs this script gets a
different (equally valid) key pair, and the artifacts are git-ignored.

### Artifacts

| File | Used by | Size (bytes) |
|---|---|---|
| `circuits/build/posture.r1cs` | build only | — |
| `circuits/build/posture_js/posture.wasm` | agent (prover) | 42,575 |
| `circuits/build/posture_final.zkey` | agent (prover) | 84,622 |
| `circuits/build/verification_key.json` | verifier | 4,025 |

---

## 5. Inspect the real public-signal order (do not assume)

```bash
cat > /tmp/in.json <<'EOF'
{"build":"2263103803","updateAgeDays":"4","firewallOn":"1","defenderOn":"1",
 "minBuild":"2200000000","maxUpdateAge":"30","requireFirewall":"1",
 "requireDefender":"1","challenge":"12345678901234567890"}
EOF
node_modules/.bin/snarkjs groth16 fullprove /tmp/in.json \
  circuits/build/posture_js/posture.wasm circuits/build/posture_final.zkey \
  /tmp/proof.json /tmp/public.json
cat /tmp/public.json
```

Real output:

```json
[
 "1",
 "152415787532388367501905199875019052100",
 "2200000000",
 "30",
 "1",
 "1",
 "12345678901234567890"
]
```

That is why `verifier/lib/public-signals.js` uses:

```
0 compliant | 1 challengeSq | 2 minBuild | 3 maxUpdateAge
4 requireFirewall | 5 requireDefender | 6 challenge
```

Note the bug this caught during development: with `component main = PostureGate();`
circom reported **0 public inputs** and `public.json` only had the two outputs.
The policy numbers were private witness and therefore not bound to the proof.
The fix is `component main {public [minBuild, maxUpdateAge, requireFirewall,
requireDefender, challenge]} = PostureGate();`. `tests/circuit.test.js` now
asserts the full seven-signal order.

---

## 6. Inspect the real KEV feed before coding against it

```bash
curl -s -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
node -e 'const d=require("./kev.json"); console.log(Object.keys(d)); console.log(d.vulnerabilities[0])'
```

Real fields found on 2026-11-08 (`count: 1769`, `catalogVersion: 2026.11.06`):

Top level: `title`, `catalogVersion`, `dateReleased`, `count`, `vulnerabilities[]`.

Each entry:

```
cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription,
requiredAction, dueDate, knownRansomwareCampaignUse, forensicTriage, notes, cwes
```

`verifier/lib/kev.js` filters `vendorProject === "Microsoft"` (390 entries on
that date) and keeps `dateAdded >= policy.updatedAt` date. The ransomware flag
is the string `"Known"`.

---

## 7. Start the verifier

```powershell
$env:ADMIN_PASSWORD = "choose-a-long-password"
$env:GATE_UPSTREAM = "http://127.0.0.1:8080"   # optional, this is the default
node verifier/server.js
```

Start the protected app in another terminal before anyone opens the gate:

```powershell
cd internal-app
python -m http.server 8080
```

Real startup output (Linux, `DEMO_LAN` unset → loopback only):

```
  ZK Posture Gate - SINGLE LAPTOP DEMO
  ====================================
  verifier + dashboard: https://127.0.0.1:3000
  gate:                 https://127.0.0.1:8081
  gate forwards to:     http://127.0.0.1:8080/
  binding: 127.0.0.1 (this machine only, never the LAN)
  policy: v1  (build >= 2262100000, updates <= 30 days)
  access token lasts:  10 min
  TLS:                 local CA (data/tls), leaf E9:12:D9:70:3A:04:F8:B6...
  CA pin:              00:4F:1E:94:0A:4B:10:48:CE:5D:1E:D1:7B:65:85:F4:25:D0:A7:A1:0A:17:07:82:01:57:63:E3:11:F2:13:CA
  first run on Windows: .\scripts\trust-ca.ps1   (CurrentUser, no admin)

  Start the protected app first (second terminal):
    cd internal-app
    python -m http.server 8080

  one-time enrollment code: SQGX-JTEN   (expires 2:05:05 PM)

  In a SECOND terminal on this same laptop:

    node agent enroll --code SQGX-JTEN --label "This laptop"
    node agent attest --open

  Then open the dashboard and sign in with $env:ADMIN_PASSWORD:
    https://127.0.0.1:3000

  Optional second identity on the SAME machine (multi-device stays optional):
    $env:AGENT_DATA_DIR = "$PWD\agent\data-second"
    node agent enroll --code <new-code> --label "same machine, 2nd identity"
    node agent attest

  Demo helpers (see docs/DEMO_SCRIPT.md):
    .\scripts\demo-policy.ps1 set-current   |  raise  |  reset
    .\scripts\demo-firewall.ps1 off-public  |  restore
    npm run demo:replay

  NOTE: this machine is not Windows. The dashboard works, but
  "node agent attest" will refuse: posture is read for real, never invented.

  Ctrl+C to stop.
```

(An earlier plain-HTTP startup is gone; TLS is on by default now.)

For the LAN demo, `DEMO_LAN=1` (or `-Lan` on the PowerShell helper) prints every
LAN address it is reachable on.

### Firewall (Windows, LAN demo only, elevated shell)

```powershell
.\scripts\setup-firewall-rule.ps1     # inbound TCP 3000, Private profile only
.\scripts\remove-firewall-rule.ps1    # after the demo
```

---

## 8. Agent on a laptop

```powershell
npm ci
$env:VERIFIER_URL = "http://<MAIN-PC-IP>:3000"
node agent enroll --code ABCD-EFGH --label "Laptop A"
node agent check
node agent attest --open
```

USB bundle without the circom compiler:

```powershell
npm run bundle                       # bundle/agent-bundle/
node scripts/build-agent-bundle.js --with-node-modules   # fully offline copy
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ADMIN_PASSWORD is not set` | Set it in the environment before starting the verifier. |
| `verification key not found` | Run `npm run setup:circuit` first. |
| `Posture can only be read on Windows` | Expected on Linux/macOS. The agent refuses to invent values. |
| `cannot reach verifier` | Wrong `VERIFIER_URL`, firewall rule missing, or not on the same network. |
| Dashboard login loops | Cookie blocked; use `https://127.0.0.1:3000` exactly, not `localhost` mixed with an IP. |
