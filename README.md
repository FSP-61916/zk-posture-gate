# ZK Posture Gate

**Prove you're patched without telling us what you're running.**

Each Windows laptop proves, in zero knowledge, that it satisfies the company's
patching policy. The server learns **pass/fail and a reason code** — never the
OS build, the update age, the firewall state or the Defender state.

---

## What it does

- An **agent** on each laptop reads real Windows posture (registry build + UBR,
  Windows Update history, firewall profiles, Defender).
- It generates a **Groth16 zero-knowledge proof** (circom 2.x) that the values
  satisfy the verifier's policy.
- It signs the submission with an **ed25519 device key** and sends the proof.
- The **verifier** checks signature, policy, challenge freshness, the proof and
  the `compliant` output — in that order — and issues a **10-minute token**.
- The token opens a **reverse-proxy gate** in front of a real app (a local
  folder served by `python -m http.server 8080` by default). The upstream is
  configuration only (`GATE_UPSTREAM`); no request can choose it.
- Every decision is written to a **hash-chained, append-only decision log**.
- A teal SOC-style **dashboard** shows compliance, decisions, policy, devices,
  log integrity and a CISA KEV advisory.

---

## Ports

| Port | Process | Binding |
|------|---------|---------|
| 3000 | Verifier + dashboard | `127.0.0.1` by default; `0.0.0.0` only when `DEMO_LAN=1` |
| 8081 | Gate (reverse proxy) | `127.0.0.1` by default; `0.0.0.0` only when `DEMO_LAN=1` |
| 8080 | Protected app (upstream) | Your app; the gate connects to it, browsers never do |
| 4000 | Agent local UI (optional) | `127.0.0.1` only, always |

TLS is on by default. The verifier creates a local CA and leaf certificate on
first run (`verifier/data/tls`, git-ignored); the agent pins the CA's public
key and refuses any other certificate. `DEMO_INSECURE=1` is the only way to
run plain HTTP.

---

## Environment variables

All are documented with placeholders in [.env.example](.env.example).

| Variable | Used by | Meaning |
|---|---|---|
| `ADMIN_PASSWORD` | verifier | Admin login. Required, minimum 12 characters. |
| `TOKEN_SIGNING_KEY` | verifier | Optional HMAC key. If absent, one is generated into `verifier/data/token-signing.key` (git-ignored, mode 600). |
| `ENROLL_CODE_TTL` | verifier | Enrollment-code lifetime in seconds (default 600). |
| `PORT` | verifier | Default 3000. |
| `GATE_UPSTREAM` | verifier | The real app the gate forwards to. Default `http://127.0.0.1:8080`. http/https, no credentials, no query. Read once at startup; never from a request. |
| `GATE_PORT` | verifier | Gate listener. Default 8081. |
| `GATE_PUBLIC_URL` | verifier | Optional gate origin used in printed links, e.g. `https://gate.corp.example`. |
| `GATE_TOKEN_TTL_SECONDS` | verifier | Gate token lifetime. Default 600 (10 minutes). |
| `SESSION_TTL_SECONDS` | verifier | Admin dashboard session. Default 28800 (8 hours). |
| `DEMO_LAN` | verifier | `1` binds `0.0.0.0`; anything else binds `127.0.0.1`. |
| `DEMO_INSECURE` | both | `1` disables TLS on both sides. The only way to run plain HTTP. |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | verifier | Optional existing cert/key instead of the generated local CA. Set both or neither. |
| `VERIFIER_URL` | agent | Base URL of the verifier (or set `verifierUrl` in `agent/agent.config.json`). Use `https://` with TLS. |
| `ZKPG_CA_FINGERPRINT` | agent | One-time CA pin (SPKI SHA-256). Colons/spaces accepted; can also live in `agent/agent.config.json` as `tlsCaFingerprint`. |
| `GATE_URL` | agent | Optional full gate origin, e.g. `https://gate.corp.example`. Default: verifier host on the port the verifier reports. |
| `AGENT_UI_PORT` | agent | Local UI port, default 4000. |
| `AGENT_DATA_DIR` | agent | Where the device key and state live (default `agent/data`). Point it at another folder to enroll a second identity on the same laptop. |

No secret is ever written into code, logs, chat or a committed file.

---

## Quick start: one laptop (single-laptop demo)

The demo runs on **one Windows laptop**: verifier on `127.0.0.1`, agent on the
same machine. The multi-device code is still there, but no LAN is needed.

```powershell
npm ci
npm run setup:circuit                    # once, needs CIRCOM_BIN
$env:ADMIN_PASSWORD = "choose-a-long-password"
npm run demo:single                      # verifier + dashboard on 127.0.0.1:3000
```

`demo:single` prints a one-time enrollment code and the exact next commands. It
also starts the gate on `127.0.0.1:8081` and forwards it to `GATE_UPSTREAM`
(default `http://127.0.0.1:8080`). Start the protected app in a second
PowerShell:

```powershell
cd internal-app
python -m http.server 8080
```

`demo:single` prints the **CA pin** and the dashboard URL (`https://`). Do this
once on the laptop:

```powershell
# Trust the demo CA for the current Windows user only (no admin):
.\scripts\trust-ca.ps1

# Copy the printed pin into agent/agent.config.json:
#   "tlsCaFingerprint": "AA:BB:..."      (the leaf can renew; the pin stays)
```

Then enroll and attest in a third PowerShell on the same laptop:

```powershell
node agent enroll --code <printed-code> --label "This laptop"
node agent attest --open                 # -> GRANTED + opens the gate URL
node agent attest --interval 1           # optional: repeat every minute for a rehearsal
```

`internal-app/` is a real static admin page, not a gate screen. It is served by
python and reached only through the proxy. Point `GATE_UPSTREAM` at an existing
intranet URL instead if you want to protect that.

Then follow [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md): raise the policy, deny,
restore, optionally turn the Public firewall profile off and back on, replay, and
tamper with the log.

A second identity on the same machine exercises the device list without a second
laptop (multi-device stays optional):

```powershell
$env:AGENT_DATA_DIR = "$PWD\agent\data-second"
node agent enroll --code <new-code> --label "same machine, 2nd identity"
node agent attest
```

---

## Quick start: several laptops (optional LAN mode)

```powershell
# 0. Node.js 20+ and npm are required
node -v
npm -v

# 1. Install the exact pinned dependencies (uses package-lock.json)
npm ci

# 2. Get the circom 2.x compiler (browser download from GitHub releases,
#    asset: circom-windows-amd64.exe), then:
$env:CIRCOM_BIN = "C:\tools\circom.exe"
npm run setup:circuit          # compile + trusted setup, writes circuits/build/

# 3. Start the verifier + dashboard
$env:ADMIN_PASSWORD = "choose-a-long-password"
$env:DEMO_LAN = "1"            # needed for the 3-laptop demo
node verifier/server.js
# or: .\scripts\start-verifier.ps1 -Lan
```

Open the dashboard at `https://<MAIN-PC-LAN-IP>:3000`, sign in, go to **Devices**
and generate an enrollment code. On each laptop, copy the CA pin printed by the
verifier and trust the CA once (see above).

On each laptop (copy `bundle/agent-bundle/` over by USB; see `npm run bundle`):

```powershell
npm ci                                        # or use the offline bundle
$env:VERIFIER_URL = "https://<MAIN-PC-IP>:3000"
$env:ZKPG_CA_FINGERPRINT = "<CA pin printed by the verifier>"
node agent enroll --code ABCD-EFGH --label "Laptop A"
node agent check
node agent attest --open
```

`attest` prints the 6-step flow and ends in `GRANTED` (with a gate URL) or
`DENIED` with a plain-language reason. Add `--open` to launch the gate URL in
the default browser, or `--interval` to repeat every 5 minutes (`--interval 1`
is allowed for rehearsals). Every attempt is logged on purpose; the Devices page
shows the record count per device.

---

## Commands

| Command | What it does |
|---|---|
| `npm run setup:circuit` | Compile the circuit and run powers-of-tau + Groth16 phase 1 and 2. |
| `npm run verifier` | Start the verifier + dashboard. |
| `node agent/index.js enroll --code CODE` | Create the ed25519 key and register the public key. |
| `node agent/index.js check` | Verifier reachability + policy version. Sends no posture. |
| `node agent/index.js attest [--open] [--interval [minutes]]` | Read posture, prove locally, submit, print the decision; `--open` launches the gate URL; `--interval` repeats (default 5 min). |
| `npm run tls:info` | Show the CA pin, leaf fingerprint, SANs and cert paths; creates the local CA on first run. |
| `npm run tls:leaf` | Regenerate only the leaf (new IP/hostname), keeping the CA pin agents already have. |
| `.\scripts\trust-ca.ps1 [-Remove]` | Trust/remove the demo CA for the current Windows user. |
| `npm run agent:ui` | Local-only UI on `127.0.0.1:4000`. |
| `npm test` | 57 automated tests (circuit, six gate checks, reverse proxy, TLS pinning, log, privacy). |
| `npm run demo` | Full in-process end-to-end demo. Windows only: it reads real posture and refuses to invent values. |
| `npm run demo:single` | Single-laptop demo: verifier + dashboard bound to `127.0.0.1`, prints an enrollment code and the next agent commands. |
| `npm run demo:replay` | One real attestation submitted twice → `GRANTED` then `DENIED (REPLAY)`. Windows only. |
| `.\scripts\demo-policy.ps1 set-current\|raise\|reset` | Set the policy to this laptop's real values, above them, or back to pre-demo. |
| `.\scripts\demo-firewall.ps1 off-public\|restore` | Elevated: disable the Public firewall profile for one denial, then restore the recorded state. |
| `node scripts/measure.js 10` | Proof/verify timings, sizes, constraint count, with the working shown. |
| `npm run bundle` | Build the USB agent bundle (wasm + zkey + pinned package.json). |

---

## Folder structure

```
agent/        the laptop side: posture reader, prover, signature, CLI, local UI
circuits/     posture.circom + build.sh (compile, trusted setup, verification key)
verifier/     Express service: policy, challenge, gate, tokens, log, advisory
dashboard/    plain HTML/CSS/JS SOC dashboard + gate 401 page (teal theme)
internal-app/ the real local admin app the gate protects (static, port 8080)
shared/       canonical JSON + signed-message format (used by BOTH sides)
scripts/      PowerShell firewall scripts, demo, measurements, USB bundle
tests/        node:test suites (real proofs, real HTTP, no mocks)
docs/         setup, architecture, design, measurements, threat table, Q&A, demo
tools/bin/    downloaded circom binary (git-ignored)
```

---

## Documentation

| Document | Contents |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | Toolchain install, every circuit command and its real output, KEV field inspection. |
| [docs/VERSIONS.md](docs/VERSIONS.md) | Pinned versions and why. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | ASCII + Mermaid diagrams, data-flow table, signal order, log canonical form. |
| [docs/DESIGN.md](docs/DESIGN.md) | Theme tokens, measured contrast ratios, states, accessibility. |
| [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md) | N=10 timings with the arithmetic shown, sizes, constraints. |
| [docs/THREAT_TABLE.md](docs/THREAT_TABLE.md) | Attack → what stops it → what does not yet. |
| [docs/PANEL_QA.md](docs/PANEL_QA.md) | 15 likely review questions with honest answers. |
| [docs/PRESENTER_GUIDE.md](docs/PRESENTER_GUIDE.md) | Beginner runbook: plain-language explanation, exact commands, what to click, panel Q&A. |
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | 5-minute demo script, backup recording plan, pre-demo checklist. |
| [docs/MANUAL_CHECKLIST.md](docs/MANUAL_CHECKLIST.md) | The 11 manual tests that need real Windows machines. |
| [docs/PHASES.md](docs/PHASES.md) | Phase reports P0–P9 with the commands and numbers used. |

Built against the capstone brief `PROJECT_RULES.md`; `docs/PHASES.md` records how
each phase's "done when" test was met (or marked UNVERIFIED).

---

## Honest limits

- **No hardware attestation.** Without a TPM-backed measurement, a modified
  agent could lie about its own values. The proof is honest about arithmetic,
  not about the machine.
- **Trusted setup is per-circuit and run by us.** It is a phase-1 and phase-2
  contribution, not a multi-party ceremony.
- **No formal security audit.**
- **TLS is on by default**, with a self-signed local CA generated into
  `verifier/data/tls` and CA public-key pinning in the agent. `DEMO_INSECURE=1`
  is the only way to run plain HTTP. The token lives for 10 minutes, so every
  log line of an attestation is intentional; the Devices page prints a record
  count per device.
- **The proxy is the gate only while the upstream is not reachable directly.**
  Bind the protected app to `127.0.0.1` (as the python example does) or block
  its port in the firewall; otherwise anyone who can reach port 8080 skips the
  gate entirely.
- **Access outlives a bad check-in by up to one token lifetime.** The gate
  checks the token, not the laptop's current posture. If a laptop becomes
  non-compliant after a successful attestation, it keeps access until its
  token expires (10 minutes by default). Tune `GATE_TOKEN_TTL_SECONDS` down to
  shorten that window.
- **The hash chain is tamper-evident, not tamper-proof** without an external
  anchor.
- **The KEV advisory is not mapped to builds.** It is a prompt to review policy.
- **Status in this build:** circuit, trusted setup, gate, real reverse proxy,
  log, dashboard, advisory and the 57 automated tests were run on Linux
  (Node 26.13.0). An
  earlier demo run used a synthetic posture input that has since been removed,
  so `npm run demo`, `npm run demo:replay` and `node scripts/measure.js` now
  require real Windows posture. **The Windows posture reader, the Windows demo
  helpers and the three-laptop LAN demo are UNVERIFIED** — they need real
  Windows/Administrator sessions, see `docs/MANUAL_CHECKLIST.md`.
