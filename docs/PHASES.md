# Phase reports

The brief asks for one phase per reply and then "next". The request for this
build was "build entire thing", so all phases were implemented in one pass. Each
phase still gets its report in the required shape: files, commands, the real
"done when" output, a 3-sentence explanation for the panel, and 3 understanding
questions.

---

## P0 — Summary, structure, ports, env, plan

**Files:** `README.md`, `.env.example`, `.gitignore`, `docs/ARCHITECTURE.md`.

**Commands:** none.

**Done when:** the structure and ports are documented.

Ports 3000 (verifier + dashboard, `127.0.0.1` unless `DEMO_LAN=1`) and 4000
(agent UI, `127.0.0.1` only). Env vars: `ADMIN_PASSWORD`, `TOKEN_SIGNING_KEY`,
`ENROLL_CODE_TTL`, `DEMO_LAN`, `VERIFIER_URL`, `PORT`, `AGENT_UI_PORT`.

**Explain it:** "We split the system at the network boundary: the laptop holds
everything sensitive, the main PC holds only the policy, the gate and the log."
"Ports 3000 and 4000 are the only listeners, and 4000 can never leave the laptop."
"Every secret comes from the environment; the only generated file is the token key,
which is git-ignored."

**Check yourself:** (1) Which port is bound to `0.0.0.0` and when? (2) Which
environment variable must exist before the verifier will start? (3) Where is the
token signing key stored if the env var is absent?

---

## P1 — Agent reads real data

**Files:** `agent/lib/posture.ps1`, `agent/lib/posture.js`,
`agent/lib/keys.js`, `agent/lib/state.js`.

**Commands (Windows):**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File agent\lib\posture.ps1
```

**Done when:** it prints one JSON object with real values. **UNVERIFIED here** —
this build machine is Linux, so the agent refuses to invent values:

```
Posture can only be read on Windows. This build refuses to invent posture values.
```

That refusal is the designed behaviour (and is why the demo script labels its
fixture loudly).

**Explain it:** "One fixed PowerShell script reads registry, update history,
firewall and Defender; Node never builds a command string, so there is no
injection surface." "The build is encoded as build × 100000 + UBR, which is
reversible and fits in 40 bits." "Update age uses Windows Update COM history
because it records when updates were *installed*, with Get-HotFix as fallback."

**Check yourself:** (1) Why must UBR stay below 100000? (2) What does
`updateSource` become when the COM history is empty? (3) Where do the posture
values go after Node reads them?

---

## P2 — Circuit and trusted setup

**Files:** `circuits/posture.circom`, `circuits/build.sh`,
`verifier/lib/public-signals.js`, artifacts in `circuits/build/`.

**Commands:** `npm run setup:circuit`.

**Done when:** the setup finishes and the key matches the circuit. Real output:

```
non-linear constraints: 125
public inputs: 5
private inputs: 4
public outputs: 2
[INFO]  snarkJS: ZKey Ok!
```

And the public-signal order, read from `public.json` (not assumed):

```json
["1","152415787532388367501905199875019052100","2200000000","30","1","1","12345678901234567890"]
```

**Explain it:** "Every 0/1 input is constrained to really be 0 or 1, and the
numbers are range-checked before comparison, otherwise the comparators are
unsound." "The four checks are AND-ed pairwise so every constraint stays
quadratic." "The challenge is squared into a public output, so the verifier can
see it is bound to this request."

**Check yourself:** (1) Why does a 40-bit comparator need a `Num2Bits(40)` on its
inputs? (2) What happens to a proof if `challengeSq` is changed? (3) Is our
trusted setup a ceremony?

---

## P3 — Prover inside the agent

**Files:** `agent/lib/prover.js`, `agent/lib/client.js`, `agent/index.js`.

**Commands:** `node agent attest` (Windows), or `npm run demo` here.

**Done when:** a proof is generated locally and nothing is printed but the
decision. Real output from the demo run (that run used a synthetic posture input,
which has since been removed from the script — it now requires Windows):

```
[6/8] Proof generated....... done in 0.4 s
[7/8] Attestation........... GRANTED
```

**Explain it:** "The prover takes the private posture and the verifier's public
policy, and returns only `proof` plus `publicSignals`; the input object is never
returned, logged or stored." "Signing covers the challenge, the device id and
digests of both the proof and the signals, so a middlebox cannot reorder
anything." "snarkjs leaves handles open, so the CLI exits explicitly."

**Check yourself:** (1) Which fields does the signed message cover? (2) Where
does the private key live? (3) What does the agent print when denied?

---

## P4 — Verifier: policy, challenge, token, signatures, enrollment

**Files:** `verifier/server.js`, `verifier/lib/{config,policy,challenges,tokens,session,devices,validate,ratelimit,verify-proof}.js`.

**Commands:** `npm test` → 57 passing; `npm run demo`.

**Done when:** each of the six checks can be triggered independently. Real test
names that prove it (the companion demo run used a synthetic posture input,
since removed; the demo now requires Windows):

```
✔ compliant laptop: GRANTED, gate accepts the token and 401 without it
✔ replaying the same proof is refused with REPLAY
✔ challenge expires after 60 seconds of verifier time
✔ bad device signature is BAD_SIGNATURE
✔ off-curve proof point is PROOF_INVALID
✔ a real proof of a non-compliant laptop is NON_COMPLIANT
```

**Explain it:** "The checks run in a fixed order and stop at the first failure, so
a denial always names the earliest broken assumption." "The policy belongs to the
verifier and every change bumps the version, so a prover cannot choose its own
bar." "Challenges are single use and consumed at check 4, which makes replay
impossible instead of merely unlikely."

**Check yourself:** (1) Why is the challenge consumed before the proof is checked?
(2) Why does an unknown device also return `BAD_SIGNATURE`? (3) Where does the
CSRF token live?

---

## P5 — Decision log

**Files:** `verifier/lib/log.js`, `verifier/lib/store.js`, routes in `verifier/server.js`.

**Commands:** `node --test tests/log.test.js`.

**Done when:** the chain verifies, persists, and reports the first broken record.
Real output:

```
✔ chain links records and verifies as intact
✔ editing one record reports that record as broken
✔ deleting a record breaks the id sequence at that position
✔ history persists across a restart and new records continue the chain
```

**Explain it:** "Each record hashes the previous hash plus its own fields, so an
edit breaks every later record." "Verify recomputes from disk and reports the
first position with a bad id, prevHash or hash." "It is tamper-evident, not
tamper-proof: a consistent full rewrite needs an external anchor to catch."

**Check yourself:** (1) What is `prevHash` for record 1? (2) Which canonicalisation
is hashed? (3) What exactly does `/api/log/verify` return for a broken chain?

---

## P6 — Vault and dashboard (teal)

**Files:** `dashboard/{index.html,app.js,theme.css,vault.html,vault-denied.html}`,
`agent/{local-ui.js,ui.html,ui.js}`.

**Commands:** `npm run verifier`, open `https://127.0.0.1:3000`.

**Done when:** the dashboard renders every screen with the six cards, denial chart,
decisions, policy form, devices (with per-device record count), log integrity and
advisory. Measured contrast: `--text`/`--bg` 15.85:1, `--muted`/`--panel` 6.80:1,
`--bad`/`--panel` 5.48:1 — all text pairs clear 4.5:1.

**Explain it:** "Everything visible on the dashboard is a real decision from the
log; there is no simulated or sample data in the product path." "Status always
has a glyph and words, because teal and green are too close to trust by hue
alone." "The privacy claim is on the first screen: posture values stored is zero,
and the detail panel shows what the server did not receive."

**Check yourself:** (1) Why is there no simulated data in the dashboard?
(2) Where are theme tokens defined? (3) Why is `--ok` a different green from
`--accent`?

---

## P7 — KEV advisory

**Files:** `verifier/lib/kev.js`, Advisory view in `dashboard/app.js`.

**Commands:** `curl` the feed (in SETUP.md), then dashboard → Advisory.

**Done when:** the panel shows Microsoft entries added since the policy changed,
with a "last fetched" time and an "advisory only" banner. Field names were
confirmed against the live feed: top level `catalogVersion/dateReleased/count/
vulnerabilities`, entry `cveID/vendorProject/product/vulnerabilityName/dateAdded/
dueDate/knownRansomwareCampaignUse`.

**Explain it:** "The feed is cached to disk so the panel works offline and says
when it is stale." "Only Microsoft entries added since the policy's last change
are shown, so the list stays short and actionable." "It never maps a CVE to a
build and never edits the policy; it recommends a review."

**Check yourself:** (1) What date drives the filter? (2) What does the panel show
when offline with a cache? (3) What does the ransomware column read from?

---

## P8 — Tests, multi-device mode, measurements

**Files:** `scripts/setup-firewall-rule.ps1`, `scripts/remove-firewall-rule.ps1`,
`scripts/build-agent-bundle.js`, `tests/*`, `scripts/measure.js`.

**Commands:** `npm test`, `node scripts/measure.js 10`, `npm run bundle`.

**Done when:** the suite passes and measurements are recorded. Real output on
Node 26.13.0 (57 tests, 11.997 s):

```
ℹ tests 57
ℹ suites 0
ℹ pass 57
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 11997.178026
proof generation: mean 67.0 ms warm (≈94 ms cold included)
verification: mean ~20 ms
proof.json: 723 bytes
```

**Explain it:** "The verifier binds to `0.0.0.0` only with `DEMO_LAN=1`, and the
firewall rule is Private-profile only and removable." "The USB bundle carries the
wasm and zkey so laptops never need the circom compiler." "Three laptops each
enroll with their own code, so the dashboard shows three distinct ids."

**Check yourself:** (1) Why does nothing call `process.exit()` any more? (2) Why is the first proof slower?
(3) What three things are in the USB bundle?

**UNVERIFIED:** three physical Windows laptops on one network.

---

## P9 — README, diagrams, threat table, demo script, manual checklist

**Files:** `README.md`, `docs/{ARCHITECTURE,DESIGN,SETUP,VERSIONS,MEASUREMENTS,THREAT_TABLE,PANEL_QA,DEMO_SCRIPT,MANUAL_CHECKLIST}.md`.

**Commands:** none; read them.

**Done when:** a person who has never seen the project can install, run, test and
demo it from the README, and the limits are stated where they cannot be missed.

**Explain it:** "The README leads with the claim, the ports and the honest limits,
so nobody is surprised later." "The architecture doc has both a hand-redrawable
ASCII diagram and a Mermaid one, plus a table of every field that crosses the
network." "The panel Q&A answers the questions we would ask if we were the
reviewers."

**Check yourself:** (1) Which limit would you fix first? (2) What does the data-flow
table prove? (3) Which test would you add next?

R3 appended TLS + CA pinning + interval + audit-record note across those docs and
added `npm run tls:info`, `npm run tls:leaf`, `.\scripts\trust-ca.ps1`,
`agent/agent.config.json`, and the Devices record-count. Live TLS was verified on
Linux: agent accepts the pinned CA, refuses a wrong pin and a missing pin; the
HTTPS gate returns 401, 302+`zkpg_gate` cookie, and proxies the protected app; plain
HTTP to the HTTPS port is refused.
