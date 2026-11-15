# Presenter guide (no prior knowledge needed)

This is the runbook for demonstrating ZK Posture Gate to a panel. It assumes you
have never used the project before. Every command is copy-paste, and every step
says what you should see and what to say.

Three terminals and one browser tab are open the whole time:

| Window | What it is |
|---|---|
| **T1** | PowerShell, project folder — runs the verifier (the server), the gate and the demo timer |
| **T2** | PowerShell, project folder — runs the agent (the "laptop") |
| **T3** | PowerShell, `internal-app` folder — serves the protected app on 8080 |
| **B**  | Browser — the dashboard at `https://127.0.0.1:3000` |

---

## 0. The 30-second explanation (say this first, no screen)

> "Our patching policy says every laptop must be on a recent Windows build, have
> recent updates, and have the firewall and Defender on. Today, checking that
> means collecting every laptop's exact build and settings into one database —
> which is also a map of which machines an attacker should target.
>
> This tool answers one question — *does this laptop meet the policy?* — without
> collecting anything. The laptop proves the answer mathematically and sends
> only `yes` or `no`. The server never sees the build number, the update age, or
> the firewall state."

If they want the analogy:

> "It's a bouncer who can check you are over 21 without ever seeing your date of
> birth."

And the honest boundary, say it early so it does not look like an omission:

> "The arithmetic is real, but the machine is trusted: without a TPM a modified
> agent could lie about its own values. That is the next step, not something this
> demo hides."

---

## 1. Setup (do this before the panel arrives)

Open **T1**: press `Win + X` → **Terminal** (or **Windows PowerShell**).

```powershell
cd C:\path\to\zk-posture-gate
node -v
npm ci
```

`node -v` must print `v20` or higher. `npm ci` takes a minute the first time.

Build the circuit once (skip if `circuits\build\posture_final.zkey` already
exists — check with `Test-Path circuits\build\posture_final.zkey`):

```powershell
$env:CIRCOM_BIN = "C:\tools\circom.exe"   # circom-windows-amd64.exe from GitHub releases
npm run setup:circuit
```

Set the admin password for this session (12+ characters, never written to a file):

```powershell
$env:ADMIN_PASSWORD = "pick-a-long-demo-password"
```

Allow the demo scripts to run in this window only (PowerShell blocks `.ps1` files
by default):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Trust the demo CA for the current user **before opening the dashboard** (no admin;
run once; to remove later, `.\scripts\trust-ca.ps1 -Remove`):

```powershell
.\scripts\trust-ca.ps1
```

Copy the CA pin into `agent\agent.config.json`:

```powershell
notepad agent\agent.config.json
```

Add: `"tlsCaFingerprint": "AA:BB:..."` (replace with the pin `demo:single` prints
at startup, or set `$env:ZKPG_CA_FINGERPRINT` in T2). The agent refuses TLS until
it has a pin; `DEMO_INSECURE=1` is the only bypass.

Check the machine is healthy enough to be granted:

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled
```

Both should show `True`. If the firewall or Defender is off, the first
attestation will be `DENIED` — that is still a valid demo, just say so.

Start the protected app in **T3** (a second PowerShell):

```powershell
cd C:\path\to\zk-posture-gate\internal-app
python -m http.server 8080
```

Leave it running. This is the real app the gate protects: a plain static page
served by python, not a gate screen. The gate proxies to `http://127.0.0.1:8080`
by default. `http.server` binds `127.0.0.1` only, so the app is not reachable
from the LAN — without that, anyone could skip the gate by opening port 8080
directly.

---

## 2. Start the server (T1) — 20 seconds

```powershell
npm run demo:single
```

Expected (exact lines, `X-X-X` is the printed CA pin):

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
  CA pin:              X-X-X
  first run on Windows: .\scripts\trust-ca.ps1   (CurrentUser, no admin)

  Start the protected app first (second terminal):
    cd internal-app
    python -m http.server 8080

  one-time enrollment code: XXXX-YYYY   (expires 7:15:54 PM)

  In a SECOND terminal on this same laptop:

    node agent enroll --code XXXX-YYYY --label "This laptop"
    node agent attest --open
```

**Leave this window running.** It is the server. Closing it stops the demo.
(The script counts the python window as the "second terminal", so its printed
"SECOND terminal" instructions are your **T2**.)

Say: "The server is bound to `127.0.0.1`, so it is not reachable from the
network. The code printed is single-use and expires in ten minutes."

Now open **B** at `https://127.0.0.1:3000`, sign in with the password from step 1.

Point at the two cards on **Overview**:

- **Posture values stored: 0**
- **What the server never saw** — build, update age, firewall, Defender, each
  tagged `never leaves the device`
- **Devices → Records** — a per-device count of every attempt, granted and denied, with the exact numbers in the title.

Say: "This is everything the server will ever know. There is no field for a
build number anywhere in its files."

---

## 3. Enroll and attest (T2) — 60 seconds

Open a **third** PowerShell (same `cd`), then:

```powershell
node agent enroll --code XXXX-YYYY --label "This laptop"
node agent attest
```

Replace `XXXX-YYYY` with the code T1 printed.

Expected:

```
  Device id: dev_...
  Enrolled. This laptop is registered with the verifier.

[1/6] Checking verifier ........ OK (policy v1)
[2/6] Reading posture .......... done (values stay on this device)
[3/6] Fetching challenge ....... OK
[4/6] Generating proof ......... done (0.1 s)
[5/6] Signing submission ....... done
[6/6] Sending attestation ...... GRANTED
  Access granted for policy v1.
  Gate URL (valid 10 min):
  https://127.0.0.1:8081/?t=...
  Tip: add --open to attest to launch it in your browser.
```

Narrate the steps as they appear: "It read the real values, turned them into a
mathematical proof locally, signed it with a key that never leaves this laptop,
and sent the proof."

The dashboard **Overview** updates within 2 seconds: a green `✔ GRANTED` row with
a hash prefix. Click **View** on that row. The split panel is the money shot:

- left: what the server received (proof, public signals, device id)
- right: what stayed on the laptop (build, update age, firewall, Defender)

Say: "The server checked the proof. It never saw the inputs."

### Open the gated app

Copy the gate URL from T2 into the browser (or use `--open`). The gate checks
the token, sets a cookie and proxies to the real `internal-app/` page. Then open
`https://127.0.0.1:8081/` in a new tab → **"No valid attestation."**

Say: "The token in the URL is the only thing that opens the app, and it dies in
ten minutes. The gate is a reverse proxy, not a mock page."

---

## 4. Show the policy saying no (T2) — 40 seconds

T1 is busy running the server, so type this in **T2** (policy command) and then
attest again in **T2** — they are separate commands, so that is fine.

```powershell
.\scripts\demo-policy.ps1 raise
```

It reads the real values through `agent\lib\posture.ps1`, prints them **in that
console** (do not stream that window), saves the old policy, and raises the bar
one build above this laptop.

Now attest again in the same window:

```powershell
node agent attest
```

Expected:

```
[6/6] Sending attestation ...... DENIED (NON_COMPLIANT)
  Reason: Device does not meet policy
```

Say: "Same laptop, same proof system, higher bar. And notice the denial does not
say *which* value failed — if it did, the error message would leak posture."

Then show the boundary case:

```powershell
.\scripts\demo-policy.ps1 set-current
node agent attest
```

Expected: `GRANTED`. Say: "Exactly at the minimum still passes, because the
circuit enforces the full range check, not a spot check."

> If `.\scripts\...ps1` is blocked, run it as
> `powershell -ExecutionPolicy Bypass -File .\scripts\demo-policy.ps1 raise`.

---

## 5. Replay (T2) — 30 seconds

```powershell
npm run demo:replay
```

Expected:

```
  first submission ............... GRANTED
  identical resubmission ......... DENIED (REPLAY)
```

Say: "That was a genuine proof. It was refused the second time because the
challenge is single-use — so a recording of the submission is worthless."

---

## 6. The log (B) — 40 seconds

Dashboard → **Log Integrity** → **Verify now** → `✔ Chain intact` with a record
count and the latest hash.

Back up the log first so you can undo the tamper:

```powershell
Copy-Item verifier\data\decisions.jsonl verifier\data\decisions.backup
notepad verifier\data\decisions.jsonl
```

In Notepad, change one `"result":"GRANTED"` to something else (add a letter),
save, close. Click **Verify now** again → `✖ Broken at record N`.

Restore and prove it goes back to intact:

```powershell
Move-Item verifier\data\decisions.backup verifier\data\decisions.jsonl -Force
```

**Verify now** → `✔ Chain intact`.

Say: "Tamper-evident, not tamper-proof. Without an external anchor, someone who
rewrites every record and every hash could hide it. That is a documented limit."

---

## 7. Optional: firewall denial (needs Administrator) — 30 seconds

Only if you have time and an elevated window. Open **Terminal (Admin)**, `cd` to
the project, then:

```powershell
.\scripts\demo-firewall.ps1 off-public
node agent attest        # in T2 -> DENIED (NON_COMPLIANT)
.\scripts\demo-firewall.ps1 restore
```

`off-public` records the Public profile's previous state and restores it
automatically if the change fails; `restore` puts it back from the saved state
and deletes the state file. Do not skip the restore — it is your machine.

---

## 8. Close (30 seconds)

```powershell
.\scripts\demo-policy.ps1 reset     # back to the pre-demo policy
```

Then press `Ctrl + C` in T1 to stop the server and the gate, and in T3 to stop
the protected app.

Say: "What this proves: a laptop can prove compliance without handing over an
inventory. What it does not prove: that the laptop is not lying about itself —
that needs TPM-backed attestation, which is the next phase."

Optionally show **Advisory**: CISA's Known Exploited Vulnerabilities list,
filtered to Microsoft, with a "Review policy" prompt. Say: "This is a nudge to
revisit the bar, not an automatic change — policy stays a human decision."

---

## 9. Panel questions and short answers

**"How can the server check without seeing the values?"**
The circuit is a small arithmetic program: `build >= minBuild`, `age <= maxAge`,
`firewall == 1`, `defender == 1`. The proof shows those comparisons are true for
hidden inputs. The server only receives the public policy numbers, a `compliant`
bit, and the proof.

**"What exactly does the server store?"**
Device id, public key, decision, reason code, policy version, timestamps, a hash
of the proof material, and the log hash chain. No build, no age, no firewall or
Defender state — the privacy test greps every verifier file to confirm it.

**"Couldn't a hacked agent just say it's compliant?"**
Yes. The proof is honest about arithmetic, not about the machine. Only something
like TPM-backed measurement fixes that, and we say so in the limits.

**"What stops someone reusing a proof?"**
The challenge: the verifier issues a random value, the proof is bound to it, and
the challenge is spent on first use and expires in 60 seconds. That is the
`REPLAY` demo.

**"Why zero knowledge instead of just an allow-list?"**
An allow-list or a build inventory is exactly the target map. This reveals only
pass/fail.

**"How fast is it?"**
Proof about 67 ms warm (≈94 ms including a cold start), verification about 20 ms,
proof size about 0.7 KB. Small enough to run on every check-in.

**"What if the laptop is offline?"**
It cannot attest. Offline devices show as stale, not compliant.

**"Is the log trustworthy?"**
It is a hash chain: each record hashes the previous one, so an edit breaks
verification at that record. It is tamper-evident, not tamper-proof, without an
external anchor.

**"What about the trusted setup?"**
It is a per-circuit phase-1/phase-2 contribution, not a multi-party ceremony. A
production deployment should run a real ceremony.

**"Isn't this just Intune/MDM?"**
No: MDM collects configuration centrally. This is a gate that collects nothing.
It could sit in front of an MDM-protected resource.

**"What did you not finish?"**
Windows posture reading, the demo helpers and the multi-device LAN flow need a
real Windows machine to verify; everything else is exercised by 57 automated
tests. Say this plainly if you did not run them.

Words to avoid: "unhackable", "blockchain", "military-grade", "TPM-backed" (we do
not have it), "anonymous" (the device is pseudonymous and enrolled).

---

## 10. If something breaks

| Symptom | Fix |
|---|---|
| `Port 3000 is already in use` | Another verifier is running. Close it, or `$env:PORT = "3100"` and use `https://127.0.0.1:3110`. |
| `cannot reach verifier` | T1 is not running, or the password was missing so it exited. Restart `npm run demo:single`. 
| `TLS refused: the CA fingerprint does not match` | The pin in `agent\agent.config.json` or `$env:ZKPG_CA_FINGERPRINT` is wrong. Copy the CA pin printed by `demo:single` (or `npm run tls:info`) exactly. A leaf regen keeps the pin. |
| `TLS is enabled but no valid CA fingerprint is configured` | Set `tlsCaFingerprint` in `agent\agent.config.json` or `$env:ZKPG_CA_FINGERPRINT`. |
| `Demo CA not trusted by browser` | Run `.\scripts\trust-ca.ps1 -Remove` then `.\scripts\trust-ca.ps1` once per user, and restart the browser. On Linux/macOS the browser warns — click through for the demo. |
| `Posture can only be read on Windows` | You are not on Windows. The demo needs the real machine. |
| `not enrolled` | Run `node agent enroll --code <new code>`; generate a code on **Devices**. |
| Enrollment code expired | **Devices** → **Generate enrollment code**, use the new one. |
| First attestation is `DENIED` | Check the firewall/Defender commands in step 1; or use it as the denial demo. |
| Policy script refused | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then retry. |
| Dashboard shows nothing after attest | Refresh once; polling is every 2 s. Check the browser is on `127.0.0.1:3000`, not `localhost` with a dead port. |
| Gate shows a 502 page | T3 is not running, or `GATE_UPSTREAM` does not match it. Start `python -m http.server 8080` in `internal-app`, then retry. |
| `Port 8081 is already in use` | Another gate is running. Close it, or set `$env:GATE_PORT = "8091"` before starting T1; the agent is told the port automatically. |
| Gate shows 401 after a successful attestation | The token was already used from another tab, or more than 10 minutes passed. Attest again. |

You never need to invent values: the agent refuses rather than guessing. If a
step cannot run, say which step and why — a missing Windows check is a known
limit, not a failure to hide.

---

## 11. One-page command cheat sheet

```powershell
# setup, once
cd C:\path\to\zk-posture-gate
npm ci
$env:ADMIN_PASSWORD = "pick-a-long-demo-password"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# T3: protected app (leave running)
cd internal-app
python -m http.server 8080

# T1: server + gate (leave running)
npm run demo:single# T2: the laptop (agent\agent.config.json already has tlsCaFingerprint, or set $env:ZKPG_CA_FINGERPRINT)
node agent enroll --code XXXX-YYYY --label "This laptop"
node agent attest --open                            # GRANTED + opens gate URL

# T2: policy says no, then exactly at the line
.\scripts\demo-policy.ps1 raise
node agent attest                                   # DENIED (NON_COMPLIANT)
.\scripts\demo-policy.ps1 set-current
node agent attest                                   # GRANTED

# T2: replay
npm run demo:replay                                 # GRANTED, then REPLAY

# T2: repeat check-in (default 5 minutes; --interval 1 for a rehearsal)
node agent attest --interval                        # keep the gate URL alive

# Browser: Log Integrity -> Verify now
Copy-Item verifier\data\decisions.jsonl verifier\data\decisions.backup
notepad verifier\data\decisions.jsonl               # edit one "result", save
# Verify now -> broken at record N


Move-Item verifier\data\decisions.backup verifier\data\decisions.jsonl -Force
# Verify now -> intact

# cleanup
.\scripts\demo-policy.ps1 reset
# Ctrl+C in T1
```

**Verified in this repository:** `npm run demo:single` starts and binds
`127.0.0.1` only, `AGENT_DATA_DIR` creates a second identity, `npm test` passes
51/51. **UNVERIFIED until you run them on Windows:** every GRANTED/DENIED
attestation, `demo-policy.ps1`, `demo-firewall.ps1` and `demo:replay` beyond
their refusal path. Do the whole run once, alone, the day before.
