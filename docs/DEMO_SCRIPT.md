# 5-minute demo script (one laptop)

Everything runs on **one Windows laptop**: the verifier on `127.0.0.1`, the agent
on the same machine. The multi-device code still exists (LAN mode, three
laptops), but it is optional — see the appendix at the end.

The demo shows, in order: **grant → raise the policy → deny → boundary grant →
optional firewall denial → replay → log tamper → limits.**

## Before anyone walks in

- [ ] `npm ci` has been run and `circuits/build/` exists (`npm run setup:circuit`).
- [ ] `$env:ADMIN_PASSWORD` is set in the terminal you will use (12+ characters).
      Do not put it in a file.
- [ ] Port 3000 is free. `npm run demo:single` refuses with a clear message if a
      verifier is already running; stop it or set `$env:PORT`.
- [ ] The laptop's firewall and Defender are healthy (so the first attestation
      can be GRANTED). Check: `Get-NetFirewallProfile | Select Name, Enabled`.
- [ ] Two PowerShell windows open, both in the project folder, font ≥ 16px.
- [ ] **Trust the demo CA once per user, before opening the dashboard:**
      `.\scripts\trust-ca.ps1`. On first run `demo:single` generates a local CA
      and prints the CA pin; copy that pin into `agent/agent.config.json` as
      `tlsCaFingerprint`, or set `$env:ZKPG_CA_FINGERPRINT`. The agent refuses TLS
      until it has a pin — `DEMO_INSECURE=1` is the only bypass.
- [ ] Optional backup: a screen recording of the run (scenes at the end).
- [ ] If you will show posture numbers on screen, know that the policy helper
      prints them to **this console only**. Do not stream or record that window.

## 0:00–0:20 — the problem (no screen yet)

"Checking our patching policy today means collecting every laptop's exact build
and security settings. That inventory is a map of exactly which machines an
attacker should target. We built a gate that answers yes/no without collecting
anything."

## 0:20–0:50 — start the verifier and sign in (terminal 1)

```powershell
$env:ADMIN_PASSWORD = "your-demo-password-here"
npm run demo:single
```

It prints:

```
  ZK Posture Gate - SINGLE LAPTOP DEMO
  verifier + dashboard: https://127.0.0.1:3000
  gate:                 https://127.0.0.1:8081
  gate forwards to:     http://127.0.0.1:8080/
  binding: 127.0.0.1 (this machine only, never the LAN)
  TLS:                 local CA (data/tls), leaf E9:12:D9:70:3A:04:F8:B6...
  CA pin:              00:4F:1E:94:0A:4B:10:48:CE:5D:1E:D1:7B:65:85:F4:25:D0:A7:A1:0A:17:07:82:01:57:63:E3:11:F2:13:CA
  first run on Windows: .\scripts\trust-ca.ps1   (CurrentUser, no admin)
  one-time enrollment code: XXXX-YYYY   (expires 12:34:56)
```

Open `https://127.0.0.1:3000` (**https**, not http), sign in with
`$env:ADMIN_PASSWORD`, and point at:

- **Posture values stored: 0**
- **What the server never saw** — build, update age, firewall, Defender, each
  tagged `never leaves the device`.
- **Devices → Records** — a per-device count of every attest attempt, granted
  and denied, exact numbers in the title.

Say: "There is no field for a build number anywhere in its data files."

## 0:50–1:50 — enroll and attest (terminal 2)

```powershell
node agent enroll --code XXXX-YYYY --label "This laptop"
node agent attest --open
```

Expected, exactly:

```
[1/6] Checking verifier ........ OK (policy v1)
[2/6] Reading posture .......... done (values stay on this device)
[3/6] Fetching challenge ....... OK
[4/6] Generating proof ......... done (0.1 s)
[5/6] Signing submission ....... done
[6/6] Sending attestation ...... GRANTED
  Gate URL (valid 10 min):
  https://127.0.0.1:8081/?t=...
  Opened in your browser.
```

`--open` launches the gate URL. The browser lands on the real `internal-app`
page (served by `python -m http.server 8080` and proxied by the gate), not on a
fake screen. Then open `https://127.0.0.1:8081/` in a fresh window → **401**.
Say: "The token is the only thing that opens the app, and it lives for ten
minutes."

On the dashboard, Overview updates within 2 s: a green `✔ GRANTED` row with the
hash prefix and the device id. Click **View** to show the split panel: what the
server saw vs what stayed on the laptop.

## 1:50–2:30 — raise the policy, deny the same laptop (terminal 1)

```powershell
.\scripts\demo-policy.ps1 raise
```

It reads this laptop's real values through `agent\lib\posture.ps1`, prints them to
this console only, then sets `minBuild` one build increment above reality. Now,
in terminal 2:

```
[6/6] Sending attestation ...... DENIED (NON_COMPLIANT)
  Reason: Device does not meet policy
```

Say: "Same laptop, same proof system, different bar. And the denial does not say
which value failed — if it did, the error message would leak posture."

## 2:30–3:00 — the boundary case (terminal 1)

```powershell
.\scripts\demo-policy.ps1 set-current
```

Policy is now set to **exactly** this machine's values (`minBuild` = real encoded
build, `maxUpdateAge` = real update age). Attest again:

```
[6/6] Sending attestation ...... GRANTED
```

Say: "Exactly at the minimum still passes — the comparison is `>=`, and the
circuit enforces the full range checks, not just the happy path."

## 3:00–3:40 — optional: firewall off, deny, restore (elevated terminal)

Only if you want the second denial cause. Open an **Administrator** PowerShell:

```powershell
.\scripts\demo-firewall.ps1 off-public
```

It records the Public profile's previous state, disables it, and prints the
restore command. Back in terminal 2: `node agent attest` →

```
[6/6] Sending attestation ...... DENIED (NON_COMPLIANT)
```

Restore immediately — this is the machine you are presenting from:

```powershell
.\scripts\demo-firewall.ps1 restore
```

The restore is recorded and idempotent: if the disable had failed, the script
restores the previous state before raising the error, and `restore` also works
from the saved state file after a crash. State file:
`verifier\data\demo-firewall-state.json` (git-ignored, deleted after restore).

## 3:40–4:10 — replay (terminal 2)

```powershell
npm run demo:replay
```

It makes **one** real attestation and submits the byte-identical body twice:

```
  first submission ............... GRANTED
  identical resubmission ......... DENIED (REPLAY)
```

Say: "The proof was genuine. The challenge is single-use, so a recording of this
submission is worthless ten seconds later."

## 4:10–4:40 — tamper with the log (terminal 1)

Dashboard → Log Integrity → **Verify now** → `✔ Chain intact`, latest hash. Then
in a third PowerShell or Notepad:

```powershell
notepad verifier\data\decisions.jsonl   # change one "result" by hand, save
```

Verify again → `✖ Broken at record N`. Say: "Tamper-evident, not tamper-proof —
without an external anchor someone could rewrite the whole chain. We say that
every time we show this."

## 4:40–5:00 — limits and cleanup

"A modified agent could lie about its own values: there is no TPM attestation.
The arithmetic is honest; the machine is trusted. That is the next thing to
build, and it is the honest boundary of this project."

Then restore the policy and stop the server:

```powershell
.\scripts\demo-policy.ps1 reset     # back to the pre-demo policy
# Ctrl+C in terminal 1
```

## If something fails live

- **Verifier will not start / port busy:** stop the other `node`, or
  `$env:PORT = 3100` and use `https://127.0.0.1:3100`.
- **Dashboard is not trusted by the browser:** run `.\scripts\trust-ca.ps1` once
  per user and restart the browser, or use the shown CA pin to trust it in the
  browser. (Windows-only; on Linux the browser will show a certificate warning —
  click through for the demo.)
- **Agent reports `TLS refused: the CA fingerprint does not match`:** the pin in
  `agent/agent.config.json` or `$env:ZKPG_CA_FINGERPRINT` is wrong. Copy the CA
  pin printed by `demo:single` (or `npm run tls:info`) exactly. A CA/leaf
  regeneration changed the leaf but not the pin; leaf-only regen with
  `npm run tls:leaf` keeps the pin agents already hold.
- **Agent reports `TLS is enabled but no valid CA fingerprint is configured`:**
  set `tlsCaFingerprint` in `agent/agent.config.json` or
  `$env:ZKPG_CA_FINGERPRINT`.
- **Attestation errors before step 6:** read the message. The likely causes are
  a stopped verifier, a firewall/Defender value that is actually off (then the
  first attestation is legitimately DENIED — show it as the denial demo), or an
  expired enrollment code (generate another on the Devices page).
- **No fallback data:** there are no fixtures anymore. `demo` and
  `demo:replay` refuse off Windows and none of them invent posture. If the
  laptop cannot read posture, say so and switch to the dashboard + recorded
  video. Do not pretend.
- **A second identity** on the same machine is the optional multi-device stand-in:
  `$env:AGENT_DATA_DIR = "$PWD\agent\data-second"`, enroll with the label
  `same machine, 2nd identity`, then `node agent attest`. The dashboard lists it
  as its own device with that label. Unset `AGENT_DATA_DIR` afterwards to go back
  to the first identity.

## Backup screen-recording plan

One file per scene, 1080p, real terminal font ≥ 16px:

1. `01-dashboard.mp4` — login, zero-stored cards, privacy panel, Devices records
   count (30 s)
2. `02-granted.mp4` — enroll, attest, GRANTED, gated app over https, 401 without
   token (60 s)
3. `03-denied-policy.mp4` — `demo-policy.ps1 raise`, DENIED (40 s)
4. `04-replay.mp4` — `npm run demo:replay`, GRANTED then REPLAY (30 s)
5. `05-log-tamper.mp4` — verify intact, edit one line, verify broken (40 s)

Do not edit out mistakes; a live REPLAY on a re-run is a feature.

## Appendix — several laptops (optional, still supported)

The multi-device path is unchanged; it is just not needed for the talk. On the
main PC: `$env:DEMO_LAN = "1"`, start the verifier, run
`.\scripts\setup-firewall-rule.ps1` elevated (Private profile, TCP 3000), set
`$env:VERIFIER_URL = "https://<MAIN-PC-IP>:3000"` and the CA pin on each laptop,
enroll one code per laptop and attest each. Expected: three distinct device ids and
three independent decisions; a compliant laptop is granted even when another is
denied.

**UNVERIFIED:** the three-laptop flow has not been run on three physical machines
in this build, and neither have `scripts/demo-policy.ps1`,
`scripts/demo-firewall.ps1` or `npm run demo:replay` on Windows. Test them once,
end to end, the day before.
