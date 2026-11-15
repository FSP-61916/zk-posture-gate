# Manual checklist

The automated suite (`npm test`, 57 tests) covers the gate, circuit, reverse proxy,
TLS pinning, log and privacy claim. These are the checks that need real hardware.
Status column: **AUTO** = covered by a test here, **TODO** = must be run on
Windows/LAN and is currently UNVERIFIED.

| # | Test | Steps | Expected | Status |
|---|---|---|---|---|
| 1 | A real compliant laptop opens the gated app with nothing typed by hand | On Windows: `npm run demo:single` in one terminal, `cd internal-app; python -m http.server 8080` in a second, then `node agent enroll --code …`, `node agent attest --open` | `GRANTED`, browser shows the internal-app page; `/` without the token shows 401 | **TODO** (agent posture reader is Windows-only; proof/sign/proxy covered by tests) |
| 2 | Raise policy above the real values → DENIED | Dashboard → Policy → set `minBuild` above the laptop's build → laptop attests | `DENIED (NON_COMPLIANT)` | **TODO** on Windows; the equivalent is `tests/verifier.test.js` "policy change … POLICY_MISMATCH" and "non-compliant laptop" using a real proof |
| 3 | Proof with a changed policy parameter → POLICY_MISMATCH | `tests/verifier.test.js` "tampered policy signal" | `POLICY_MISMATCH` | **AUTO** |
| 4a | Corrupt proof, off-curve point | `tests/verifier.test.js` "off-curve proof point" | `DENIED (PROOF_INVALID)` | **AUTO** |
| 4b | Corrupt proof, on-curve wrong point | `tests/verifier.test.js` "on-curve but wrong proof point" | `DENIED (PROOF_INVALID)` | **AUTO** |
| 5 | Values exactly equal to the minimum → GRANTED | `tests/circuit.test.js` "values exactly at the policy minimum" | `compliant = 1` | **AUTO** (circuit level); end-to-end TODO on Windows |
| 6 | Replay the same proof | `tests/verifier.test.js` "replaying the same proof" | `DENIED (REPLAY)` | **AUTO** |
| 7 | Restart everything: history persists and the log verifies | Stop the verifier, start it again, Dashboard → Log Integrity | same record count, `✔ Chain intact` | **TODO** manually (persistence logic is **AUTO**: "history persists across a restart") |
| 8 | Edit one log record by hand → broken record reported | `notepad verifier\data\decisions.jsonl`, change a `result`, save, Verify now | `✖ Broken at record N` | **AUTO** (unit) + **TODO** manual click-through |
| 9 | Search all verifier files and logs for the real build number → not found | `tests/privacy.test.js` does exactly this after a granted attestation | not found anywhere | **AUTO** |
| 10 | Wrong or unsigned device signature → DENIED | `tests/verifier.test.js` "bad device signature" and "unknown id" | `DENIED (BAD_SIGNATURE)` | **AUTO** |
| 11 | One laptop runs two identities without a second machine | `$env:AGENT_DATA_DIR = "$PWD\agent\data-second"`; enroll a second code labelled `same machine, 2nd identity`; `node agent attest`; then `Remove-Item Env:AGENT_DATA_DIR` | two distinct `dev_…` ids and two independent decisions; the dashboard shows the second with that label; the first identity is unaffected | **TODO** on Windows |
| 11b (optional) | Three laptops get three independent decisions | Three Windows machines, three codes, attest each (`DEMO_LAN=1`, firewall rule installed) | three distinct device ids, three rows | **TODO** — needs the LAN |

## Demo helpers (single laptop)

Run these once on Windows and record the output in `docs/PHASES.md`:

```powershell
npm run demo:single                      # prints a code, binds 127.0.0.1 only
node agent enroll --code <code> --label "This laptop"
node agent attest                        # GRANTED
.\scripts\demo-policy.ps1 raise
node agent attest                        # DENIED (NON_COMPLIANT)
.\scripts\demo-policy.ps1 set-current
node agent attest                        # GRANTED at the exact boundary
npm run demo:replay                      # GRANTED, then DENIED (REPLAY)
.\scripts\demo-policy.ps1 reset
```

Elevated, and only when you want the firewall denial:

```powershell
.\scripts\demo-firewall.ps1 off-public
node agent attest                        # DENIED (NON_COMPLIANT)
.\scripts\demo-firewall.ps1 restore      # Public profile back to its recorded state
```

Check `netstat -ano | findstr 3000` shows `127.0.0.1:3000`, not `0.0.0.0:3000`.

## Manual Windows checks worth doing once

1. **Posture read accuracy.** Run
   `powershell -File agent\lib\posture.ps1` and compare `build`/`ubr` with
   `winver` and `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'`.
   Then compare `updateAgeDays` with Settings → Windows Update → Update history.
2. **Elevation behaviour.** Run the posture script in a non-elevated shell: it
   must still return firewall/Defender and set `bitlocker: null` (skipped
   gracefully), not crash.
3. **Update-age fallback.** On a machine with an empty Windows Update history,
   confirm `updateSource` becomes `get-hotfix` rather than an error.
4. **Agent UI binding.** `netstat -ano | findstr 4000` must show `127.0.0.1:4000`
   only, never `0.0.0.0`.
5. **Firewall scope.** After `setup-firewall-rule.ps1`,
   `Get-NetFirewallRule -DisplayName 'ZK Posture Gate (TCP 3000)'` must show
   `Profile: Private`.
6. **Dashboard at 390px.** Browser device toolbar at 390×844: cards stack two per
   row, sidebar becomes a top nav, no horizontal page scroll.
7. **Keyboard only.** Tab through login → nav → policy form; the focus ring must
   be visible on every control and the dialog must trap focus (native `dialog`).

## Cleanup before handing the laptop back

```powershell
.\scripts\remove-firewall-rule.ps1
```

Delete `agent\data\` and any `agent\data-*\` folders (second identity) to remove
device keys and enrollment state, and `verifier\data\` if you want a fresh policy
and log. Before deleting `verifier\data\`, run
`.\scripts\demo-firewall.ps1 restore` if you ever ran `off-public` — the recorded
firewall state lives there.
