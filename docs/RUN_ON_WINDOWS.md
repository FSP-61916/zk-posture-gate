# Run on Windows (one laptop) - exact commands

Needs Node.js 20 or newer. Python is NOT needed (`npm run app` serves the protected app).
Use three PowerShell windows, all opened in the project folder.

## Once, in window 1
```powershell
cd C:\path\to\zk-posture-gate
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
npm ci
npm run pin                       # creates the local CA, writes its pin into agent\agent.config.json
.\scripts\trust-ca.ps1            # browser trusts the demo certificate (current user, no admin)
```

## Every run
```powershell
# window 1: verifier + dashboard + gate
$env:ADMIN_PASSWORD = "choose-a-long-password"     # 12+ characters
npm run demo:single                                 # leave running, note the enrollment code

# window 2: the protected app (leave running)
cd C:\path\to\zk-posture-gate
npm run app

# window 3: the laptop agent
cd C:\path\to\zk-posture-gate
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$env:ADMIN_PASSWORD = "choose-a-long-password"     # same password, used by demo-policy.ps1
node agent enroll --code XXXX-YYYY --label "This laptop"   # first time only, use the real code
.\scripts\demo-policy.ps1 set-current               # policy = this laptop's real values
node agent attest --open                            # GRANTED, opens the gate in the browser
```

Dashboard: https://127.0.0.1:3000  (sign in with the admin password).

## Reset everything to zero
Stop the verifier (Ctrl+C), then:
```powershell
Remove-Item verifier\data -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item agent\data -Recurse -Force -ErrorAction SilentlyContinue
npm run pin
.\scripts\trust-ca.ps1
```
(Deleting `verifier\data` creates a new CA, so run `npm run pin` and `trust-ca.ps1` again.)
