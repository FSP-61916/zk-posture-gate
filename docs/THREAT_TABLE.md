# Threat table

| # | Attack | What stops it | What does **not** stop it yet |
|---|---|---|---|
| 1 | Replay a captured proof | Challenge is random, bound to one deviceId, valid 60 s, consumed at check 4 (`REPLAY`) | An attacker who wins the race within 60 s on the LAN could submit first. TLS is on by default with CA pinning; `DEMO_INSECURE=1` is the only bypass. |
| 2 | Forge a proof for posture that fails policy | Groth16 soundness: without a valid witness the circuit cannot output `compliant = 1`; the verifier checks `compliant` separately (check 6) | **A modified agent can lie about its own inputs.** No TPM-backed attestation, so the values feeding the circuit are only as honest as the code reading them |
| 3 | Claim another laptop's device id | deviceId is `sha256(public key)`; the verifier checks the ed25519 signature against the stored key, and enrollment rejects an id that does not match the key | Someone with the private key file can impersonate that device; the key is mode 600 but not hardware-bound |
| 4 | Reuse an enrollment code | Single use (burned on redemption), TTL (`ENROLL_CODE_TTL`, default 600 s), 32-character alphabet, 8 characters | No account lockout beyond a 10/min IP limit; a leaked unused code within its TTL works |
| 5 | Make the verifier accept a weaker policy | The verification policy is verifier-owned and versioned; the body's `policyVersion` and all four policy public signals must match exactly (`POLICY_MISMATCH`) | An attacker with the admin password can lower the policy — that is the admin's authority, by design |
| 6 | Prove under an old policy after the admin raised it | Every policy change bumps `version`; proofs carry the version in the signed message and the public signals | Nothing; this is the intended gate |
| 7 | Hand-edit the decision log | Hash chain over `prevHash + canonical fields`; `/api/log/verify` reports the first broken record | **A hash chain is tamper-evident, not tamper-proof.** Rewriting every record consistently defeats it without an external anchor (future work) |
| 8 | Extract posture values from the server or log | Values never leave the laptop; the request schema rejects extra fields; the log schema has no field for them; `tests/privacy.test.js` scans every verifier file for the real build number | A memory dump of a *compromised laptop* still has the values — that is the machine's own data |
| 9 | Send an off-curve point to crash verification | `snarkjs.groth16.verify` throws, the wrapper catches it and returns false → `PROOF_INVALID` (tested with both an off-curve and an on-curve wrong point) | Verification still costs ~20 ms; a flood is limited to 30/min per IP, which is a demo-grade control |
| 10 | Cross-site request forgery against the admin API | `SameSite=Strict` httpOnly cookie + required `x-csrf-token` header matched in constant time | XSS on the dashboard would bypass CSRF; CSP is `script-src 'self'` with no inline scripts, but there is no formal audit |
| 11 | Steal the admin session | httpOnly + Secure (when TLS) cookie, 8 h expiry, HMAC-signed payload | **Plain HTTP**: anyone on the path can read the cookie. That is why `DEMO_INSECURE=1` must not be used outside a throwaway demo. |
| 12 | Brute-force the admin password | Constant-time comparison, 10 attempts/min per IP, 200 ms delay | No MFA, no lockout, no password policy beyond 12 characters |
| 13 | Poison the KEV advisory | Advisory only: it is displayed with a timestamp and a "not mapped to your builds" banner, cached locally, and never changes policy | A compromised CISA feed or local cache is trusted as data; nothing verifies its signature |
| 14 | Swap the verification key for one matching a fake circuit | The verifier loads a local `verification_key.json` and never accepts one over the network | Anyone who can write to the verifier's disk can replace it; file permissions are the only control |
| 15 | Flood `/api/attest` | 30/min per IP, 256 KB body cap, 20 ms verification | Distributed sources are not correlated; no global limit |
| 16 | Turn the gate into an open proxy (SSRF) | `GATE_UPSTREAM` is read once from the environment and is the only target; scheme, credentials, query and host are validated at startup; protocol-relative paths (`//host/...`) are rejected; the gate cookie is stripped before forwarding | An admin who points `GATE_UPSTREAM` somewhere bad can proxy there — that is their authority; the gate does not add path-level authorization for the app |
| 17 | Access the app after compliance drops | Token lifetime bounds it (`GATE_TOKEN_TTL_SECONDS`, default 600 s) | The gate checks the token, not current posture: a laptop that turns non-compliant keeps access until the token expires |
| 18 | MITM with a different trusted certificate | TLS is on by default; the agent pins the CA public key (SPKI SHA-256) and verifies the full chain, hostname and validity, refusing on pin mismatch. `DEMO_INSECURE=1` is the only bypass. | An attacker with the verifier's private key can impersonate it; key lives on the verifier's disk, mode 600. Leaf regen changes the leaf but not the CA pin. |

## The one that matters

**No hardware attestation.** Every other row is engineering; this one is physics.
Without a TPM measurement of the running agent, a laptop that is fully patched but
running a tampered agent can still produce a valid proof of honest values. The
README and the demo say this out loud rather than hiding it.
