# 15 likely panel questions

Short, honest answers. If an answer starts with "we did not", that is the answer.

**1. Why not just a database?**
Because a central inventory is a ready-made map of which machines are vulnerable.
The gate only needs a yes/no answer per laptop, so the system is designed to never
hold the values. A database would be the easy version of the wrong product.

**2. What stops a lying agent?**
Nothing, completely. The proof is honest about arithmetic, not about the machine:
a modified agent could feed false values into the circuit. Real fix: hardware
attestation (TPM quote / measured boot) so the verifier knows which code is
running. We say this on the dashboard, in the README and in the demo.

**3. What is a trusted setup?**
Groth16 needs a one-time parameter generation. Phase 1 is a universal
powers-of-tau file; phase 2 is circuit-specific and produces the proving and
verification keys. If someone kept the toxic waste they could forge proofs, so a
real deployment uses a multi-party ceremony where one honest participant
suffices. Ours is a single contribution run by us, documented as such.

**4. Why Groth16 and not PLONK / STARKs?**
Groth16 has the smallest proofs (~723 bytes) and the cheapest verification
(~20 ms), which matters when the gate runs on a small machine. Cost: a per-circuit
trusted setup. PLONK would avoid the ceremony but produce bigger proofs and
slower verification; STARKs avoid both but are much heavier.

**5. What exactly does the verifier learn?**
Six things: the device id, the policy version, the seven public signals (which
are the verifier's own policy numbers plus the challenge plus `compliant`), the
decision, a reason code, and a latency figure. No posture value.

**6. Why TLS now?**
It is on by default. The verifier creates a local CA and leaf on first run
(`verifier/data/tls`, git-ignored), and the agent pins the CA public key
(SPKI SHA-256) once. A pin mismatch hard-refuses; `DEMO_INSECURE=1` is the only
bypass. The demo label now reads `DEMO · HTTPS · CA pinned`.

**7. What if the laptop is offline?**
It cannot attest — it needs the challenge and the policy. That is deliberate: a
challenge must be fresh to prevent replay. The agent fails cleanly with
`cannot reach verifier`.

**8. How is replay prevented?**
The verifier issues a random 8-byte challenge, stores it bound to one device id,
and burns it on first use (check 4). A replayed proof gets `REPLAY`. Expiry is
judged by the verifier's clock only.

**9. How does the advisory work?**
It downloads CISA's KEV feed, caches it, filters Microsoft entries added since the
policy last changed, and shows them with a banner saying it is advisory only. It
never maps a CVE to a build and never edits the policy.

**10. Why is the log a file and not a database?**
JSON Lines is append-only by construction, readable line by line, and needs no
native module. It also makes tampering a simple hand edit, which is exactly the
attack the hash chain is there to expose.

**11. What happens if I raise the policy?**
The version bumps, old proofs become `POLICY_MISMATCH`, and each laptop must
refetch and reprove. This is how a new threat changes the gate's answer in
seconds.

**12. Can the admin see which check failed on a laptop?**
The admin sees a reason code (e.g. `NON_COMPLIANT`) but not which value failed.
That is intentional: a reason code that names the failing field would leak
posture.

**13. Where are the private keys?**
Only on the laptop, in `agent/data/device.key`, mode 600, generated on first
enroll, never committed and never transmitted. The verifier stores only the
public key.

**14. How do you know the proof really hides the values?**
Because the circuit's public signals are fixed: `compliant`, `challengeSq` and the
five policy inputs. The private inputs (`build`, `updateAgeDays`, `firewallOn`,
`defenderOn`) are witness, and `tests/privacy.test.js` checks that the real build
number appears in no verifier file after a granted attestation. Zero-knowledge is
a property of Groth16 for this circuit; we also demonstrate it mechanically.

**15. What would you build next with more time?**
Hardware attestation via TPM, an external anchor for the log hash (a second
machine or a public chain), and per-device rate limiting. TLS + CA pinning is
already here; the remaining gaps are hardware attestation and a tamper-proof
anchor for the decision log.
