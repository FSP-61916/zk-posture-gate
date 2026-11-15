# Versions

All runtime dependency versions are **exact** (no `^`, no `~`) and installed with
`npm ci` from the committed `package-lock.json`.

| Package | Version | Kind | Released | Age at build |
|---|---|---|---|---|
| `express` | 4.19.2 | runtime | 2024-03-25 | > 2 years |
| `snarkjs` | 0.7.5 | runtime | 2024-05-20 | > 2 years |
| `circomlib` | 2.0.5 | dev (circuit include only) | 2023-03-15 | > 3 years |
| `circom` (binary) | 2.1.9 | toolchain, not npm | 2024-01-31 | > 2 years |
| Node.js | >= 20 (tested on 26.13.0) | runtime | — | — |
| npm | 11.20.0 (tested) | toolchain | — | — |

Every pinned package is far older than the two-week minimum the brief requires.
No dependency was upgraded to make this build work.

## Why these dependencies

- **express 4.19.2** — one HTTP framework. Express 5 would also work, but 4.x is
  the version three students are most likely to find answers for.
- **snarkjs 0.7.5** — official Groth16 implementation and CLI (compile setup,
  prove, verify). It is the only way to use circom output from Node.
- **circomlib 2.0.5** — provides `Num2Bits`, `GreaterEqThan`, `LessEqThan`. It is
  a `devDependency` because the laptop never compiles circuits; only gate 2
  (`npm run setup:circuit`) and the tests need it.
- Nothing else. Rate limiting, sessions, CSRF, ed25519, HMAC and hashing all use
  Node's built-in `node:crypto` and `node:http`, so there is no express-session,
  no helmet, no jsonwebtoken, no better-sqlite3.

## snarkjs handle rule (no `process.exit()`)

By default snarkjs proves on worker threads and leaves `MessagePort` handles
open afterwards. Scripts then had to call `process.exit()`, and on Node 24 for
Windows that call could fire while handles were still closing and abort the
process:

```
Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 76
```

Two changes remove the cause instead of exiting around it:

- `agent/lib/prover.js` calls `groth16.fullProve` with `{ singleThread: true }`
  for both the witness calculator and the prover, so no worker handles survive
  the proof.
- `agent/lib/client.js` uses `node:http` with `agent: false` instead of the
  global `fetch`, so each request owns one socket that closes with it. No
  undici keep-alive pool is left to tear down. `closeClient()` destroys anything
  a cut-short request left behind.
- `verifier/lib/verify-proof.js` forces the same in-process curve build before
  loading snarkjs. `groth16.verify()` has no option for it, and its worker
  threads kept the *server* alive after Ctrl+C. This pins `ffjavascript`
  0.3.1 as a direct dependency so the shim cannot break silently.

As a result nothing calls `process.exit()`: the agent and scripts set
`process.exitCode`, close the servers/sockets they own, and let the event loop
drain. The tests no longer need `--test-force-exit`: with Node 24.13.0 and
26.13.0 they run 33/33 and exit on their own.

The test command uses a glob (`node --test "tests/*.test.js"`) because Node
24.13.0 rejects a bare directory argument with `MODULE_NOT_FOUND`.

Measured on Linux with Node 24.13.0: a single-threaded proof leaves
`process.getActiveResourcesInfo()` at `["CloseReq","PipeWrap","PipeWrap"]`,
a full prove-and-submit run ends at `["SimpleShutdownWrap","PipeWrap",
"TCPSocketWrap","PipeWrap"]` and still exits on its own with code 0, and the
verifier stops on SIGINT with no worker handles left. The Windows assertion
itself is UNVERIFIED here (no Windows machine).

## Lockfile

`package-lock.json` is committed. `npm ci` is the only install command in the
docs and in `scripts/start-verifier.ps1`. The USB bundle gets its own
`package-lock.json`, generated from a package.json that pins `snarkjs` to the
same exact version.

## R1: real mode only

- The simulated fleet is gone: toggle, `SIM_FLEET` rows, badge, banner, CSS and
  the design/phase text. Every dashboard row now comes from the decision log.
- `GET /api/admin/enrollment-codes` lists every code with a `state` of `active`,
  `used` or `expired`, computed once in `EnrollmentStore.listWithState`. The
  Devices page shows that state and only offers the copy banner while the code
  is still active.
- `GET /api/advisory?window=policy|30d|90d`; `windowSince()` is unit-tested and
  an unknown window falls back to the policy-change date.
- Record counts are pluralised (`1 record`, `2 records`).
- `node agent attest` prints posture / proof / network timings. Durations only:
  no posture value is printed, stored or sent.
- `tests/no-fixtures.test.js` fails if product code imports test code or assigns
  a literal to a posture field.
- `tests/enrollment-codes.test.js` proves a used or expired code is refused and
  never reported as active.

## R2: reverse-proxy gate

- The fake `/vault` page is gone. `verifier/lib/gate.js` is a real reverse proxy
  on `GATE_PORT` (default 8081) that checks a signed token and forwards the
  request to `GATE_UPSTREAM` (default `http://127.0.0.1:8080`).
- The upstream is configuration only: scheme/host are validated at startup, no
  credentials or query allowed, and protocol-relative paths are rejected, so a
  request cannot redirect the proxy.
- `internal-app/` is the real static app used in the demo, served by
  `python -m http.server 8080`.
- A token in `?t=` is moved into an HttpOnly `zkpg_gate` cookie with a 302 and
  removed from the URL. The gate cookie is stripped before forwarding.
- `node agent attest --open` opens the gate URL; `GATE_URL` overrides the origin.
- Gate tokens now last 600 s by default (`GATE_TOKEN_TTL_SECONDS`), admin
  sessions 8 h (`SESSION_TTL_SECONDS`). Documented consequence: a device that
  becomes non-compliant keeps access until its token expires.- `tests/gate.test.js` uses a real upstream: 401 without a token, redirect and
  cookie, GET and POST proxying, upstream status/headers passed through, expired
  and tampered tokens, 502 when upstream is down, SSRF-style path rejection.

## R3: TLS, CA pinning, check-in interval and audit-record note

- **TLS on by default** with a local CA + leaf generated on first run into
  `verifier/data/tls` (git-ignored, keys mode 600): RSA-2048, SHA-256, CA 10
  years, leaf 397 days, leaf file carries the CA PEM for the chain.
- **Local CA is dependency-free**: built by hand in `verifier/lib/tls.js` using
  DER/X.509; no crypto or TLS library required. `npm run tls:info` shows the CA
  pin, leaf fingerprint, SANs and cert paths. `npm run tls:leaf` regenerates only
  the leaf (new IP/hostname), keeping the CA pin agents already have.
- **SANs** = LAN IP + hostname + `127.0.0.1` + `localhost`. Autoregeneration of
  the leaf happens at startup when the SAN set changes; on the LAN the SAN
  includes the host's own IP.
- **CA pinning**: the agent pins the CA public key (SPKI SHA-256) once, via
  `tlsCaFingerprint` in `agent/agent.config.json` or `$env:ZKPG_CA_FINGERPRINT`
  (colon/space tolerant). On every TLS connect the agent verifies the chain, the
  self-signed CA, the leaf signature and validity window, the pin, and the
  hostname (and `127.0.0.1` IP). Pin mismatch hard-refuses; missing pin refuses;
  `DEMO_INSECURE=1` is the only bypass.
- **Interval**: `node agent attest --interval [minutes]` repeats every N minutes
  (default 5; `--interval 1` allowed for rehearsals); one-shot is still the default.
- **Audit records**: every attestation attempt is logged on purpose. The dashboard
  Devices page shows a per-device record count (total, granted, denied) computed
  from the decision log.
- **Secure cookies**: the gate cookie and admin session cookie are set with the
  `Secure` flag only over TLS.
- **Tests**: 57 total, including `tests/tls.test.js` (5) and `tests/records.test.js` (1).
  TLS verified live on Linux: agent accepts the pinned CA, refuses a wrong pin and
  refuses no pin; the gate over HTTPS returns 401 without a token, 302 with a
  token and `zkpg_gate` cookie, and proxies the protected app; plain HTTP to the
  HTTPS port is refused.
- **UNVERIFIED on Windows**: `trust-ca.ps1` (browser trust), `--open` on Windows,
  real Windows posture reads, and leaf auto-regen after a LAN IP change.


