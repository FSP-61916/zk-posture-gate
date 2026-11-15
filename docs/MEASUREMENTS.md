# Measurements

Environment: Linux x86_64 VM, Node.js 26.13.0, circom 2.1.9, snarkjs 0.7.5,
Groth16 over BN128, circuit `circuits/posture.circom` (125 constraints).

These numbers were recorded before proving switched to `singleThread: true`
(see `docs/VERSIONS.md`), so the proof timings below are from the worker-thread
path and should be re-measured on Windows before quoting them again. Verify and
artifact sizes are unaffected.

Produced by `node scripts/measure.js 10`. The recorded run used a synthetic
posture input (build 22631 / UBR 3803 / 4 days / firewall on / Defender on) passed
directly into the circuit. That sample has since been removed from the script,
which now reads real Windows posture and exits with an error elsewhere. Proof,
setup and timings are real; timings depend on circuit size, not on the input
values.

## Proof generation, N = 10

Raw values in milliseconds:

```
333.9, 66.1, 73.1, 67.7, 67.0, 71.2, 68.2, 56.3, 75.9, 57.8
```

Working:

```
sum  = 937.1 ms
mean = 937.1 / 10 = 93.7 ms      <- skewed by the first (cold) run
```

Sample standard deviation:

```
deviations squared: 57688.5, 764.7, 423.9, 677.9, 714.9, 504.8, 651.9, 1400.6, 316.8, 1292.1
sum of squared deviations = 64436.0
variance = 64436.0 / (10 - 1) = 7159.6
stddev   = sqrt(7159.6) = 84.6 ms
range    = 56.3 ms .. 333.9 ms
```

The spread is dominated by the very first run (JIT warm-up, first read of the
zkey, curve initialisation). Excluding that cold run:

```
sum  = 937.1 - 333.9 = 603.2 ms
mean = 603.2 / 9 = 67.0 ms
stddev = 6.5 ms
```

**Reported honestly:** ~67 ms warm, ~94 ms including a cold start. If a panel
asks for "the" proof time, quote 67 ms warm and mention the 0.33 s cold outlier.

## Verification, N = 10

```
21.79, 20.61, 22.68, 21.36, 17.81, 23.45, 19.74, 21.77, 18.97, 16.51
mean   = 20.47 ms
stddev = 2.20 ms
```

Verification is ~3× faster than proving, which is the usual Groth16 property.

## Sizes

| Artifact | Bytes |
|---|---|
| `posture.wasm` (witness generator) | 42,575 |
| `posture_final.zkey` (proving key) | 84,622 |
| `verification_key.json` | 4,025 |
| `proof.json` (one proof) | 723 |

The USB bundle is therefore tiny by ZK standards (~127 KB of circuit artifacts).

## Constraint system

From `snarkjs r1cs info circuits/build/posture.r1cs`:

```
# of Wires: 126
# of Constraints: 125
# of Private Inputs: 4
# of Public Inputs: 5
# of Outputs: 2
```

The count is small because the circuit only compares and ANDs. `Num2Bits(40)` for
the build and the comparators account for most of the 125.

## What is NOT measured here

- **Windows posture read time** (`Get-MpComputerStatus`, `Get-NetFirewallProfile`,
  Windows Update COM history). UNVERIFIED — needs a real Windows machine. Expect
  the PowerShell script to dominate the agent's wall-clock time, not the proof.
- **End-to-end LAN latency** on three laptops. UNVERIFIED.
- **Dashboard frame timings.** Not measured; it polls every 2 s and renders
  static tables.

## Reproduce

```bash
npm run setup:circuit      # once
node scripts/measure.js 10
```

The script prints the same working shown above, so every number in this file can
be checked by hand.
