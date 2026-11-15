pragma circom 2.1.6;

// ---------------------------------------------------------------------------
// ZK Posture Gate - the circuit
//
// The laptop proves: "my build is at least minBuild, my last update is no older
// than maxUpdateAge days, and the firewall/Defender settings satisfy the two
// booleans the verifier requires" - without revealing the actual values.
//
// Private (witness only, never leaves the laptop):
//   build           build * 100000 + UBR, fits in 40 bits (see docs/ARCHITECTURE.md)
//   updateAgeDays   whole days since the last installed update
//   firewallOn      1 if firewall is enabled on ALL profiles, else 0
//   defenderOn      1 if Defender real-time protection is on, else 0
//
// Public (sent to the verifier as public signals):
//   minBuild, maxUpdateAge, requireFirewall, requireDefender   (verifier policy)
//   challenge       random number from the verifier, ties proof to one request
//
// Outputs (also public):
//   compliant       1 if every check passed, else 0
//   challengeSq     challenge * challenge, so the challenge cannot be dropped
// ---------------------------------------------------------------------------

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template PostureGate() {
    // --- private inputs -----------------------------------------------------
    signal input build;
    signal input updateAgeDays;
    signal input firewallOn;
    signal input defenderOn;

    // --- public inputs ------------------------------------------------------
    signal input minBuild;
    signal input maxUpdateAge;
    signal input requireFirewall;
    signal input requireDefender;
    signal input challenge;

    // --- public outputs -----------------------------------------------------
    signal output compliant;
    signal output challengeSq;

    // 1. Every 0/1 input must really be 0 or 1, otherwise a device could send
    //    e.g. firewallOn = 2 and make the boolean arithmetic lie.
    //    (x * (x - 1) === 0  forces x to be 0 or 1 over the prime field.)
    firewallOn * (firewallOn - 1) === 0;
    defenderOn * (defenderOn - 1) === 0;
    requireFirewall * (requireFirewall - 1) === 0;
    requireDefender * (requireDefender - 1) === 0;

    // 2. Range-check the private numbers. Comparators below are only sound when
    //    their inputs are known to fit in the declared width, so we prove it.
    //    build < 2^40 (40 bits) and updateAgeDays < 2^16 (65535 days).
    component buildBits = Num2Bits(40);
    buildBits.in <== build;

    component ageBits = Num2Bits(16);
    ageBits.in <== updateAgeDays;

    // 3. Comparisons. Both sides are range-checked inside the comparator
    //    (GreaterEqThan/LessEqThan decompose both inputs to bits).
    component buildOk = GreaterEqThan(40);
    buildOk.in[0] <== build;
    buildOk.in[1] <== minBuild;

    component ageOk = LessEqThan(16);
    ageOk.in[0] <== updateAgeDays;
    ageOk.in[1] <== maxUpdateAge;

    // 4. Boolean requirement: ok = 1 - required * (1 - value)
    //    required=0 -> always ok; required=1 -> ok only when value=1.
    signal fwOk <== 1 - requireFirewall * (1 - firewallOn);
    signal dfOk <== 1 - requireDefender * (1 - defenderOn);

    // 5. Combine the four checks with AND, using only quadratic constraints.
    //    Quadratic means "product of at most two signals per constraint", so
    //    we cannot write a*b*c*d directly - we chain pairwise.
    signal and1 <== buildOk.out * ageOk.out;
    signal and2 <== and1 * fwOk;
    compliant <== and2 * dfOk;

    // 6. Bind the verifier's challenge into the proof. challengeSq is a public
    //    output, so the verifier can check it equals challenge^2 outside the
    //    circuit as well; the multiplication cannot be optimised away.
    challengeSq <== challenge * challenge;

    // Sanity: compliant really is a bit (helps catch mistakes when editing).
    compliant * (compliant - 1) === 0;
}

component main {public [minBuild, maxUpdateAge, requireFirewall, requireDefender, challenge]} = PostureGate();
