pragma circom 2.1.6;

template TestOnlyEligibility() {
    signal input challenge;
    signal input eligible;
    signal input nullifier;
    signal input secret;
    signal input blinding;

    challenge === secret * secret + blinding;
    eligible === 1;
    nullifier === secret;
}

component main { public [challenge, eligible, nullifier] } = TestOnlyEligibility();
