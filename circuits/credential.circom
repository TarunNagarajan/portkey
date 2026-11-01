pragma circom 2.1.0;

include "eddsaposeidon.circom";
include "poseidon.circom";

// Proves, without revealing the secret or the issuer signature, that the
// prover holds a credential the issuer signed over
// Poseidon(secret, dept, year), and that its attributes match the public
// requirement. The nullifier binds the credential to one room scope so the
// same credential cannot take two seats in the same room, while remaining
// unlinkable across rooms.
template CredentialProof() {
    // Public
    signal input issuerAx;
    signal input issuerAy;
    signal input dept;
    signal input year;
    signal input scope;
    signal input challenge;
    signal input validUntil;
    signal output nullifier;
    signal output binding;

    // Private
    signal input secret;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;

    signal commitment;

    component hash = Poseidon(4);
    hash.inputs[0] <== secret;
    hash.inputs[1] <== dept;
    hash.inputs[2] <== year;
    hash.inputs[3] <== validUntil;
    commitment <== hash.out;
    component expiryBits = Num2Bits(32);
    expiryBits.in <== validUntil;
    component sessionBinding = Poseidon(2);
    sessionBinding.inputs[0] <== secret;
    sessionBinding.inputs[1] <== challenge;
    binding <== sessionBinding.out;

    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== issuerAx;
    verifier.Ay <== issuerAy;
    verifier.R8x <== sigR8x;
    verifier.R8y <== sigR8y;
    verifier.S <== sigS;
    verifier.M <== commitment;

    // Keep the signed attributes inside the 32-bit range the UI and database
    // use, so a prover cannot present a field-sized "year" that happens to
    // match by accident.
    component deptBits = Num2Bits(16);
    deptBits.in <== dept;
    component yearBits = Num2Bits(16);
    yearBits.in <== year;

    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== secret;
    nullifierHash.inputs[1] <== scope;
    nullifier <== nullifierHash.out;
}

component main { public [issuerAx, issuerAy, dept, year, scope, challenge, validUntil] } = CredentialProof();
