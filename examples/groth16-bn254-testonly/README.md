# Test-only Groth16 BN254 example

This tiny circuit is only for demonstrating Portkey's custom proof adapter. It is not a credential system. Its eligibility rule is public and trivial, and the deterministic test ceremony below exposes its toxic waste. Never use these generated keys or this ceremony in production.

The circuit has three public inputs in declared order: `challenge`, `eligible`, and `nullifier`. It constrains `challenge = secret² + blinding`, `eligible = 1`, and `nullifier = secret` in BN254's scalar field. The generator chooses a nonzero test secret and calculates the blinding for the wallet's challenge, so all mandatory signals are circuit-bound and the nullifier stays stable across requests.

With Node.js 22+ and `snarkjs` 0.7.5 installed from the repository, run the following from this directory. This pins the `circom2` wrapper at 0.2.23 (Circom compiler 2.2.3). Keep all generated output local; `build/`, the proof, and ceremony files are deliberately not committed.

```sh
mkdir -p build
npx --yes circom2@0.2.23 eligibility.circom --r1cs --wasm --sym -o build
snarkjs powersoftau new bn128 8 build/pot8_0000.ptau
snarkjs powersoftau contribute build/pot8_0000.ptau build/pot8_0001.ptau --name="TEST ONLY INSECURE" --entropy="public deterministic test entropy; never production"
snarkjs powersoftau prepare phase2 build/pot8_0001.ptau build/pot8_final.ptau
snarkjs groth16 setup build/eligibility.r1cs build/pot8_final.ptau build/eligibility_0000.zkey
snarkjs zkey contribute build/eligibility_0000.zkey build/eligibility_final.zkey --name="TEST ONLY INSECURE" --entropy="public deterministic test entropy; never production"
snarkjs zkey export verificationkey build/eligibility_final.zkey build/verification_key.json
```

Publish a custom Groth16 contract using `build/verification_key.json` and public signal names `challenge, eligibility result, nullifier`. In the wallet, copy the challenge decimal into this command:

```sh
node generate.mjs <challenge-decimal>
```

Import `proof.json` in the wallet. It contains only the proof and public signals; the private witness is not uploaded. The circuit, witness, and proof generation run on the participant's machine. Check the public signals shown in the wallet before approving. The issuer selects and describes the circuit; verification proves only that the proof matches that selected circuit and key.

Portkey treats a nullifier as single-use within one contract version. This test uses a stable nullifier to demonstrate replay handling. A real circuit should derive nullifiers from the subject and the intended application or request scope when that subject must complete separate checks.
