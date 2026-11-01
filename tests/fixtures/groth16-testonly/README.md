# Test-only Groth16 artifacts

These small WASM, proving-key, and verification-key files were generated from `eligibility.circom` with Circom compiler 2.2.3 (`circom2` 0.2.23), snarkjs 0.7.5, and a power-8 BN254 test ceremony with publicly disclosed deterministic entropy. They are public test data with known toxic waste and MUST NOT be used in production or to protect any real eligibility decision. CI uses the committed WASM and keys directly and does not run a ceremony.

The circuit binds three public inputs in order: a per-request challenge constrained as `secret² + blinding`, eligibility result equal to one, and a stable nullifier equal to the private test secret. The alternate proving key is for checking that a valid proof for the same circuit is rejected against the wrong pinned key.
