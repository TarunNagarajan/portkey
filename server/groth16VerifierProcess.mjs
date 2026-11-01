import { createRequire } from "node:module";
import { groth16 } from "snarkjs";

function finish(valid) {
  const curve = globalThis.curve_bn128;
  const cleanup = curve?.terminate ? curve.terminate() : Promise.resolve();
  Promise.resolve(cleanup).finally(() => {
    if (process.connected) process.send(valid === true, () => process.exit(0));
    else process.exit(0);
  });
}

async function validatePoints(op, config, proof) {
  const require = createRequire(import.meta.url);
  const ff = require("ffjavascript");
  const curve = await ff.buildBn128(true);
  try {
    const key = config.verificationKey;
    const g1ProofPoints = op === "verify" ? [proof.proof.pi_a, proof.proof.pi_c] : [];
    const toBigInts = (value) =>
      Array.isArray(value) ? value.map(toBigInts) : BigInt(value);
    const g1Points = [...key.IC, key.vk_alpha_1, ...g1ProofPoints].map((point) =>
      curve.G1.fromObject(toBigInts(point)),
    );
    const g2ProofPoints = op === "verify" ? [proof.proof.pi_b] : [];
    const g2Points = [
      key.vk_beta_2,
      key.vk_gamma_2,
      key.vk_delta_2,
      ...g2ProofPoints,
    ].map((point) => curve.G2.fromObject(toBigInts(point)));
    if (g1Points.some((point) => curve.G1.isZero(point) || !curve.G1.isValid(point))) {
      return false;
    }
    if (
      g2Points.some(
        (point) =>
          curve.G2.isZero(point) ||
          !curve.G2.isValid(point) ||
          !curve.G2.isZero(
            curve.G2.timesScalar(point, ff.Scalar.toLEBuff(BigInt(curve.r))),
          ),
      )
    ) {
      return false;
    }
    return true;
  } finally {
    await curve.terminate();
  }
}

process.once("disconnect", () => process.exit(1));
process.once("message", async (data) => {
  const { op, config, proof } = data;
  try {
    const pointsValid = await validatePoints(op, config, proof);
    const valid =
      pointsValid &&
      (op === "validate-key" ||
        (await groth16.verify(
          config.verificationKey,
          proof.publicSignals,
          proof.proof,
        )));
    finish(valid);
  } catch {
    finish(false);
  }
});
