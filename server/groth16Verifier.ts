import { fork, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  BN254_SCALAR_FIELD,
  canonicalJson,
  type Groth16AdapterConfig,
} from "../shared/platform.js";
import { HttpError } from "./errors.js";

const FIELD = BN254_SCALAR_FIELD;
const BASE = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const DECIMAL = /^(0|[1-9][0-9]{0,76})$/;

const BASE_COORDINATE = z
  .string()
  .max(77)
  .regex(DECIMAL)
  .refine((value) => DECIMAL.test(value) && value.length <= 77 && BigInt(value) < BASE);
const SCALAR = z
  .string()
  .max(77)
  .regex(DECIMAL)
  .refine((value) => DECIMAL.test(value) && value.length <= 77 && BigInt(value) < FIELD);
const G1 = z.array(BASE_COORDINATE).length(3).refine((point) => point[2] === "1");
const F2 = z.array(BASE_COORDINATE).length(2);
const G2 = z
  .array(F2)
  .length(3)
  .refine((point) => point[2][0] === "1" && point[2][1] === "0");
const PRECOMPUTED_PAIRS = z.array(z.array(F2).length(3)).length(2);

const verificationKeySchema = z
  .object({
    protocol: z.literal("groth16"),
    curve: z.enum(["bn128", "bn254"]),
    nPublic: z.number().int().min(3).max(16),
    vk_alpha_1: G1,
    vk_beta_2: G2,
    vk_gamma_2: G2,
    vk_delta_2: G2,
    IC: z.array(G1).min(4).max(17),
    vk_alphabeta_12: PRECOMPUTED_PAIRS.optional(),
  })
  .strict();

function rejectInfinity(config: Groth16AdapterConfig) {
  const key = config.verificationKey as Record<string, unknown> & {
    vk_alpha_1: string[];
    vk_beta_2: string[][];
    vk_gamma_2: string[][];
    vk_delta_2: string[][];
    IC: string[][];
  };
  const g1Points = [key.vk_alpha_1, ...key.IC];
  if (g1Points.some((point) => point[0] === "0" && point[1] === "0")) {
    throw new HttpError(422, "INVALID_VERIFICATION_KEY", "Verification key contains a point at infinity.");
  }
  const g2Points = [key.vk_beta_2, key.vk_gamma_2, key.vk_delta_2];
  if (
    g2Points.some(
      (point) =>
        point[0][0] === "0" &&
        point[0][1] === "0" &&
        point[1][0] === "0" &&
        point[1][1] === "0",
    )
  ) {
    throw new HttpError(422, "INVALID_VERIFICATION_KEY", "Verification key contains a point at infinity.");
  }
}

export function parseVerificationKey(
  value: unknown,
  names: unknown,
): Groth16AdapterConfig {
  const parsed = verificationKeySchema.parse(value);
  if (Buffer.byteLength(canonicalJson(parsed)) > 32 * 1024) {
    throw new HttpError(422, "INVALID_VERIFICATION_KEY", "Verification key exceeds the 32 KiB limit.");
  }

  // snarkjs may include this known precomputation. Portkey ignores it and fingerprints only verifier inputs.
  const { vk_alphabeta_12: _precomputed, ...key } = parsed;
  void _precomputed;
  if (key.curve === "bn254") key.curve = "bn128";
  if (key.IC.length !== key.nPublic + 1) {
    throw new HttpError(422, "INVALID_VERIFICATION_KEY", "Verification key input count does not match its IC points.");
  }

  const publicSignalNames = z
    .array(z.string().trim().min(1).max(48).regex(/^[A-Za-z][A-Za-z0-9 _.-]*$/))
    .length(key.nPublic)
    .parse(names);
  if (new Set(publicSignalNames.map((name) => name.toLowerCase())).size !== publicSignalNames.length) {
    throw new HttpError(422, "INVALID_VERIFICATION_KEY", "Public signal names must be unique.");
  }
  if (
    publicSignalNames[0].toLowerCase() !== "challenge" ||
    !["eligibility result", "eligible"].includes(publicSignalNames[1].toLowerCase()) ||
    publicSignalNames[2].toLowerCase() !== "nullifier"
  ) {
    throw new HttpError(422, "INVALID_VERIFICATION_KEY", "The first three public signal names must be challenge, eligibility result, and nullifier in that order.");
  }

  const verificationKey = key as unknown as Record<string, unknown>;
  if (Buffer.byteLength(canonicalJson(verificationKey)) > 32 * 1024) {
    throw new HttpError(422, "INVALID_VERIFICATION_KEY", "Verification key exceeds the 32 KiB limit.");
  }
  const config: Groth16AdapterConfig = {
    protocol: "groth16",
    curve: "bn128",
    nPublic: key.nPublic,
    verificationKey,
    publicSignalNames,
    fingerprint: createHash("sha256").update(canonicalJson(verificationKey)).digest("hex"),
  };
  rejectInfinity(config);
  return config;
}

export const customProofSchema = z
  .object({
    proof: z
      .object({
        protocol: z.literal("groth16"),
        curve: z.enum(["bn128", "bn254"]),
        pi_a: G1,
        pi_b: G2,
        pi_c: G1,
      })
      .strict(),
    publicSignals: z.array(SCALAR).min(3).max(16),
  })
  .strict();

type VerificationJob =
  | { op: "validate-key"; config: Groth16AdapterConfig }
  | { op: "verify"; config: Groth16AdapterConfig; proof: unknown };

let busy = false;
const activeChildren = new Set<ChildProcess>();
const QUEUE_TIMEOUT_MS = 10_000;

process.once("exit", () => {
  for (const child of activeChildren) child.kill();
});

async function runGroth16Process(data: VerificationJob): Promise<boolean> {
  if (busy) {
    throw new HttpError(429, "PROOF_BUSY", "Proof checks are busy. Wait a moment and try again.");
  }
  busy = true;
  try {
    const child = fork(
      fileURLToPath(new URL("./groth16VerifierProcess.mjs", import.meta.url)),
      [],
      {
        execArgv: ["--max-old-space-size=256"],
        stdio: ["ignore", "ignore", "ignore", "ipc"],
        windowsHide: true,
        env: {
          PATH: process.env.PATH ?? "",
          ...(process.platform === "win32" && process.env.SystemRoot
            ? { SystemRoot: process.env.SystemRoot }
            : {}),
        },
      },
    );
    activeChildren.add(child);
    try {
      return await new Promise<boolean>((resolve, reject) => {
        let settled = false;
        const settle = (value: boolean, error?: Error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (error) reject(error);
          else resolve(value);
        };
        const timer = setTimeout(() => {
          const code = data.op === "verify" ? "PROOF_INVALID" : "INVALID_VERIFICATION_KEY";
          settle(false, new HttpError(422, code, "The cryptographic check exceeded its time limit."));
          child.kill("SIGKILL");
        }, QUEUE_TIMEOUT_MS);
        child.once("message", (valid: unknown) => settle(valid === true));
        child.once("error", () => settle(false));
        child.once("exit", () => settle(false));
        child.send(data, (error) => {
          if (error) settle(false);
        });
      });
    } finally {
      activeChildren.delete(child);
      if (child.connected) child.disconnect();
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
        setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill();
        }, 100).unref();
      }
    }
  } finally {
    busy = false;
  }
}

export async function validateVerificationKeyBounded(config: Groth16AdapterConfig) {
  const valid = await runGroth16Process({ op: "validate-key", config });
  if (!valid) {
    throw new HttpError(422, "INVALID_VERIFICATION_KEY", "Verification key contains invalid or non-subgroup curve points.");
  }
}

export function verifyGroth16Bounded(
  config: Groth16AdapterConfig,
  proof: unknown,
) {
  return runGroth16Process({ op: "verify", config, proof });
}
