import { writeFile } from 'node:fs/promises';
import { groth16 } from 'snarkjs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const challenge = process.argv[2];
if (!challenge || !/^(0|[1-9][0-9]{0,76})$/.test(challenge)) {
  throw new Error('Pass the decimal challenge returned by the wallet.');
}

const scalarField = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const value = BigInt(challenge);
if (value <= 0n || value >= scalarField) throw new Error('Challenge is outside the BN254 scalar field.');
const privateValue = process.argv[6] ? BigInt(process.argv[6]) : 42n;
if (privateValue <= 0n || privateValue >= scalarField) throw new Error('Test nullifier secret is outside the BN254 scalar field.');
const blinding = ((value - privateValue * privateValue) % scalarField + scalarField) % scalarField;
const input = {
  challenge: value.toString(),
  eligible: '1',
  nullifier: privateValue.toString(),
  secret: privateValue.toString(),
  blinding: blinding.toString(),
};
const wasm = new URL('./build/eligibility_js/eligibility.wasm', import.meta.url);
const zkey = new URL('./build/eligibility_final.zkey', import.meta.url);
const wasmPath = process.argv[3] ? resolve(process.argv[3]) : fileURLToPath(wasm);
const zkeyPath = process.argv[4] ? resolve(process.argv[4]) : fileURLToPath(zkey);
const outputPath = process.argv[5] ? resolve(process.argv[5]) : fileURLToPath(new URL('./proof.json', import.meta.url));
const { proof, publicSignals } = await groth16.fullProve(input, wasmPath, zkeyPath, undefined, undefined, { singleThread: true });
if (publicSignals.length !== 3 || publicSignals[0] !== value.toString() || publicSignals[1] !== '1' || publicSignals[2] !== privateValue.toString())
  throw new Error('Unexpected public signal ordering or values.');
await writeFile(outputPath, JSON.stringify({ proof, publicSignals }, null, 2));
console.log('Wrote proof.json. It reveals the declared public signals and is valid only for this challenge.');
