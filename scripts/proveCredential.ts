// Generates a credential proof outside the browser. Used by the API tests and
// useful for debugging a credential without opening the app.
//
//   npx tsx scripts/proveCredential.ts --credential alice.json --room <room-uuid>
//
// Prints { proof, publicSignals } on stdout. The secret in the credential file
// is only read locally; it is never part of the output.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { credentialFile, credentialProofInput } from '../shared/credentials.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const flags = new Map<string, string>();
const args = process.argv.slice(2);
for (let index = 0; index < args.length; index += 2) {
  const flag = args[index];
  if (!flag?.startsWith('--')) continue;
  flags.set(flag.slice(2), args[index + 1] ?? '');
}

async function main() {
  const credentialPath = flags.get('credential');
  const roomId = flags.get('room');
  if (!credentialPath || !roomId) {
    throw new Error('Usage: --credential <file> --room <room-uuid>');
  }
  const credential = credentialFile.parse(
    JSON.parse(await readFile(resolve(root, credentialPath), 'utf8')),
  );
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    credentialProofInput(credential, roomId, flags.get('challenge') ?? (() => { throw new Error('Pass --challenge from POST /api/join/:code/challenge'); })()),
    resolve(root, 'public/zk/credential.wasm'),
    resolve(root, 'public/zk/credential.zkey'),
  );
  const output = JSON.stringify({ proof, publicSignals });
  await new Promise<void>((resolveWrite, rejectWrite) => {
    process.stdout.write(output, (error) => (error ? rejectWrite(error) : resolveWrite()));
  });
  // SnarkJS's proving curve leaves worker threads running in Node, so exit
  // explicitly once the result is flushed.
  process.exit(0);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
