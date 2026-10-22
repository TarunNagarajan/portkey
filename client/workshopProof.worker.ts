/// <reference lib="webworker" />
import { Group } from '@semaphore-protocol/group';
import { Identity } from '@semaphore-protocol/identity';
import { generateProof } from '@semaphore-protocol/proof';
import { WORKSHOP_PROOF_DEPTH } from '../shared/workshopProof.js';

interface ProofJob {
  identity: string;
  commitments: string[];
  root: string;
  scope: string;
  message: string;
  depth: number;
}

self.onmessage = async (event: MessageEvent<ProofJob>) => {
  try {
    const { identity: exportedIdentity, commitments, root, scope, message, depth } = event.data;
    if (depth !== WORKSHOP_PROOF_DEPTH) throw new Error('This workshop uses an unsupported proof version.');
    const identity = Identity.import(exportedIdentity);
    const group = new Group(commitments.map(BigInt));
    if (group.root.toString() !== root) throw new Error('The workshop membership list changed. Refresh and try again.');
    const index = group.indexOf(identity.commitment);
    if (index < 0) throw new Error('This credential is not enrolled in this workshop. Use the organizer’s enrollment link.');
    const proof = await generateProof(identity, group, message, scope, depth, {
      wasm: new URL('/zk/semaphore-10.wasm', self.location.origin).toString(),
      zkey: new URL('/zk/semaphore-10.zkey', self.location.origin).toString(),
    });
    self.postMessage({ proof });
  } catch (error) {
    self.postMessage({ error: error instanceof Error ? error.message : 'Could not create the workshop proof.' });
  }
};
