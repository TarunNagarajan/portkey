import type { SemaphoreProof } from '@semaphore-protocol/proof';
import { ApiError, api } from './api.js';

export interface ProofRule { mode: 'any'; version: string; depth: number; digest: string; groups: Array<{ id: string; name: string }> }

export interface WorkshopChallenge {
  challengeId: string;
  version: string;
  depth: number;
  root: string;
  scope: string;
  message: string;
  commitments: string[];
  expiresAt: string;
  proofRule?: ProofRule;
}

export async function submitProofWithBusyRetry(code: string, body: Record<string, unknown>, signal: AbortSignal, expiresAt: number) {
  for (let attempt = 0; ; attempt += 1) {
    if (expiresAt <= Date.now()) throw new Error('This proof challenge expired while checking membership. Start a new proof.');
    try { return await api(`/join/${code}/prove`, 'POST', body, signal); }
    catch (error) {
      if (!(error instanceof ApiError) || error.code !== 'PROOF_BUSY' || attempt >= 3) throw error;
      const delay = 250 * (attempt + 1);
      if (expiresAt <= Date.now() + delay) throw new Error('This proof challenge is about to expire while the verifier is busy. Start a new proof.');
      await new Promise<void>((resolve, reject) => {
        const timer = window.setTimeout(done, delay);
        function done() { signal.removeEventListener('abort', aborted); resolve(); }
        function aborted() { window.clearTimeout(timer); signal.removeEventListener('abort', aborted); reject(new DOMException('Proof request cancelled.', 'AbortError')); }
        signal.addEventListener('abort', aborted, { once: true });
        if (signal.aborted) aborted();
      });
    }
  }
}

export function generateWorkshopProof(identity: string, challenge: WorkshopChallenge, signal?: AbortSignal): Promise<SemaphoreProof> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('Proof generation was cancelled.'));
      return;
    }
    const worker = new Worker(new URL('./workshopProof.worker.ts', import.meta.url), { type: 'module' });
    const timer = window.setTimeout(() => {
      finish();
      reject(new Error('Proof generation took too long. Check that your browser supports the workshop proof files and try again.'));
    }, Math.max(0, Date.parse(challenge.expiresAt) - Date.now() - 5_000));
    const finish = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      worker.terminate();
    };
    const abort = () => {
      finish();
      reject(new Error('Proof generation was cancelled.'));
    };
    signal?.addEventListener('abort', abort, { once: true });
    worker.onmessage = (event: MessageEvent<{ proof?: SemaphoreProof; error?: string }>) => {
      finish();
      if (event.data.proof) resolve(event.data.proof);
      else reject(new Error(event.data.error || 'Could not create the workshop proof.'));
    };
    worker.onerror = () => {
      finish();
      reject(new Error('Proof generation failed in this browser. Try a current browser and check your connection.'));
    };
    worker.postMessage({
      identity,
      commitments: challenge.commitments,
      root: challenge.root,
      scope: challenge.scope,
      message: challenge.message,
      depth: challenge.depth,
    });
  });
}
