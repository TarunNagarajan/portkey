import type { SemaphoreProof } from '@semaphore-protocol/proof';

export interface WorkshopChallenge {
  challengeId: string;
  version: string;
  depth: number;
  root: string;
  scope: string;
  message: string;
  commitments: string[];
  expiresAt: string;
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
