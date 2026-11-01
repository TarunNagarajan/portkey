import type { Queries } from '../server/database.js';
import { credentialNullifier, roomScope, type CredentialFile } from '../shared/credentials.js';
import { checkCredential, signRevocation, type IssuerKeyFile } from './issuerLib.js';
export async function deliverRevocations(database: Queries, issuer: IssuerKeyFile, credentials: CredentialFile[], send: (body: {roomId: string; nullifier: string; signature: ReturnType<typeof signRevocation>}) => Promise<void>) {
  const rooms = await database.query<{ id: string }>(`SELECT id FROM rooms WHERE expires_at > clock_timestamp()
    AND credential_issuer_ax = $1 AND credential_issuer_ay = $2`, [issuer.publicKey.ax, issuer.publicKey.ay]);
  let delivered = 0;
  for (const credential of credentials) {
    if (!checkCredential(credential) || credential.issuer.ax !== issuer.publicKey.ax || credential.issuer.ay !== issuer.publicKey.ay) throw new Error('A revoked credential does not belong to this issuer.');
    if (credential.validUntil * 1000 <= Date.now()) continue;
    for (const room of rooms) {
      const nullifier = credentialNullifier(BigInt(credential.secret), roomScope(room.id)).toString();
      if ((await database.query('SELECT 1 FROM credential_revocations WHERE room_id = $1 AND nullifier = $2', [room.id, nullifier])).length) continue;
      await send({ roomId: room.id, nullifier, signature: signRevocation(issuer, room.id, nullifier) });
      delivered++;
    }
  }
  return { roomsChecked: rooms.length, revocationsDelivered: delivered };
}
