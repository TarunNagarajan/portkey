import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";

const b64 = (value: Uint8Array) => Buffer.from(value).toString("base64url");
const sha256 = (value: Uint8Array | string) =>
  createHash("sha256").update(value).digest();

export type TestPasskey = ReturnType<typeof createPasskey>;

export function createPasskey(credentialId = `credential-${randomUUID()}`) {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const id = Buffer.from(credentialId);
  const x = Buffer.from(jwk.x!, "base64url");
  const y = Buffer.from(jwk.y!, "base64url");
  const coseKey = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, x],
      [-3, y],
    ]),
  );
  return {
    id: b64(id),
    idBytes: id,
    privateKey: pair.privateKey,
    coseKey,
    rpIdHash(rpId: string) {
      return sha256(rpId);
    },
    registration(challenge: string, origin: string) {
      const clientDataJSON = Buffer.from(
        JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false }),
      );
      const authData = Buffer.concat([
        sha256(new URL(origin).hostname),
        Buffer.from([0x45]), // UP, UV, and AT
        Buffer.alloc(4),
        Buffer.alloc(16),
        Buffer.from([id.length >> 8, id.length & 0xff]),
        id,
        coseKey,
      ]);
      return {
        id: b64(id),
        rawId: b64(id),
        type: "public-key",
        response: {
          clientDataJSON: b64(clientDataJSON),
          attestationObject: b64(
            isoCBOR.encode(
              new Map<string, any>([
                ["fmt", "none"],
                ["attStmt", new Map()],
                ["authData", authData],
              ]),
            ),
          ),
          transports: ["internal"],
        },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      };
    },
    assertion(challenge: string, origin: string, options: { flags?: number; counter?: number; userHandle?: string | null; tamper?: boolean; rpId?: string } = {}) {
      const clientDataJSON = Buffer.from(
        JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }),
      );
      const counter = options.counter ?? 1;
      const authData = Buffer.concat([
        sha256(options.rpId ?? new URL(origin).hostname),
        Buffer.from([options.flags ?? 0x05]), // UP and UV
        Buffer.from([counter >>> 24, counter >>> 16, counter >>> 8, counter]),
      ]);
      const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
      const signature = sign("sha256", signed, pair.privateKey);
      if (options.tamper) signature[0] ^= 1;
      return {
        id: b64(id),
        rawId: b64(id),
        type: "public-key",
        response: {
          clientDataJSON: b64(clientDataJSON),
          authenticatorData: b64(authData),
          signature: b64(signature),
          userHandle: options.userHandle ?? null,
        },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      };
    },
  };
}

export function challengeFrom(options: Record<string, any>): string {
  return options.challenge;
}
