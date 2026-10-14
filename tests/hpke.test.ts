import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  Aes256Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from '@hpke/core';

const vector = {
  info: '4f6465206f6e2061204772656369616e2055726e',
  ikmR: 'a0ce15d49e28bd47a18a97e147582d814b08cbe00109fed5ec27d1b4e9f6f5e3',
  ikmE: 'a90d3417c3da9cb6c6ae19b4b5dd6cc9529a4cc24efb7ae0ace1f31887a8cd6c',
  publicKey:
    '04abc7e49a4c6b3566d77d0304addc6ed0e98512ffccf505e6a8e3eb25c685136f853148544876de76c0f2ef99cdc3a05ccf5ded7860c7c021238f9e2073d2356c',
  enc: '04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f03e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0',
  plaintext: '4265617574792069732074727574682c20747275746820626561757479',
  aad: '436f756e742d30',
  ciphertext:
    '58c61a45059d0c5704560e9d88b564a8b63f1364b8d1fcb3c4c6ddc1d291742465e902cd216f8908da49f8f96f',
};
const hex = (value: string) =>
  Uint8Array.from(value.match(/../g) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
const hexOf = (value: ArrayBuffer | ArrayBufferView) =>
  Buffer.from(
    value instanceof ArrayBuffer
      ? value
      : value.buffer.slice(
          value.byteOffset,
          value.byteOffset + value.byteLength,
        ),
  ).toString('hex');

test('HPKE P-256/HKDF-SHA256/AES-256-GCM matches RFC 9180 Appendix A vector', async () => {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  const recipient = await suite.kem.deriveKeyPair(hex(vector.ikmR));
  const ephemeral = await suite.kem.deriveKeyPair(hex(vector.ikmE));
  assert.equal(
    hexOf(await suite.kem.serializePublicKey(recipient.publicKey)),
    vector.publicKey,
  );
  const sender = await suite.createSenderContext({
    recipientPublicKey: recipient.publicKey,
    info: hex(vector.info),
    ekm: ephemeral,
  });
  assert.equal(hexOf(sender.enc), vector.enc);
  const ciphertext = await sender.seal(hex(vector.plaintext), hex(vector.aad));
  assert.equal(hexOf(ciphertext), vector.ciphertext);
  const receiver = await suite.createRecipientContext({
    recipientKey: recipient.privateKey,
    enc: sender.enc,
    info: hex(vector.info),
  });
  assert.equal(
    hexOf(await receiver.open(ciphertext, hex(vector.aad))),
    vector.plaintext,
  );
});
