import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const sha256 = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const manifest = { protocol: 'portkey-credential-v2', setup: 'development', ceremony: null, generatedAt: new Date().toISOString(), hashes: {
 circuit: sha256('circuits/credential.circom'), wasm: sha256('public/zk/credential.wasm'), zkey: sha256('public/zk/credential.zkey'), verificationKey: sha256('server/zk/verification_key.json'), ptau: sha256('circuits/build/pot14_final.ptau'),
} };
for (const path of ['public/zk/manifest.json', 'server/zk/manifest.json']) writeFileSync(path, JSON.stringify(manifest, null, 2) + '\n');
