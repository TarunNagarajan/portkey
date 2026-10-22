import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(await readFile(resolve(root, 'scripts/zk-artifacts.json'), 'utf8'));
const files = manifest.files;
const destination = resolve(root, 'public/zk');
const base = manifest.source;

function verified(bytes, file) {
  return bytes.length > 0 && bytes.length <= file.maxBytes &&
    createHash('sha256').update(bytes).digest('hex') === file.sha256;
}

async function download(file) {
  const url = `${base}/${file.name}`;
  let response;
  let currentUrl = url;
  try {
    response = await fetch(currentUrl, { signal: AbortSignal.timeout(30_000), redirect: 'manual' });
    for (let redirects = 0; response.status >= 300 && response.status < 400; redirects += 1) {
      if (redirects >= 3) throw new Error('too many redirects');
      const location = response.headers.get('location');
      if (!location) throw new Error('redirect had no destination');
      const target = new URL(location, currentUrl);
      if (target.protocol !== 'https:' || target.username || target.password)
        throw new Error('redirect destination is not trusted HTTPS');
      currentUrl = target;
      response = await fetch(target, { signal: AbortSignal.timeout(30_000), redirect: 'manual' });
    }
    if (!response.ok || !response.body) throw new Error(`download returned HTTP ${response.status}`);
    const declaredSize = Number(response.headers.get('content-length'));
    if (Number.isFinite(declaredSize) && declaredSize > file.maxBytes)
      throw new Error('artifact exceeds the size limit');
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > file.maxBytes) throw new Error('artifact exceeds the size limit');
      chunks.push(chunk);
    }
    const bytes = Buffer.concat(chunks, size);
    if (!verified(bytes, file)) throw new Error('SHA256 checksum did not match the pinned artifact');
    return bytes;
  } catch (error) {
    throw new Error(`Could not prepare Semaphore artifact ${file.name}: ${error instanceof Error ? error.message : 'download failed'}. Check network access and retry.`, { cause: error });
  }
}

async function prepare(file) {
  const target = resolve(destination, file.name);
  try {
    if (verified(await readFile(target), file)) return;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  await mkdir(destination, { recursive: true });
  const bytes = await download(file);
  const temporary = `${target}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(temporary, bytes, { flag: 'wx' });
    await rename(temporary, target);
  } finally {
    await rm(temporary, { force: true });
  }
}

for (const file of files) await prepare(file);
console.log('Semaphore v4 depth 10 artifacts are ready.');
