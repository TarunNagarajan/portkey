import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import https from "node:https";
import http from "node:http";
import type { ClientRequest, IncomingMessage, RequestOptions } from "node:http";

export interface DomainRequestResult {
  status: number;
  contentType: string | undefined;
  body: Buffer;
}
export interface DomainAddress {
  address: string;
  family: number;
}
export interface DomainVerificationDependencies {
  resolve(hostname: string): Promise<DomainAddress[]>;
  request(
    url: URL,
    pinned: DomainAddress,
    timeoutMs: number,
    maximumBytes: number,
  ): Promise<DomainRequestResult>;
  transport?: DomainTransport;
}
export type DomainTransport = (
  url: URL,
  options: RequestOptions,
  callback: (response: IncomingMessage) => void,
) => ClientRequest;

function ipv6Number(address: string): bigint | null {
  if (address.includes(".")) return null;
  const pieces = address.toLowerCase().split("::");
  if (pieces.length > 2) return null;
  const left = pieces[0] ? pieces[0].split(":") : [];
  const right = pieces[1] ? pieces[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if (
    (pieces.length === 1 && missing !== 0) ||
    (pieces.length === 2 && missing < 1)
  )
    return null;
  const words = [...left, ...Array(Math.max(0, missing)).fill("0"), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word)))
    return null;
  return words.reduce(
    (value, word) => (value << 16n) | BigInt(`0x${word}`),
    0n,
  );
}

export function isPublicAddress(address: string) {
  if (isIP(address) === 4) {
    const octets = address.split(".").map(Number);
    const [a, b, c] = octets;
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 &&
        (b === 0 || b === 2 || b === 168 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)
    );
  }
  if (isIP(address) !== 6) return false;
  const value = ipv6Number(address);
  if (value === null) return false;
  const inPrefix = (prefix: bigint, bits: number) =>
    value >> BigInt(128 - bits) === prefix;
  const globalUnicast = inPrefix(1n, 3); // 2000::/3
  const firstWord = value >> 112n;
  const secondWord = (value >> 96n) & 0xffffn;
  const special2001 = firstWord === 0x2001n && secondWord <= 0x01ffn;
  const documentation = inPrefix(0x20010db8n, 32);
  const sixToFour = inPrefix(0x2002n, 16);
  const documentationNew = inPrefix(0x3fff0n, 20);
  return (
    globalUnicast &&
    !special2001 &&
    !documentation &&
    !sixToFour &&
    !documentationNew
  );
}

export async function requestPinnedDomain(
  url: URL,
  pinned: DomainAddress,
  timeoutMs: number,
  maximumBytes: number,
  transport?: DomainTransport,
): Promise<DomainRequestResult> {
  const network = url.protocol === "https:" ? https : http;
  const get = transport ?? network.get.bind(network);
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error, value?: DomainRequestResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (error) reject(error);
      else resolve(value!);
    };
    const request = get(
      url,
      {
        agent: false,
        timeout: timeoutMs,
        ...(url.protocol === "https:" ? { servername: url.hostname } : {}),
        headers: { Accept: "application/json", Host: url.host },
        lookup: ((
          hostname: string,
          options: { all?: boolean },
          callback: (...args: unknown[]) => void,
        ) => {
          if (hostname !== url.hostname)
            return callback(new Error("unexpected hostname"));
          if (options?.all)
            callback(null, [
              { address: pinned.address, family: pinned.family },
            ]);
          else callback(null, pinned.address, pinned.family);
        }) as typeof lookup,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        response.on("data", (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > maximumBytes) {
            response.destroy(new Error("response too large"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () =>
          finish(undefined, {
            status: response.statusCode ?? 0,
            contentType: response.headers["content-type"],
            body: Buffer.concat(chunks),
          }),
        );
        response.on("error", (error) => finish(error));
      },
    );
    const deadline = setTimeout(
      () => request.destroy(new Error("verification timeout")),
      timeoutMs,
    );
    request.on("timeout", () =>
      request.destroy(new Error("verification timeout")),
    );
    request.on("error", (error) => finish(error));
  });
}

let activeChecks = 0;
let pendingResolutions = 0;
export async function fetchDomainVerificationFile(
  origin: string,
  allowLocalHttp: boolean,
  dependencies: Partial<DomainVerificationDependencies> = {},
) {
  if (activeChecks >= 4) throw new Error("Domain verification is busy.");
  activeChecks += 1;
  try {
    const url = new URL("/.well-known/portkey-app.json", origin);
    const localName =
      url.hostname === "localhost" ||
      url.hostname.endsWith(".localhost") ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]";
    if (
      url.protocol !== "https:" &&
      !(allowLocalHttp && localName && url.protocol === "http:")
    )
      throw new Error("HTTPS is required.");
    if (url.protocol === "https:" && url.port)
      throw new Error("HTTPS port 443 is required.");
    if (url.protocol === "http:" && !localName)
      throw new Error("Local HTTP is required.");
    if (pendingResolutions >= 4)
      throw new Error("Domain verification is busy.");
    pendingResolutions += 1;
    const resolveHost =
      dependencies.resolve ??
      ((hostname) => {
        if (allowLocalHttp && url.protocol === "http:" && localName) {
          return Promise.resolve([{ address: "127.0.0.1", family: 4 }]);
        }
        return lookup(hostname, { all: true, verbatim: true });
      });
    const resolution = Promise.resolve().then(() => resolveHost(url.hostname));
    void resolution.then(
      () => {
        pendingResolutions -= 1;
      },
      () => {
        pendingResolutions -= 1;
      },
    );
    let addresses: DomainAddress[];
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      addresses = await Promise.race([
        resolution,
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(() => reject(new Error("DNS timeout")), 2000);
        }),
      ]);
    } finally {
      if (timeout) clearTimeout(timeout);
    }
    if (!addresses.length) throw new Error("No address found.");
    if (
      url.protocol === "http:" &&
      (!localName ||
        addresses.some((item) => !["127.0.0.1", "::1"].includes(item.address)))
    )
      throw new Error("Local address required.");
    if (
      url.protocol === "https:" &&
      addresses.some((item) => !isPublicAddress(item.address))
    )
      throw new Error("Public address required.");
    const result = dependencies.request
      ? await dependencies.request(url, addresses[0], 3500, 4096)
      : await requestPinnedDomain(
          url,
          addresses[0],
          3500,
          4096,
          dependencies.transport,
        );
    if (result.body.length > 4096)
      throw new Error("Verification file is too large.");
    if (result.status >= 300 && result.status < 400)
      throw new Error("Redirects are not allowed.");
    if (
      result.status !== 200 ||
      !/^application\/json(?:\s*;|\s*$)/i.test(result.contentType ?? "")
    )
      throw new Error("Verification file is unavailable.");
    return JSON.parse(result.body.toString("utf8")) as unknown;
  } finally {
    activeChecks -= 1;
  }
}
