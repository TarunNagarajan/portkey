import type { PlaceSuggestion } from '../shared/rooms.js';

let csrfToken = '';
let publicOrigin = '';

export function buildInvitationUrl(origin: string, code: string, fingerprint?: string | null, passToken?: string): string {
  let base: URL;
  try { base = new URL(origin); } catch { throw new Error('Invitation origin is invalid.'); }
  if (
    !['http:', 'https:'].includes(base.protocol) ||
    base.username ||
    base.password ||
    base.pathname !== '/' ||
    base.search ||
    base.hash
  )
    throw new Error('Invitation origin is invalid.');
  if (!/^[A-Za-z0-9_-]{16}$/.test(code)) throw new Error('Room invitation code is invalid.');
  if (fingerprint && !/^[a-f0-9]{64}$/.test(fingerprint)) throw new Error('Inbox key fingerprint is invalid.');
  if (
    passToken !== undefined &&
    !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(passToken)
  ) {
    throw new Error('Admission pass is invalid.');
  }
  const url = new URL(`/join/${encodeURIComponent(code)}`, base.origin);
  const fragment = new URLSearchParams();
  if (passToken !== undefined) fragment.set('pass', passToken);
  if (fingerprint) fragment.set('key', fingerprint);
  if (fragment.size) url.hash = fragment.toString();
  return url.toString();
}

export function buildWorkshopEnrollmentUrl(origin: string, code: string, fingerprint: string | null, token: string) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('Workshop enrollment link is invalid.');
  try {
    const decoded = atob(token.replaceAll('-', '+').replaceAll('_', '/') + '=');
    const canonical = btoa(decoded).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
    if (decoded.length !== 32 || canonical !== token) throw new Error('invalid token');
  } catch {
    throw new Error('Workshop enrollment link is invalid.');
  }
  const url = new URL(buildInvitationUrl(origin, code, fingerprint));
  const fragment = new URLSearchParams(url.hash.slice(1));
  fragment.set('enroll', token);
  url.hash = fragment.toString();
  return url.toString();
}

export function setPublicOrigin(origin: string) { publicOrigin = origin; }
export function getPublicOrigin() { return publicOrigin; }

export function configuredPageUrl(origin: string, pathname: string, search = '', hash = ''): string {
  const target = new URL(origin);
  target.pathname = pathname;
  target.search = search;
  target.hash = hash;
  return target.toString();
}

export function isLocalOrigin(origin: string): boolean {
  const hostname = new URL(origin).hostname.toLowerCase();
  return hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '::1' || hostname === '[::1]' || hostname.startsWith('127.') || hostname === '0.0.0.0';
}

export async function loadPublicConfig(): Promise<{ publicOrigin: string }> {
  let response: Response;
  try {
    response = await fetch('/api/config', { credentials: 'same-origin', cache: 'no-store' });
  } catch {
    throw new Error('Could not load the invitation address. Check your connection and retry.');
  }
  if (!response.ok) throw new Error('Could not load the invitation address. Check your connection and retry.');
  let value: { publicOrigin?: unknown } | null;
  try { value = await response.json() as { publicOrigin?: unknown } | null; }
  catch { throw new Error('The server returned an invalid invitation address. Contact the site administrator.'); }
  if (!value || typeof value !== 'object' || typeof value.publicOrigin !== 'string')
    throw new Error('The server did not provide a valid invitation address. Contact the site administrator.');
  let url: URL;
  try { url = new URL(value.publicOrigin); } catch { throw new Error('The server invitation address is invalid. Contact the site administrator.'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash || url.origin !== value.publicOrigin)
    throw new Error('The server invitation address is invalid. Contact the site administrator.');
  if (window.location.protocol === 'https:' && url.protocol !== 'https:') throw new Error('The server invitation address must use HTTPS. Contact the site administrator.');
  return { publicOrigin: url.origin };
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public retryAfterSeconds = 0,
  ) {
    super(message);
  }
}

export async function api<T>(
  path: string,
  method = 'GET',
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    credentials: 'same-origin',
    signal,
    headers: {
      'Content-Type': 'application/json',
      ...(method !== 'GET' ? { 'X-CSRF-Token': csrfToken } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  if (response.status === 204) return undefined as T;
  const data = await response.json();
  if (!response.ok)
    throw new ApiError(
      response.status,
      data.error.code,
      data.error.message,
      Number(response.headers.get('Retry-After') ?? 0),
    );
  return data as T;
}

export async function apiBytes(
  path: string,
  method = 'GET',
  body?: Uint8Array,
  signal?: AbortSignal,
): Promise<{ bytes: Uint8Array; sha256: string }> {
  const response = await fetch(`/api${path}`, {
    method,
    credentials: 'same-origin',
    signal,
    headers: {
      ...(body ? { 'Content-Type': 'application/octet-stream' } : {}),
      ...(method !== 'GET' ? { 'X-CSRF-Token': csrfToken } : {}),
    },
    ...(body ? { body: Uint8Array.from(body).buffer } : {}),
  });
  if (!response.ok) {
    const data = await response.json();
    throw new ApiError(
      response.status,
      data.error.code,
      data.error.message,
      Number(response.headers.get('Retry-After') ?? 0),
    );
  }
  return {
    bytes: new Uint8Array(await response.arrayBuffer()),
    sha256: response.headers.get('X-Ciphertext-SHA256') ?? '',
  };
}

export async function startSession() {
  const session = await api<{ csrfToken: string }>('/session', 'POST');
  csrfToken = session.csrfToken;
}

export async function searchPlaces(query: string) {
  const response = await api<{ results: PlaceSuggestion[] }>(
    `/geo/search?q=${encodeURIComponent(query)}`,
  );
  return response.results;
}

export interface GeoFix {
  lat: number;
  lng: number;
  accuracyM: number;
  timestamp: string;
}

function readOnce(timeoutMs: number): Promise<GeoFix> {
  return new Promise((resolve, reject) => {
    if (!('geolocation' in navigator)) {
      reject(new Error('Location is not supported on this device or browser.'));
      return;
    }
    const timer = setTimeout(() => reject(new Error('Location timed out. Try again near a window or outdoors.')), timeoutMs);
    navigator.geolocation.getCurrentPosition(
      (position) => {
        clearTimeout(timer);
        resolve({
          lat: position.coords.latitude,
          lng: position.coords.longitude,
          accuracyM: position.coords.accuracy,
          timestamp: new Date(position.timestamp).toISOString(),
        });
      },
      (error) => {
        clearTimeout(timer);
        if (error.code === error.PERMISSION_DENIED)
          reject(new Error('Location permission was denied. Allow location access and try again.'));
        else if (error.code === error.POSITION_UNAVAILABLE)
          reject(new Error('Location is unavailable. Try again near a window or outdoors.'));
        else reject(new Error('Location timed out. Try again.'));
      },
      { enableHighAccuracy: true, maximumAge: 0, timeout: timeoutMs },
    );
  });
}

export async function requestFix(): Promise<GeoFix> {
  const samples: GeoFix[] = [];
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      samples.push(await readOnce(9000));
    } catch (error) {
      if (samples.length === 0 && attempt === 2) throw error;
      if (samples.length > 0) break;
    }
  }
  const middle = (values: number[]) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
  return {
    lat: middle(samples.map((sample) => sample.lat)),
    lng: middle(samples.map((sample) => sample.lng)),
    accuracyM: middle(samples.map((sample) => sample.accuracyM)),
    timestamp: samples[samples.length - 1].timestamp,
  };
}
