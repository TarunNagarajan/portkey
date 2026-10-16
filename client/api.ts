import type { PlaceSuggestion } from '../shared/rooms.js';

let csrfToken = '';

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
