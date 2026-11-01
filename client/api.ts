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

// A misdirected request (for example, the dev proxy pointing at a port another
// service owns) answers with HTML or an empty body. Report that plainly instead
// of surfacing the browser's "JSON.parse: unexpected character" message.
async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(
      response.status,
      'INVALID_RESPONSE',
      `The API answered HTTP ${response.status} without JSON. Check that the API is running on the port the frontend calls.`,
    );
  }
}

async function fetchApi(input: string, init: RequestInit) {
  try { return await fetch(input, init); }
  catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError(0, 'NETWORK_UNAVAILABLE', 'Cannot reach Portkey. Check your connection and retry. Saved uploads remain in this browser.');
  }
}

export async function api<T>(
  path: string,
  method = 'GET',
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetchApi(`/api${path}`, {
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
  const data = await readJson(response);
  if (!response.ok) {
    const error = (data as { error?: { code?: string; message?: string } }).error;
    throw new ApiError(
      response.status,
      error?.code ?? 'INVALID_RESPONSE',
      error?.message ?? `The API answered HTTP ${response.status}.`,
      Number(response.headers.get('Retry-After') ?? 0),
    );
  }
  return data as T;
}

export async function apiBytes(
  path: string,
  method = 'GET',
  body?: Uint8Array,
  signal?: AbortSignal,
): Promise<{ bytes: Uint8Array; sha256: string }> {
  const response = await fetchApi(`/api${path}`, {
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
    const data = (await readJson(response)) as { error: { code: string; message: string } };
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

export { requestFix, type GeoFix } from './location.js';
