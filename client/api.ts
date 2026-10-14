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
