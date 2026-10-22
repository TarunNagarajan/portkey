export interface PortkeyCallback { code?: string; state?: string; error?: string }

export function readPortkeyCallback(): PortkeyCallback {
  const values = new URLSearchParams(window.location.hash.slice(1));
  const callback: PortkeyCallback = {
    ...(values.get('code') ? { code: values.get('code')! } : {}),
    ...(values.get('state') ? { state: values.get('state')! } : {}),
    ...(values.get('error') ? { error: values.get('error')! } : {}),
  };
  window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
  return callback;
}
