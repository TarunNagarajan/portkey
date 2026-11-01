export interface PortkeyCallback { code?: string; state?: string; error?: string }

export function readPortkeyCallback(): PortkeyCallback {
  const fragment = window.location.hash.slice(1);
  // Remove the one-use values before parsing or starting any asynchronous work.
  window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
  const values = new URLSearchParams(fragment);
  const callback: PortkeyCallback = {
    ...(values.get('code') ? { code: values.get('code')! } : {}),
    ...(values.get('state') ? { state: values.get('state')! } : {}),
    ...(values.get('error') ? { error: values.get('error')! } : {}),
  };
  return callback;
}
