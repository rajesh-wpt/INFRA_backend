// lib/webLinkQr.ts
// Pure helpers for the Web-linking QR (BE-6.1 / WEB-R1.0). No React Native imports so they can be unit-tested.
//
// QR payload shown by Web:
//   JSON : {"version":1,"type":"sealine_web_link","token":"<32-256 chars [A-Za-z0-9_-]>","wsUrl":"https://<backend>"}
//   or   : the raw token string itself (32-256 chars [A-Za-z0-9_-])

export type WebLinkQr = { token: string; wsUrl: string | null };

const TOKEN_RE = /^[A-Za-z0-9_-]{32,256}$/;

export function parseWebLinkQr(raw: string): WebLinkQr | null {
  // BE-6.1: some Web builds put the RAW token in the QR (no JSON wrapper). The phone sends it to its own backend.
  const bare = raw.trim();
  if (TOKEN_RE.test(bare)) return { token: bare, wsUrl: null };

  let data: unknown;
  try {
    data = JSON.parse(raw.trim());
  } catch {
    return null;
  }
  if (!data || typeof data !== 'object') return null;
  const o = data as Record<string, unknown>;
  if (o.type !== 'sealine_web_link' || o.version !== 1) return null;
  if (typeof o.token !== 'string' || !TOKEN_RE.test(o.token)) return null;
  return { token: o.token, wsUrl: typeof o.wsUrl === 'string' ? o.wsUrl : null };
}

export function normalizeOrigin(url: string): string | null {
  try {
    const u = new URL(url.trim());
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return `${u.protocol}//${u.host}`.toLowerCase();
  } catch {
    return null;
  }
}

/** True when the QR was generated for the same backend this app is configured to talk to. */
export function sameBackend(qrWsUrl: string | null, appBackendUrl: string): boolean {
  if (!qrWsUrl) return true; // older QR without wsUrl: nothing to compare
  const a = normalizeOrigin(qrWsUrl);
  const b = normalizeOrigin(appBackendUrl);
  return a !== null && a === b;
}
