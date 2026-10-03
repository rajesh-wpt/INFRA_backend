// api/linkingApi.ts
//
// BE-6.1 — phone side of Web linking: confirm a scanned Web QR.
//
//   POST {BACKEND_URL}/api/v1/linking/scan   { token }   Authorization: Bearer <phone access token>
//
// SECURITY: the request ALWAYS goes to this app's own configured BACKEND_URL. The `wsUrl` inside a QR is
// untrusted input and is only compared, never used as a destination — otherwise a hostile QR could make the
// phone send its access token to an attacker's server.

import * as SecureStore from 'expo-secure-store';

const BACKEND_URL =
  process.env.EXPO_PUBLIC_BACKEND_URL ?? 'http://localhost:4000';

export const LINKING_BACKEND_URL = BACKEND_URL;

export type LinkResult =
  | { ok: true }
  | { ok: false; reason: 'expired' | 'unauthorized' | 'rate_limited' | 'network' | 'server'; message: string };

async function postScan(token: string, accessToken: string | null): Promise<Response> {
  return fetch(`${BACKEND_URL}/api/v1/linking/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify({ token }),
  });
}

/**
 * The 1h access token may be stale. Refresh tokens ROTATE: the response carries a NEW refreshToken that must be
 * stored, otherwise the next refresh is treated as reuse and every session in the family is revoked.
 */
async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = await SecureStore.getItemAsync('refreshToken');
  if (!refreshToken) return null;

  const res = await fetch(`${BACKEND_URL}/api/v1/onboarding/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken }),
  });
  if (!res.ok) return null;

  const data = (await res.json()) as { accessToken?: string; refreshToken?: string };
  if (!data.accessToken || !data.refreshToken) return null;

  await SecureStore.setItemAsync('accessToken', data.accessToken);
  await SecureStore.setItemAsync('refreshToken', data.refreshToken);
  return data.accessToken;
}

export async function confirmWebLink(token: string): Promise<LinkResult> {
  try {
    let accessToken = await SecureStore.getItemAsync('accessToken');
    let res = await postScan(token, accessToken);

    if (res.status === 401) {
      accessToken = await refreshAccessToken();
      if (!accessToken) {
        return { ok: false, reason: 'unauthorized', message: 'Your session has expired. Please log in again.' };
      }
      res = await postScan(token, accessToken);
    }

    if (res.ok) return { ok: true };
    if (res.status === 410) {
      return { ok: false, reason: 'expired', message: 'This QR code expired or was already used. Refresh the QR on the web page and scan again.' };
    }
    if (res.status === 401) {
      return { ok: false, reason: 'unauthorized', message: 'Your session has expired. Please log in again.' };
    }
    if (res.status === 429) {
      return { ok: false, reason: 'rate_limited', message: 'Too many attempts. Wait a minute and try again.' };
    }
    return { ok: false, reason: 'server', message: `Linking failed (HTTP ${res.status}). Please try again.` };
  } catch {
    return {
      ok: false,
      reason: 'network',
      message: `Cannot reach the server at ${BACKEND_URL}. Check that this phone can open that address.`,
    };
  }
}
