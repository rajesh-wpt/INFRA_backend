/**
 * ENC-4.5 — Short-lived download URLs for encrypted group icons.
 *
 * Group icons travel through the E2EE media pipeline: the client encrypts the
 * image, uploads the ciphertext, and stores the storage pointer in
 * `groups.encrypted_icon_ref`. The backend NEVER sees the plaintext — it only
 * hands a member a short-lived URL for the ciphertext blob.
 *
 * Two drivers:
 *
 *   supabase  SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY are set. Ask Supabase
 *             Storage for a signed download URL (the original implementation).
 *
 *   local     Default when Supabase credentials are absent (dev / self-host).
 *             The backend signs an HMAC URL pointing at its own media route and
 *             serves the blob from MEDIA_ROOT. No third-party account needed.
 *
 * Selection happens per call, so a deployment can switch by setting the env
 * without touching code.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export type StorageDriver = "supabase" | "local";

/** Only allow simple, traversal-free object names. */
export const MEDIA_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function storageDriver(): StorageDriver {
  return process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY
    ? "supabase"
    : "local";
}

function mediaRoot(): string {
  const configured = process.env.MEDIA_ROOT?.trim();
  return resolve(configured && configured.length > 0 ? configured : "var/media");
}

function mediaUrlSecret(): string {
  const secret = process.env.MEDIA_URL_SECRET ?? process.env.JWT_SECRET;
  if (!secret) {
    throw new Error(
      "MEDIA_URL_SECRET (or JWT_SECRET) must be set to sign media URLs",
    );
  }
  return secret;
}

function publicBaseUrl(): string {
  const configured = process.env.PUBLIC_BASE_URL?.trim();
  if (configured) return configured.replace(/\/+$/, "");
  return `http://localhost:${process.env.PORT ?? 4000}`;
}

function signMediaPath(bucket: string, name: string, expiresAtSec: number): string {
  return createHmac("sha256", mediaUrlSecret())
    .update(`${bucket}/${name}:${expiresAtSec}`)
    .digest("hex");
}

/** Constant-time check of a media download token. */
export function verifyMediaToken(
  bucket: string,
  name: string,
  expiresAtSec: number,
  signature: string,
): { ok: true } | { ok: false; reason: "expired" | "bad_signature" } {
  if (!Number.isFinite(expiresAtSec) || expiresAtSec * 1000 <= Date.now()) {
    return { ok: false, reason: "expired" };
  }
  const expected = signMediaPath(bucket, name, expiresAtSec);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(signature, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { ok: false, reason: "bad_signature" };
  }
  return { ok: true };
}

async function supabaseSignedUrl(
  bucket: string,
  path: string,
  expiresInSec: number,
): Promise<string | null> {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;

  const endpoint = `${url}/storage/v1/object/sign/${encodeURIComponent(bucket)}/${path}`;
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ expiresIn: expiresInSec }),
    });
    if (!res.ok) {
      console.error(
        "createSignedUrl: storage returned",
        res.status,
        (await res.text()).slice(0, 200),
      );
      return null;
    }
    const data = (await res.json()) as { signedUrl?: string; signedURL?: string };
    const signedUrl = data.signedUrl ?? data.signedURL;
    if (!signedUrl) {
      console.error(
        "createSignedUrl: no signedUrl in response:",
        JSON.stringify(data).slice(0, 200),
      );
      return null;
    }
    // Supabase returns a path-relative URL; the client joins it onto SUPABASE_URL.
    return signedUrl;
  } catch (err) {
    console.error("createSignedUrl failed:", err);
    return null;
  }
}

/**
 * Produce a short-lived signed download URL for a private storage object.
 * Returns null if the object cannot be addressed (caller maps to 500/404).
 */
export async function createSignedUrl(
  bucket: string,
  path: string,
  expiresInSec = 3600,
): Promise<string | null> {
  if (!MEDIA_NAME_RE.test(path)) return null;

  if (storageDriver() === "supabase") {
    return supabaseSignedUrl(bucket, path, expiresInSec);
  }

  const expiresAtSec = Math.floor(Date.now() / 1000) + expiresInSec;
  const signature = signMediaPath(bucket, path, expiresAtSec);
  const query = new URLSearchParams({
    exp: String(expiresAtSec),
    sig: signature,
  });
  return `${publicBaseUrl()}/api/v1/media/${encodeURIComponent(bucket)}/${path}?${query.toString()}`;
}

/** Absolute path of a local object, or null when the name is unsafe. */
export function localObjectPath(bucket: string, name: string): string | null {
  if (!MEDIA_NAME_RE.test(name)) return null;
  if (!MEDIA_NAME_RE.test(bucket)) return null;
  return join(mediaRoot(), bucket, name);
}

/** Write a local object (dev/self-host upload path). */
export function putLocalObject(bucket: string, name: string, bytes: Buffer): string | null {
  const target = localObjectPath(bucket, name);
  if (!target) return null;
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  writeFileSync(target, bytes, { mode: 0o600 });
  return target;
}

/** Read a local object, or null when it does not exist. */
export function readLocalObject(bucket: string, name: string): Buffer | null {
  const target = localObjectPath(bucket, name);
  if (!target || !existsSync(target)) return null;
  return readFileSync(target);
}
