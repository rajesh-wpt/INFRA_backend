import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * At-rest encryption for the OTP payload handed to the self-hosted SMS gateway.
 *
 * Why this exists
 * ---------------
 * `sms_outbox` must not contain a recoverable OTP in plaintext: a database
 * dump would hand an attacker every live login code. But the gateway needs the
 * real digits to put in an SMS, and the verification table only stores a
 * one-way SHA-256 hash. So the code is stored as AES-256-GCM ciphertext,
 * readable only with `SMS_PAYLOAD_KEY`, and the ciphertext is cleared the
 * moment the gateway acknowledges dispatch.
 *
 * Threat model: protects against a database-only compromise. It does not
 * protect against an attacker who also holds the application environment
 * (they can decrypt, and they can already mint OTPs).
 *
 * Wire format: `v1.<iv b64>.<tag b64>.<ciphertext b64>`
 */

const ALGORITHM = "aes-256-gcm";
const VERSION = "v1";
const KEY_BYTES = 32;
const IV_BYTES = 12;

function loadKey(): Buffer | null {
  const raw = process.env.SMS_PAYLOAD_KEY?.trim();
  if (!raw) return null;

  const key = /^[0-9a-fA-F]{64}$/.test(raw)
    ? Buffer.from(raw, "hex")
    : Buffer.from(raw, "base64");

  if (key.length !== KEY_BYTES) {
    throw new Error(
      `SMS_PAYLOAD_KEY must decode to ${KEY_BYTES} bytes (got ${key.length}); use 64 hex chars or base64`,
    );
  }
  return key;
}

/**
 * Encrypt an OTP for storage in `sms_outbox.payload`.
 *
 * Returns null when no key is configured: the row is still created and the
 * gateway sees no code, which keeps local development working without
 * inventing a key (and without silently storing plaintext).
 */
export function encryptOtpPayload(code: string): string | null {
  const key = loadKey();
  if (!key) return null;

  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(code, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [
    VERSION,
    iv.toString("base64"),
    tag.toString("base64"),
    ciphertext.toString("base64"),
  ].join(".");
}

/**
 * Decrypt a payload produced by {@link encryptOtpPayload}.
 *
 * Returns null for absent/malformed/tampered payloads or when no key is
 * configured. Never throws: a bad row must not take down the poll endpoint.
 */
export function decryptOtpPayload(payload: string | null | undefined): string | null {
  if (!payload) return null;

  const key = loadKey();
  if (!key) return null;

  const parts = payload.split(".");
  if (parts.length !== 4 || parts[0] !== VERSION) return null;

  const [, ivB64, tagB64, ciphertextB64] = parts;
  if (!ivB64 || !tagB64 || !ciphertextB64) return null;

  try {
    const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(ivB64, "base64"));
    decipher.setAuthTag(Buffer.from(tagB64, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(ciphertextB64, "base64")),
      decipher.final(),
    ]);
    return plaintext.toString("utf8");
  } catch {
    return null;
  }
}
