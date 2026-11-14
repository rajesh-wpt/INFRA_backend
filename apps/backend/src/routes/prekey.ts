/**
 * ENC-4.1 / ENC-4.2 — Prekey distribution.
 *
 * ENC-4.1 — the server holds PUBLIC prekeys only. Devices generate their
 * identity key, signed prekey and one-time prekey batches locally and upload
 * the public halves here; the server stores them, serves them, expires stale
 * ones, and tells the device when to refill. It never generates key material
 * (Tech Arch §8.8).
 *
 * ENC-4.2 — `POST /prekey-bundle/:deviceId` returns everything a sender needs
 * to start an X3DH session with a recipient device:
 *   - the recipient device's identity public key
 *   - its current signed prekey (+ identity signature)
 *   - ONE one-time prekey, deleted in the same transaction it is served in
 *
 * SECURITY:
 *   - Both routers are mounted behind `requireAuth` (app audience) — neither
 *     is public.
 *   - The one-time prekey is selected with `FOR UPDATE SKIP LOCKED` and
 *     hard-deleted immediately, so the same key can never be handed out twice,
 *     even to concurrent requesters.
 *   - Only public key material is ever accepted or returned. Session state
 *     lives entirely client-side (§8.4); the backend's role begins and ends at
 *     distribution.
 */

import { Router, type Request, type Response } from "express";
import { sql } from "drizzle-orm";
import { getDb } from "../db/index.js";

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Same format the DB CHECK constraints enforce; validated here for clean 400s. */
const KEY_RE = /^[A-Za-z0-9/+=_-]{40,128}$/;

/** A device batch is 100 one-time keys; it is refilled once it drops below 20. */
export const ONE_TIME_BATCH_SIZE = 100;
export const ONE_TIME_REPLENISH_THRESHOLD = 20;
/** Signed prekey rotation cadence (Tech Arch §8.3). */
export const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;

type DeviceRow = { id: string; user_id: string; identity_public_key: string | null };
type OneTimeRow = { id: string; key_id: number; public_key: string };
type CountRow = { n: number };

/** The authenticated app device (set by requireAuth from the access token). */
function authContext(res: Response): { userId: string; deviceId: string } | null {
  const auth = res.locals.auth as { sub?: string; deviceId?: string } | undefined;
  if (!auth?.sub || !auth.deviceId) return null;
  return { userId: auth.sub, deviceId: auth.deviceId };
}

function decodeBase64Key(value: unknown, expectedBytes?: number): Buffer | null {
  if (typeof value !== "string" || !KEY_RE.test(value)) return null;
  const bytes = Buffer.from(value, "base64");
  if (bytes.length === 0) return null;
  // Reject non-canonical base64 (Buffer.from silently ignores trailing garbage).
  if (bytes.toString("base64") !== value) return null;
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) return null;
  return bytes;
}

function validKeyId(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 2_147_483_647;
}

// ─────────────────────────────────────────────────────────────────────────────
// Device-facing upload / status router (mounted at /api/v1/prekeys)
// ─────────────────────────────────────────────────────────────────────────────

export const prekeysRouter: Router = Router();

/**
 * POST /prekeys/upload
 *
 * Body:
 *   identityPublicKey?  base64 (32 bytes) — required on the first upload
 *   signedPrekey?       { keyId, publicKey, signature }
 *   oneTimePrekeys?     [{ keyId, publicKey }]  (max 100)
 *
 * Both key fields are optional so a device can rotate the signed prekey and
 * refill one-time keys independently. At least one must be present.
 *
 * Idempotent: re-uploading an identical signed prekey is a no-op; identical
 * one-time keys are skipped, not duplicated. A different public key under an
 * already-used keyId is rejected (409) rather than silently replacing it.
 */
prekeysRouter.post("/upload", async (req: Request, res: Response) => {
  try {
    const ctx = authContext(res);
    if (!ctx) {
      res.status(401).json({ success: false, error: "TOKEN_REQUIRED" });
      return;
    }

    const body = req.body as {
      identityPublicKey?: unknown;
      signedPrekey?: unknown;
      oneTimePrekeys?: unknown;
    };

    // ── identity key (optional; required if the device has none yet) ──
    let identityPublicKey: string | null = null;
    if (body.identityPublicKey !== undefined && body.identityPublicKey !== null) {
      if (!decodeBase64Key(body.identityPublicKey, 32)) {
        res.status(400).json({
          success: false,
          error: "INVALID_IDENTITY_KEY",
          message: "identityPublicKey must be a base64-encoded 32-byte X25519 public key",
        });
        return;
      }
      identityPublicKey = body.identityPublicKey as string;
    }

    // ── signed prekey (optional) ──
    let signed: { keyId: number; publicKey: string; signature: string } | null = null;
    if (body.signedPrekey !== undefined && body.signedPrekey !== null) {
      const sp = body.signedPrekey as { keyId?: unknown; publicKey?: unknown; signature?: unknown };
      if (!validKeyId(sp.keyId) || !decodeBase64Key(sp.publicKey, 32) || !decodeBase64Key(sp.signature)) {
        res.status(400).json({
          success: false,
          error: "INVALID_SIGNED_PREKEY",
          message:
            "signedPrekey must be { keyId:int, publicKey: base64 32-byte key, signature: base64 signature }",
        });
        return;
      }
      signed = { keyId: sp.keyId, publicKey: sp.publicKey as string, signature: sp.signature as string };
    }

    // ── one-time prekeys (optional) ──
    const oneTime: Array<{ keyId: number; publicKey: string }> = [];
    if (body.oneTimePrekeys !== undefined && body.oneTimePrekeys !== null) {
      if (!Array.isArray(body.oneTimePrekeys)) {
        res.status(400).json({ success: false, error: "INVALID_ONE_TIME_PREKEYS" });
        return;
      }
      if (body.oneTimePrekeys.length > ONE_TIME_BATCH_SIZE) {
        res.status(400).json({
          success: false,
          error: "PREKEY_BATCH_TOO_LARGE",
          message: `oneTimePrekeys may contain at most ${ONE_TIME_BATCH_SIZE} keys per request`,
        });
        return;
      }
      const seen = new Set<number>();
      for (const raw of body.oneTimePrekeys as unknown[]) {
        const otp = raw as { keyId?: unknown; publicKey?: unknown };
        if (!validKeyId(otp.keyId) || !decodeBase64Key(otp.publicKey, 32)) {
          res.status(400).json({
            success: false,
            error: "INVALID_ONE_TIME_PREKEY",
            message: "each one-time prekey must be { keyId:int, publicKey: base64 32-byte key }",
          });
          return;
        }
        if (seen.has(otp.keyId)) {
          res.status(400).json({ success: false, error: "DUPLICATE_KEY_ID" });
          return;
        }
        seen.add(otp.keyId);
        oneTime.push({ keyId: otp.keyId, publicKey: otp.publicKey as string });
      }
    }

    if (!identityPublicKey && !signed && oneTime.length === 0) {
      res.status(400).json({
        success: false,
        error: "NOTHING_TO_UPLOAD",
        message: "provide identityPublicKey, signedPrekey and/or oneTimePrekeys",
      });
      return;
    }

    const db = getDb();

    const outcome = await db.transaction(async (tx) => {
      // Serialize uploads per device: two concurrent refills must not each
      // believe the pool is empty and push it past the batch size.
      const deviceRows = (await tx.execute(
        sql`SELECT id, user_id, identity_public_key
            FROM devices
            WHERE id = ${ctx.deviceId}
            FOR UPDATE`,
      )) as unknown as { rows: DeviceRow[] };
      const device = deviceRows.rows[0];

      if (!device || device.user_id !== ctx.userId) {
        return { kind: "device_not_found" } as const;
      }

      // An identity key is the trust anchor of every bundle this device
      // serves. Allow setting it once; a later different value is a key swap
      // and must go through re-linking, not a silent overwrite.
      if (identityPublicKey) {
        if (device.identity_public_key && device.identity_public_key !== identityPublicKey) {
          return { kind: "identity_mismatch" } as const;
        }
        if (!device.identity_public_key) {
          await tx.execute(
            sql`UPDATE devices SET identity_public_key = ${identityPublicKey} WHERE id = ${ctx.deviceId}`,
          );
        }
      }

      const identityAfter = device.identity_public_key ?? identityPublicKey;
      if (!identityAfter && (signed || oneTime.length > 0)) {
        // A signature nobody can verify, and keys tied to no identity, are
        // useless: refuse to accept prekeys before the identity key exists.
        return { kind: "identity_required" } as const;
      }

      let signedStored = false;
      if (signed) {
        const existing = (await tx.execute(
          sql`SELECT key_id, public_key FROM signed_prekeys
              WHERE device_id = ${ctx.deviceId} AND key_id = ${signed.keyId} LIMIT 1`,
        )) as unknown as { rows: { key_id: number; public_key: string }[] };

        if (existing.rows[0]) {
          if (existing.rows[0].public_key !== signed.publicKey) {
            return { kind: "signed_key_id_reused" } as const;
          }
        } else {
          await tx.execute(
            sql`INSERT INTO signed_prekeys (device_id, key_id, public_key, signature)
                VALUES (${ctx.deviceId}, ${signed.keyId}, ${signed.publicKey}, ${signed.signature})`,
          );
          signedStored = true;
        }

        // Weekly rotation keeps exactly ONE signed prekey per device; anything
        // older (lower key id) is dead weight and is pruned in the same tx.
        await tx.execute(
          sql`DELETE FROM signed_prekeys
              WHERE device_id = ${ctx.deviceId} AND key_id < ${signed.keyId}`,
        );
      }

      let inserted = 0;
      if (oneTime.length > 0) {
        const countRows = (await tx.execute(
          sql`SELECT count(*)::int AS n FROM one_time_prekeys
              WHERE device_id = ${ctx.deviceId} AND consumed_at IS NULL`,
        )) as unknown as { rows: CountRow[] };
        const available = countRows.rows[0]?.n ?? 0;
        if (available + oneTime.length > ONE_TIME_BATCH_SIZE) {
          return { kind: "batch_full", available } as const;
        }

        const batchJson = JSON.stringify(
          oneTime.map((k) => ({ key_id: k.keyId, public_key: k.publicKey })),
        );
        const insertedRows = (await tx.execute(
          sql`INSERT INTO one_time_prekeys (device_id, key_id, public_key)
              SELECT ${ctx.deviceId}::uuid, k.key_id, k.public_key
              FROM jsonb_to_recordset(${batchJson}::jsonb) AS k(key_id int, public_key text)
              ON CONFLICT (device_id, key_id) DO NOTHING
              RETURNING key_id`,
        )) as unknown as { rows: { key_id: number }[] };
        inserted = insertedRows.rows.length;
      }

      const after = (await tx.execute(
        sql`SELECT count(*)::int AS n FROM one_time_prekeys
            WHERE device_id = ${ctx.deviceId} AND consumed_at IS NULL`,
      )) as unknown as { rows: CountRow[] };
      const unconsumed = after.rows[0]?.n ?? 0;

      const newestSigned = (await tx.execute(
        sql`SELECT created_at FROM signed_prekeys
            WHERE device_id = ${ctx.deviceId}
            ORDER BY key_id DESC LIMIT 1`,
      )) as unknown as { rows: { created_at: Date | string }[] };
      const signedAt = newestSigned.rows[0]?.created_at;

      return {
        kind: "ok",
        signedStored,
        inserted,
        skipped: oneTime.length - inserted,
        unconsumed,
        needsReplenish: unconsumed < ONE_TIME_REPLENISH_THRESHOLD,
        signedPrekeyAgeMs: signedAt ? Date.now() - new Date(signedAt).getTime() : null,
        needsSignedRotation: signedAt
          ? Date.now() - new Date(signedAt).getTime() >= SIGNED_PREKEY_ROTATION_MS
          : true,
      } as const;
    });

    if (outcome.kind === "device_not_found") {
      res.status(404).json({ success: false, error: "DEVICE_NOT_FOUND" });
      return;
    }
    if (outcome.kind === "identity_mismatch") {
      res.status(409).json({
        success: false,
        error: "IDENTITY_KEY_MISMATCH",
        message:
          "This device already has a different identity public key; re-link the device to rotate it",
      });
      return;
    }
    if (outcome.kind === "identity_required") {
      res.status(409).json({
        success: false,
        error: "IDENTITY_KEY_REQUIRED",
        message: "Upload identityPublicKey before signed or one-time prekeys",
      });
      return;
    }
    if (outcome.kind === "signed_key_id_reused") {
      res.status(409).json({
        success: false,
        error: "SIGNED_KEY_ID_REUSED",
        message: "That keyId already maps to a different public key",
      });
      return;
    }
    if (outcome.kind === "batch_full") {
      res.status(409).json({
        success: false,
        error: "PREKEY_BATCH_FULL",
        message: `The device already holds ${outcome.available} unconsumed one-time prekeys (batch size ${ONE_TIME_BATCH_SIZE})`,
      });
      return;
    }

    res.json({
      success: true,
      stored: {
        signedPrekey: outcome.signedStored,
        oneTimePrekeys: outcome.inserted,
        skippedOneTimePrekeys: outcome.skipped,
      },
      status: {
        unconsumedOneTimePrekeys: outcome.unconsumed,
        needsReplenish: outcome.needsReplenish,
        signedPrekeyAgeMs: outcome.signedPrekeyAgeMs,
        needsSignedRotation: outcome.needsSignedRotation,
      },
    });
  } catch (err) {
    console.error("POST /prekeys/upload error", err);
    res.status(500).json({ success: false, error: "INTERNAL_ERROR" });
  }
});

/** GET /prekeys/status — what this device still needs to upload. */
prekeysRouter.get("/status", async (_req: Request, res: Response) => {
  try {
    const ctx = authContext(res);
    if (!ctx) {
      res.status(401).json({ success: false, error: "TOKEN_REQUIRED" });
      return;
    }

    const db = getDb();

    const deviceRows = (await db.execute(
      sql`SELECT id, identity_public_key FROM devices
          WHERE id = ${ctx.deviceId} AND user_id = ${ctx.userId} AND is_active = true
            AND revoked_at IS NULL`,
    )) as unknown as { rows: DeviceRow[] };
    const device = deviceRows.rows[0];
    if (!device) {
      res.status(404).json({ success: false, error: "DEVICE_NOT_FOUND" });
      return;
    }

    const countRows = (await db.execute(
      sql`SELECT count(*)::int AS n FROM one_time_prekeys
          WHERE device_id = ${ctx.deviceId} AND consumed_at IS NULL`,
    )) as unknown as { rows: CountRow[] };
    const unconsumed = countRows.rows[0]?.n ?? 0;

    const signedRows = (await db.execute(
      sql`SELECT key_id, created_at FROM signed_prekeys
          WHERE device_id = ${ctx.deviceId} ORDER BY key_id DESC LIMIT 1`,
    )) as unknown as { rows: { key_id: number; created_at: Date | string }[] };
    const current = signedRows.rows[0];
    const ageMs = current ? Date.now() - new Date(current.created_at).getTime() : null;

    res.json({
      success: true,
      status: {
        hasIdentityKey: Boolean(device.identity_public_key),
        unconsumedOneTimePrekeys: unconsumed,
        oneTimeBatchSize: ONE_TIME_BATCH_SIZE,
        oneTimeReplenishThreshold: ONE_TIME_REPLENISH_THRESHOLD,
        needsReplenish: unconsumed < ONE_TIME_REPLENISH_THRESHOLD,
        currentSignedPrekeyId: current?.key_id ?? null,
        signedPrekeyAgeMs: ageMs,
        needsSignedRotation: ageMs === null || ageMs >= SIGNED_PREKEY_ROTATION_MS,
      },
    });
  } catch (err) {
    console.error("GET /prekeys/status error", err);
    res.status(500).json({ success: false, error: "INTERNAL_ERROR" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Bundle fetch router (mounted at /api/v1/prekey-bundle)
// ─────────────────────────────────────────────────────────────────────────────

export const bundleRouter: Router = Router();

/** POST /prekey-bundle/:deviceId — see the file header. */
bundleRouter.post("/:deviceId", async (req: Request, res: Response) => {
  try {
    const rawDeviceId = req.params.deviceId;
    if (typeof rawDeviceId !== "string" || !UUID_RE.test(rawDeviceId)) {
      res.status(400).json({
        success: false,
        error: "INVALID_DEVICE_ID",
        message: "deviceId must be a UUID",
      });
      return;
    }
    const deviceId = rawDeviceId;

    const db = getDb();

    const outcome = await db.transaction(async (tx) => {
      const deviceRows = (await tx.execute(
        sql`SELECT id, identity_public_key FROM devices
            WHERE id = ${deviceId} AND is_active = true AND revoked_at IS NULL
            LIMIT 1`,
      )) as unknown as { rows: { id: string; identity_public_key: string | null }[] };
      const device = deviceRows.rows[0];

      if (!device || !device.identity_public_key) {
        return { kind: "not_found" } as const;
      }

      const signedRows = (await tx.execute(
        sql`SELECT key_id, public_key, signature, created_at
            FROM signed_prekeys
            WHERE device_id = ${deviceId}
            ORDER BY key_id DESC
            LIMIT 1`,
      )) as unknown as {
        rows: { key_id: number; public_key: string; signature: string; created_at: Date | string }[];
      };
      const signed = signedRows.rows[0];
      if (!signed) {
        return { kind: "no_signed_prekey" } as const;
      }

      // Reserve exactly one unconsumed one-time prekey. SKIP LOCKED makes two
      // concurrent requesters take two DIFFERENT rows; with a single row left,
      // the loser gets none and we report the pool as exhausted rather than
      // reusing the same key.
      const result = (await tx.execute(
        sql`SELECT id, key_id, public_key
            FROM one_time_prekeys
            WHERE device_id = ${deviceId} AND consumed_at IS NULL
            ORDER BY key_id
            LIMIT 1
            FOR UPDATE SKIP LOCKED`,
      )) as unknown as { rows: OneTimeRow[] };
      const oneTime = result.rows[0];

      if (!oneTime) {
        // Pool exhausted — new session establishment is blocked until the
        // device refills (§8.3). Surface it distinctly rather than serving a
        // degraded bundle.
        return { kind: "no_one_time_prekey" } as const;
      }

      // The row leaves the pool in the same transaction that serves it, so the
      // same key can never be handed out twice.
      await tx.execute(sql`DELETE FROM one_time_prekeys WHERE id = ${oneTime.id}`);

      // Refill hint rides along on every bundle: the sender cannot act on it,
      // but the response is a convenient place to surface it to instrumented
      // recipients during a call. Never leaks private material.
      const remainingRows = (await tx.execute(
        sql`SELECT count(*)::int AS n FROM one_time_prekeys
            WHERE device_id = ${deviceId} AND consumed_at IS NULL`,
      )) as unknown as { rows: CountRow[] };

      return {
        kind: "ok",
        bundle: {
          deviceId,
          identityKey: device.identity_public_key,
          signedPrekey: {
            keyId: signed.key_id,
            publicKey: signed.public_key,
            signature: signed.signature,
            createdAt: new Date(signed.created_at).toISOString(),
          },
          oneTimePrekey: {
            keyId: oneTime.key_id,
            publicKey: oneTime.public_key,
          },
        },
        remainingOneTimePrekeys: remainingRows.rows[0]?.n ?? 0,
      } as const;
    });

    if (outcome.kind === "not_found") {
      res.status(404).json({
        success: false,
        error: "DEVICE_NOT_FOUND",
        message: "No active recipient device with that id",
      });
      return;
    }
    if (outcome.kind === "no_signed_prekey") {
      res.status(409).json({
        success: false,
        error: "NO_SIGNED_PREKEY",
        message: "Recipient device has no signed prekey provisioned",
      });
      return;
    }
    if (outcome.kind === "no_one_time_prekey") {
      res.status(409).json({
        success: false,
        error: "NO_ONE_TIME_PREKEY",
        message: "Recipient device's one-time prekey pool is exhausted",
      });
      return;
    }

    res.json({
      success: true,
      bundle: outcome.bundle,
      remainingOneTimePrekeys: outcome.remainingOneTimePrekeys,
      recipientNeedsReplenish: outcome.remainingOneTimePrekeys < ONE_TIME_REPLENISH_THRESHOLD,
    });
  } catch (err) {
    console.error("POST /prekey-bundle/:deviceId error", err);
    res.status(500).json({ success: false, error: "INTERNAL_ERROR" });
  }
});
