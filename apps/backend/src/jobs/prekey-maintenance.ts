/**
 * ENC-4.1 — Prekey maintenance job.
 *
 * Run manually:  pnpm --filter @wpt/backend exec tsx src/jobs/prekey-maintenance.ts
 * Or leave it to the in-process scheduler (src/jobs/scheduler.ts), enabled
 * unless PREKEY_MAINTENANCE_INTERVAL_MS=0.
 *
 * Responsibilities (Tech Arch §8.3, §8.10):
 *   1. EXPIRE one-time prekeys the device has not refreshed in 30 days. They
 *      are stale key material; serving them invites handshakes against keys
 *      the device may no longer hold.
 *   2. COLLAPSE signed prekeys to exactly one (the highest key id) per device
 *      and drop any older than 30 days. A device with no signed prekey left
 *      gets a 409 NO_SIGNED_PREKEY on bundle fetch until it re-uploads — the
 *      correct failure mode for a device that has been offline for a month.
 *   3. REPORT devices that need to refill (below 20 one-time keys) or rotate
 *      (signed prekey >= 7 days old) so operators can see the health of the
 *      prekey population.
 *
 * SECURITY (§8.8): THIS JOB GENERATES NO KEYS. The server never produces or
 * holds private key material; it only expires and prunes public rows the
 * devices uploaded. (The previous scaffold generated throwaway keypairs here,
 * which made the server a participant in the key exchange. That is gone.)
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import pg from "pg";
import { createPool } from "../db/pool.js";

export const ONE_TIME_BATCH_SIZE = 100;
export const ONE_TIME_REPLENISH_THRESHOLD = 20;
export const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;
/** Hard expiry: a prekey older than this is deleted rather than served. */
export const ONE_TIME_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
export const SIGNED_PREKEY_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

export type PrekeyMaintenanceSummary = {
  devicesProcessed: number;
  devicesNeedingReplenish: number;
  devicesNeedingSignedRotation: number;
  expiredOneTimePrekeys: number;
  expiredSignedPrekeys: number;
  prunedSupersededSignedPrekeys: number;
};

type DeviceHealthRow = {
  id: string;
  unconsumed: number;
  signed_created_at: Date | string | null;
};

/**
 * Run one maintenance pass. Safe to call concurrently: every statement is
 * idempotent and the pruning deletes are set-based.
 */
export async function runPrekeyMaintenance(
  pool: pg.Pool,
  now: Date = new Date(),
): Promise<PrekeyMaintenanceSummary> {
  const oneTimeCutoff = new Date(now.getTime() - ONE_TIME_MAX_AGE_MS);
  const signedCutoff = new Date(now.getTime() - SIGNED_PREKEY_MAX_AGE_MS);

  // Stale one-time keys: never used, device stopped refreshing them.
  const expiredOneTime = await pool.query(
    `DELETE FROM one_time_prekeys WHERE created_at < $1`,
    [oneTimeCutoff],
  );

  // Stale signed prekeys: the device must upload a fresh one.
  const expiredSigned = await pool.query(
    `DELETE FROM signed_prekeys WHERE created_at < $1`,
    [signedCutoff],
  );

  // Collapse leftovers so exactly one signed prekey (highest key id) remains.
  const prunedSuperseded = await pool.query(
    `DELETE FROM signed_prekeys sp
     USING signed_prekeys newer
     WHERE sp.device_id = newer.device_id AND sp.key_id < newer.key_id`,
  );

  const health = await pool.query<DeviceHealthRow>(
    `SELECT d.id,
            (SELECT count(*)::int FROM one_time_prekeys o
              WHERE o.device_id = d.id AND o.consumed_at IS NULL) AS unconsumed,
            (SELECT max(s.created_at) FROM signed_prekeys s
              WHERE s.device_id = d.id) AS signed_created_at
     FROM devices d
     WHERE d.is_active = true AND d.revoked_at IS NULL`,
  );

  let devicesNeedingReplenish = 0;
  let devicesNeedingSignedRotation = 0;

  for (const row of health.rows) {
    if (row.unconsumed < ONE_TIME_REPLENISH_THRESHOLD) devicesNeedingReplenish += 1;

    const signedAt = row.signed_created_at ? new Date(row.signed_created_at) : null;
    if (!signedAt || now.getTime() - signedAt.getTime() >= SIGNED_PREKEY_ROTATION_MS) {
      devicesNeedingSignedRotation += 1;
    }
  }

  return {
    devicesProcessed: health.rows.length,
    devicesNeedingReplenish,
    devicesNeedingSignedRotation,
    expiredOneTimePrekeys: expiredOneTime.rowCount ?? 0,
    expiredSignedPrekeys: expiredSigned.rowCount ?? 0,
    prunedSupersededSignedPrekeys: prunedSuperseded.rowCount ?? 0,
  };
}

/** Credentials come from .env when the file exists, shell env otherwise. */
export function loadBackendEnv(): void {
  try {
    const env = readFileSync(resolve(import.meta.dirname, "../../.env"), "utf-8");
    for (const line of env.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      const val = trimmed.slice(eq + 1).trim();
      if (!process.env[key]) process.env[key] = val;
    }
  } catch {
    /* .env not found — rely on shell env */
  }
}

async function main(): Promise<void> {
  loadBackendEnv();

  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error(
      "DATABASE_URL is not set. Set it in apps/backend/.env or pass it as an env var.",
    );
    process.exit(1);
  }

  const pool = createPool({ connectionString: url });
  try {
    const summary = await runPrekeyMaintenance(pool);
    console.log("Prekey maintenance complete:", JSON.stringify(summary));
  } finally {
    await pool.end();
  }
}

// Only run as a standalone script; importing the module must not kick off a
// full maintenance pass.
const isEntrypoint =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntrypoint) {
  main().catch((err) => {
    console.error("Prekey maintenance failed:", err);
    process.exit(1);
  });
}
