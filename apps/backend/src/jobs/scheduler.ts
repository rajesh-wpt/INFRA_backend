/**
 * ENC-4.1 — In-process maintenance scheduler.
 *
 * The card requires the prekey hygiene pass to run on a schedule. This repo
 * deploys as a single backend process (no external queue), so a plain
 * interval is the least-moving-parts option: no new dependency, no second
 * deployment target, and it shuts down with the process.
 *
 * PREKEY_MAINTENANCE_INTERVAL_MS controls it:
 *   - unset  -> every 6 hours (first run 60s after boot)
 *   - 0      -> disabled (deployments that use an external cron instead)
 *   - >0     -> that interval in milliseconds
 *
 * The standalone script (src/jobs/prekey-maintenance.ts) remains the entry
 * point for external schedulers and manual runs.
 */

import { getPool } from "../db/index.js";
import { runPrekeyMaintenance } from "./prekey-maintenance.js";

const DEFAULT_INTERVAL_MS = 6 * 60 * 60 * 1000;
const FIRST_RUN_DELAY_MS = 60 * 1000;

export function startPrekeyMaintenanceScheduler(): () => void {
  const raw = process.env.PREKEY_MAINTENANCE_INTERVAL_MS;
  const intervalMs = raw === undefined || raw.trim() === "" ? DEFAULT_INTERVAL_MS : Number(raw);

  if (!Number.isFinite(intervalMs) || intervalMs < 0) {
    console.warn(
      `[prekey-maintenance] ignoring invalid PREKEY_MAINTENANCE_INTERVAL_MS=${raw}; scheduler disabled`,
    );
    return () => {};
  }
  if (intervalMs === 0) {
    console.log("[prekey-maintenance] scheduler disabled (PREKEY_MAINTENANCE_INTERVAL_MS=0)");
    return () => {};
  }

  let running = false;

  const pass = async (): Promise<void> => {
    // Never overlap passes: a slow database must not stack jobs.
    if (running) return;
    running = true;
    try {
      const summary = await runPrekeyMaintenance(getPool());
      const unhealthy =
        summary.devicesNeedingReplenish > 0 || summary.devicesNeedingSignedRotation > 0;
      const line = `[prekey-maintenance] ${JSON.stringify(summary)}`;
      if (unhealthy) console.warn(line);
      else console.log(line);
    } catch (err) {
      console.error("[prekey-maintenance] pass failed:", err);
    } finally {
      running = false;
    }
  };

  const firstRun = setTimeout(() => {
    void pass();
  }, FIRST_RUN_DELAY_MS);
  firstRun.unref();

  const timer = setInterval(() => {
    void pass();
  }, intervalMs);
  timer.unref();

  console.log(
    `[prekey-maintenance] scheduler started (every ${Math.round(intervalMs / 1000)}s)`,
  );

  return () => {
    clearTimeout(firstRun);
    clearInterval(timer);
  };
}
