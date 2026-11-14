import "dotenv/config";
import { createApp } from "./app.js";
import { startPrekeyMaintenanceScheduler } from "./jobs/scheduler.js";

const PORT = process.env.PORT ?? 4000;

const { httpServer } = createApp();
httpServer.listen(PORT, () => {
  console.log(`@wpt/backend listening on :${PORT}`);
});

// ENC-4.1 — expire/refill hygiene for the prekey population. Disabled with
// PREKEY_MAINTENANCE_INTERVAL_MS=0 (deployments that use an external cron).
const stopPrekeyMaintenance = startPrekeyMaintenanceScheduler();

function shutdown(signal: string): void {
  stopPrekeyMaintenance();
  httpServer.close(() => {
    console.log(`@wpt/backend stopped (${signal})`);
    process.exit(0);
  });
}

process.once("SIGINT", () => shutdown("SIGINT"));
process.once("SIGTERM", () => shutdown("SIGTERM"));
