/**
 * LOGIN-3.10 — seed dashboard admins.
 *
 * Creates the initial owner account (and optionally a second admin) so a fresh
 * environment has a way into the dashboard. Idempotent: existing emails are
 * left untouched.
 *
 * Credentials come from the environment — never from a checked-in literal:
 *
 *   DASHBOARD_SEED_EMAIL      (default: admin@wpt.local)
 *   DASHBOARD_SEED_PASSWORD   (required; 12+ characters)
 *   DASHBOARD_SEED_ROLE       (default: owner)
 *   DASHBOARD_SEED_TEST       ("true" to mark the account as a test account)
 *
 * Usage:
 *   cd apps/backend
 *   DASHBOARD_SEED_PASSWORD='...' pnpm exec tsx src/db/seed-dashboard-admins.ts
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import bcrypt from "bcryptjs";
import { eq } from "drizzle-orm";
import { getDb, getPool } from "./index.js";
import { dashboardAdmins } from "./dashboard-admins-schema.js";

function loadBackendEnv(): void {
  try {
    const env = readFileSync(resolve(import.meta.dirname, "../../.env"), "utf-8");
    for (const line of env.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIndex = trimmed.indexOf("=");
      if (eqIndex === -1) continue;
      const key = trimmed.slice(0, eqIndex).trim();
      if (!process.env[key]) process.env[key] = trimmed.slice(eqIndex + 1).trim();
    }
  } catch {
    /* .env optional */
  }
}

async function main(): Promise<void> {
  loadBackendEnv();

  const email = (process.env.DASHBOARD_SEED_EMAIL ?? "admin@wpt.local")
    .trim()
    .toLowerCase();
  const password = process.env.DASHBOARD_SEED_PASSWORD ?? "";
  const role = process.env.DASHBOARD_SEED_ROLE === "owner" ? "owner" : "admin";
  const isTestAccount = process.env.DASHBOARD_SEED_TEST === "true";

  if (password.length < 12) {
    console.error(
      "DASHBOARD_SEED_PASSWORD must be at least 12 characters (set it in the environment).",
    );
    process.exit(1);
  }
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is not set (apps/backend/.env or shell env).");
    process.exit(1);
  }

  const db = getDb();

  const [existing] = await db
    .select({ id: dashboardAdmins.id, role: dashboardAdmins.role })
    .from(dashboardAdmins)
    .where(eq(dashboardAdmins.email, email))
    .limit(1);

  if (existing) {
    console.log(`Dashboard admin already exists: ${email} (role=${existing.role}) — unchanged`);
  } else {
    const passwordHash = await bcrypt.hash(password, 12);
    await db.insert(dashboardAdmins).values({
      email,
      passwordHash,
      role,
      isTestAccount,
    });
    console.log(`Created dashboard admin: ${email} (role=${role}, test=${isTestAccount})`);
  }

  await getPool().end();
}

main().catch((err) => {
  console.error("Dashboard admin seed failed:", err);
  process.exit(1);
});
