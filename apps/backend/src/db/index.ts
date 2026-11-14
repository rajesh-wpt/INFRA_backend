import { drizzle } from "drizzle-orm/node-postgres";
import type pg from "pg";
import * as schema from "./schema.js";
import { createPool } from "./pool.js";

let _db: ReturnType<typeof drizzle<typeof schema>> | null = null;
let _pool: pg.Pool | null = null;

/**
 * Returns the shared pg Pool.
 *
 * The pool reads DATABASE_URL from the environment once and reuses
 * connections for the lifetime of the process. Background jobs that need raw
 * SQL (e.g. the prekey maintenance job) use this rather than opening their own.
 */
export function getPool(): pg.Pool {
  if (_pool) return _pool;

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is not set");
  }

  _pool = createPool({ connectionString });
  return _pool;
}

/**
 * Returns a shared Drizzle instance backed by the shared pg Pool.
 */
export function getDb() {
  if (_db) return _db;

  _db = drizzle(getPool(), { schema });
  return _db;
}

export { schema };

/** Drizzle database type — use for optional db parameters in auth functions. */
export type AppDb = ReturnType<typeof drizzle<typeof schema>>;
