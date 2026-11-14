import pg from "pg";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import dotenv from "dotenv";

// Load .env
dotenv.config({ path: resolve(import.meta.dirname, "../../.env") });

const { Pool } = pg;

async function runMigration(sqlFilePath: string) {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error("DATABASE_URL is not set");
    process.exit(1);
  }
  console.log(`Connecting to database...`);
  const pool = new Pool({ connectionString: url });

  try {
    const sql = readFileSync(sqlFilePath, "utf-8");
    console.log(`Running migration: ${sqlFilePath}`);
    await pool.query(sql);
    console.log("Migration completed successfully!");
  } catch (err) {
    console.error("Migration failed:", err);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

const migrations = [
  "C:\\Users\\prava\\OneDrive\\Desktop\\vs code\\Team Beta\\apps\\backend\\src\\db\\migrations\\010_add_account_status.sql",
  "C:\\Users\\prava\\OneDrive\\Desktop\\vs code\\Team Beta\\apps\\backend\\src\\db\\migrations\\011_moderation_enforcement.sql",
];

for (const migration of migrations) {
  await runMigration(migration);
}

console.log("All migrations completed!");