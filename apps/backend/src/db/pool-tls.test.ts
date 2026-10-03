import { strict as assert } from "node:assert";
import { assertTls, isSupabasePoolerHost } from "./pool.js";
const POOLER = "postgresql://u:p@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres?sslmode=require";
const DIRECT = "postgresql://u:p@db.abc.supabase.co:5432/postgres?sslmode=require";
const fake = (encrypted: boolean | undefined, ssl: boolean) => ({
  connect: async () => ({ connection: { stream: { encrypted } }, query: async () => ({ rows: [{ ssl }] }), release() {} }),
}) as any;
const rejects = async (p: Promise<unknown>, re: RegExp) => { try { await p; } catch (e) { assert.match((e as Error).message, re); return; } assert.fail("did not throw"); };
(async () => {
  assert.equal(isSupabasePoolerHost("aws-0-ap-southeast-1.pooler.supabase.com"), true);
  assert.equal(isSupabasePoolerHost("evil.com/.pooler.supabase.com.evil.com"), false);
  assert.equal(isSupabasePoolerHost("pooler.supabase.com.evil.com"), false);
  await assertTls(fake(true, false), POOLER);                       // pooler: our TLS ok, pg_stat_ssl=false -> PASS
  await rejects(assertTls(fake(false, true), POOLER), /NOT encrypted/);      // pooler: plaintext socket -> REFUSED
  await rejects(assertTls(fake(undefined, true), POOLER), /NOT encrypted/);  // pooler: no socket info -> REFUSED
  await assertTls(fake(false, true), DIRECT);                       // direct: pg_stat_ssl true -> PASS
  await rejects(assertTls(fake(true, false), DIRECT), /pg_stat_ssl/);        // direct: unchanged strictness
  await assertTls(fake(false, false), "postgresql://u:p@localhost:5432/db"); // local skipped
  console.log("ALL 8 ASSERTIONS PASS");
})();
