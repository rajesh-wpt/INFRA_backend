import { strict as assert } from "node:assert";
import { createPool } from "./pool.js";

const REMOTE = "postgresql://u:p@db.abcdefg.supabase.com:6543/postgres";
const LOCAL = "postgresql://u:p@localhost:5432/postgres";

let pass = 0;
let fail = 0;

function check(name: string, fn: () => void) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
    pass++;
  } catch (err) {
    console.log(`  FAIL  ${name} -> ${(err as Error).message}`);
    fail++;
  }
}

function throws(name: string, fn: () => void, expect: RegExp) {
  try {
    fn();
    console.log(`  FAIL  ${name} -> did not throw`);
    fail++;
  } catch (err) {
    const msg = (err as Error).message;
    if (expect.test(msg)) {
      console.log(`  PASS  ${name}`);
      pass++;
    } else {
      console.log(`  FAIL  ${name} -> wrong error: ${msg.slice(0, 90)}`);
      fail++;
    }
  }
}

console.log("\ncreatePool transport decisions");

process.env.DATABASE_URL = REMOTE;
delete process.env.DATABASE_CA_CERT;

throws("remote without sslmode is REFUSED", () => createPool({ connectionString: REMOTE }),
  /declares no sslmode/);

throws("remote with sslmode=disable is REFUSED",
  () => createPool({ connectionString: REMOTE + "?sslmode=disable" }), /not a recognised value/);

throws("remote with sslmode=prefer is REFUSED (allows plaintext fallback)",
  () => createPool({ connectionString: REMOTE + "?sslmode=prefer" }), /permits a plaintext fallback/);

throws("remote with sslmode=nonsense is REFUSED",
  () => createPool({ connectionString: REMOTE + "?sslmode=tlsplease" }), /not a recognised value/);

throws("missing DATABASE_URL is REFUSED", () => createPool({ connectionString: undefined }),
  /DATABASE_URL is not set/);

throws("malformed URL is REFUSED", () => createPool({ connectionString: "not-a-url" }),
  /not a valid URL/);

check("remote WITH sslmode=require is accepted (warns, no CA)", () => {
  const pool = createPool({ connectionString: REMOTE + "?sslmode=require" });
  assert.equal(typeof pool.query, "function");
  void pool.end();
});

// pg rebuilds its config with Object.assign({}, config, parse(connectionString)),
// so an sslmode left in the URL overrides the ssl option createPool decides on.
// pg-connection-string >= 2.14 maps require/prefer/verify-ca onto verify-full,
// which is what turned an encrypted-but-unverified pool into a hard boot failure
// with "self-signed certificate in certificate chain".
check("sslmode in the URL cannot re-enable verification behind our back", () => {
  const pool = createPool({ connectionString: REMOTE + "?sslmode=require" });
  const ssl = pool.options.ssl as { rejectUnauthorized: boolean };
  assert.equal(ssl.rejectUnauthorized, false);
  void pool.end();
});

check("sslmode=verify-full without a CA verifies against the system trust store", () => {
  const pool = createPool({ connectionString: REMOTE + "?sslmode=verify-full" });
  assert.equal(pool.options.ssl, true);
  void pool.end();
});

check("DATABASE_CA_CERT PEM turns verification on", () => {
  process.env.DATABASE_CA_CERT = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----";
  const pool = createPool({ connectionString: REMOTE + "?sslmode=require" });
  const ssl = pool.options.ssl as { rejectUnauthorized: boolean; ca: string };
  assert.equal(ssl.rejectUnauthorized, true);
  assert.ok(ssl.ca.includes("BEGIN CERTIFICATE"));
  delete process.env.DATABASE_CA_CERT;
  void pool.end();
});

check("localhost WITHOUT sslmode is accepted (plaintext allowed locally)", () => {
  const pool = createPool({ connectionString: LOCAL });
  assert.equal(typeof pool.query, "function");
  void pool.end();
});

check("127.0.0.1 WITHOUT sslmode is accepted", () => {
  const pool = createPool({ connectionString: LOCAL.replace("localhost", "127.0.0.1") });
  assert.equal(typeof pool.query, "function");
  void pool.end();
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
