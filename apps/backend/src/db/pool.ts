import { readFileSync } from "node:fs";
import pg from "pg";

const { Pool } = pg;

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"]);

const TLS_MODES = new Set(["require", "verify-ca", "verify-full", "prefer", "allow"]);

export function redactUrl(raw: string): string {
  return raw.replace(/\/\/[^:@/]*:[^@/]*@/, "//***:***@");
}

function loadCa(): string | undefined {
  const raw = process.env.DATABASE_CA_CERT;
  if (!raw) return undefined;
  if (raw.includes("BEGIN CERTIFICATE")) return raw;
  try {
    return readFileSync(raw, "utf8");
  } catch (err) {
    throw new Error(
      `DATABASE_CA_CERT is set but could not be read as a PEM file: ${(err as Error).message}`,
    );
  }
}

export interface PoolOptions {
  connectionString: string | undefined;
}

/**
 * Drops `sslmode` from the URL handed to pg.
 *
 * pg builds its client config with `Object.assign({}, config, parse(connectionString))`,
 * so anything the connection string says about TLS wins over the `ssl` option this
 * module passes in. pg-connection-string turns any `sslmode` into a fresh `ssl = {}`
 * and, since 2.14, treats require/prefer/verify-ca as aliases for verify-full — i.e.
 * `rejectUnauthorized` left to its default of true. Passing `sslmode=require` for an
 * unverified-but-encrypted connection would therefore be silently upgraded to
 * certificate verification and fail against a server using a private CA.
 *
 * sslmode is interpreted and enforced above, so it must not reach pg.
 */
function withoutSslMode(url: URL): string {
  const stripped = new URL(url.toString());
  stripped.searchParams.delete("sslmode");
  stripped.searchParams.delete("uselibpqcompat");
  return stripped.toString();
}

/**
 * Builds a pg Pool with transport security decided in code rather than left to a
 * substring of the connection string.
 *
 * Local targets may connect in plaintext. Any remote target must state its intent
 * via sslmode, and an absent or disabled sslmode is refused rather than defaulted.
 * When DATABASE_CA_CERT is supplied the server certificate is verified against it;
 * without it the connection is still encrypted but the peer is not authenticated.
 */
export function createPool({ connectionString }: PoolOptions): pg.Pool {
  if (!connectionString) {
    throw new Error("DATABASE_URL is not set");
  }

  let url: URL;
  try {
    url = new URL(connectionString);
  } catch {
    throw new Error("DATABASE_URL is not a valid URL");
  }

  if (LOCAL_HOSTS.has(url.hostname.toLowerCase())) {
    return new Pool({ connectionString });
  }

  const sslmode = url.searchParams.get("sslmode");
  if (!sslmode) {
    throw new Error(
      `DATABASE_URL points at remote host ${url.hostname} but declares no sslmode. ` +
        `Refusing to guess. Add ?sslmode=require to the URL, and set DATABASE_CA_CERT to a PEM ` +
        `file so the server certificate is verified.`,
    );
  }
  if (!TLS_MODES.has(sslmode)) {
    throw new Error(
      `DATABASE_URL declares sslmode=${sslmode}, which is not a recognised value. ` +
        `Use require or verify-full.`,
    );
  }
  if (sslmode === "allow" || sslmode === "prefer") {
    throw new Error(
      `DATABASE_URL declares sslmode=${sslmode}, which permits a plaintext fallback. ` +
        `Use require or verify-full for a remote database.`,
    );
  }

  const ca = loadCa();
  const verifyServer = sslmode === "verify-full" || ca !== undefined;
  if (!ca) {
    console.warn(
      verifyServer
        ? `[db] sslmode=verify-full for ${url.hostname} but DATABASE_CA_CERT is not set, so the ` +
          `server certificate is verified against the system trust store only. A database behind ` +
          `a private CA will be refused; set DATABASE_CA_CERT to that CA's PEM file.`
        : `[db] TLS enabled for ${url.hostname} (sslmode=${sslmode}) but DATABASE_CA_CERT is not set, ` +
          `so the server certificate is NOT verified. The connection is encrypted but the peer is ` +
          `unauthenticated. Set DATABASE_CA_CERT to a PEM file to close this.`,
    );
  }

  return new Pool({
    connectionString: withoutSslMode(url),
    ssl: ca ? { ca, rejectUnauthorized: true } : verifyServer ? true : { rejectUnauthorized: false },
  });
}

/**
 * Confirms the negotiated connection is actually encrypted. Call once per pool
 * before relying on it, so a misconfigured URL fails at boot rather than silently.
 */
export async function assertTls(pool: pg.Pool, connectionString: string): Promise<void> {
  const url = new URL(connectionString);
  if (LOCAL_HOSTS.has(url.hostname.toLowerCase())) return;

  const client = await pool.connect();
  try {
    const res = await client.query("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()");
    const serverSaysSsl = res.rows[0]?.ssl === true;

    // A connection pooler (Supavisor, PgBouncer) terminates TLS itself and
    // forwards to Postgres in plaintext, so pg_stat_ssl reports false even
    // though the client's hop is encrypted. Trust the client socket in that
    // case; otherwise require the server to confirm SSL.
    const stream = (client as unknown as { connection?: { stream?: { encrypted?: boolean } } })
      .connection?.stream;
    const clientSideEncrypted = stream?.encrypted === true;

    if (!serverSaysSsl && !clientSideEncrypted) {
      throw new Error(
        `Refusing to continue: the connection to ${url.hostname} is NOT encrypted ` +
          `(pg_stat_ssl.ssl=${res.rows[0]?.ssl}, client stream encrypted=${clientSideEncrypted}).`,
      );
    }
  } finally {
    client.release();
  }
}
