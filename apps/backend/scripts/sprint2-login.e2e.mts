/**
 * Sprint 2 login end-to-end verification.
 *
 * Covers the four backend items from the Team Beta Sprint 2 list:
 *
 *   LOGIN-3.5  OTP delivery through the self-hosted gateway (no Twilio)
 *   LOGIN-3.7  new-device handoff stores real platform/key + revokes the
 *              superseded device, and the server owns device identity
 *   LOGIN-3.8  `force_logout` actually reaches the old device (two sockets)
 *   LOGIN-3.9  /session/check resolves the live session, not an arbitrary row
 *
 * Requirements
 *   - backend running (default http://127.0.0.1:4000)
 *   - apps/backend/.env with DATABASE_URL, DATABASE_CA_CERT,
 *     SMS_GATEWAY_TOKEN and SMS_PAYLOAD_KEY
 *
 * Usage
 *   cd apps/backend
 *   ../../node_modules/.bin/tsx scripts/sprint2-login.e2e.mts
 *
 * Every account, session, device, OTP and outbox row created here is deleted
 * at the end. No SMS is sent: the gateway queue is polled directly.
 */
import { readFileSync } from "node:fs";
import { setDefaultResultOrder } from "node:dns";
import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

setDefaultResultOrder("ipv4first");

const HERE = dirname(fileURLToPath(import.meta.url));
const BACKEND = resolve(HERE, "..");
const REPO = resolve(BACKEND, "..", "..");

const env: Record<string, string> = {};
for (const line of readFileSync(resolve(BACKEND, ".env"), "utf8").split("\n")) {
  const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
  if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, "");
}

const missing = ["DATABASE_URL", "SMS_GATEWAY_TOKEN", "SMS_PAYLOAD_KEY"].filter((k) => !env[k]);
if (missing.length > 0) {
  console.error(`missing env: ${missing.join(", ")} (see .env.example)`);
  process.exit(2);
}

const BASE = process.env.E2E_BASE_URL ?? "http://127.0.0.1:4000";
const API = `${BASE}/api/v1/onboarding`;
const SMS = `${BASE}/api/v1/sms`;
const GATEWAY = env.SMS_GATEWAY_TOKEN;
const PHONE_MAIN = "+919000000781";
const PHONE_SOCKET = "+919000000782";
const KEY_A = "A".repeat(43) + "=";
const KEY_B = "B".repeat(43) + "=";

// socket.io-client lives in the mobile workspace; resolve it from there.
const requireFromMobile = createRequire(resolve(REPO, "apps/mobile/package.json"));
const { io } = requireFromMobile("socket.io-client") as {
  io: (url: string, opts: Record<string, unknown>) => any;
};

const client = new pg.Client({
  connectionString: env.DATABASE_URL.replace(/[?&]sslmode=[^&]*/g, ""),
  ssl: env.DATABASE_CA_CERT
    ? { ca: readFileSync(resolve(BACKEND, env.DATABASE_CA_CERT), "utf8"), rejectUnauthorized: true }
    : { rejectUnauthorized: false },
});

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean, detail = ""): void {
  if (ok) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

async function post(url: string, body: unknown, token?: string) {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => null)) as any };
}

async function purgePhone(phone: string): Promise<void> {
  await client.query(`delete from sms_outbox where phone_number = $1`, [phone]);
  await client.query(`delete from otp_verifications where phone_number = $1`, [phone]);
  await client.query(`delete from legal_acceptances where phone_number = $1`, [phone]);
}

async function purgeUser(userId: string): Promise<void> {
  await client.query(`delete from sessions where user_id = $1`, [userId]);
  await client.query(`delete from devices where user_id = $1`, [userId]);
  await client.query(`delete from contact_hashes where user_id = $1`, [userId]).catch(() => {});
  await client.query(`delete from users where id = $1`, [userId]);
}

/** OTP send → gateway poll, returning the code the gateway would have sent. */
async function loginAndGetCode(phone: string) {
  await purgePhone(phone);
  await post(`${API}/accept-legal`, { phoneNumber: phone });
  let sent = await post(`${API}/otp/send`, { phoneNumber: phone });

  // Back-to-back runs trip the 3-per-minute send limit. Wait it out instead of
  // reporting a false failure.
  if (sent.status === 429) {
    const waitMs = Math.min(60, Number(sent.json?.secondsRemaining ?? 60)) * 1000 + 500;
    console.log(`        send rate-limited; waiting ${Math.round(waitMs / 1000)}s`);
    await new Promise((r) => setTimeout(r, waitMs));
    sent = await post(`${API}/otp/send`, { phoneNumber: phone });
  }

  const polled = await post(`${SMS}/outbox/poll`, { limit: 50 }, GATEWAY);
  const item = polled.json?.items?.find((i: any) => i.phoneNumber === phone);
  if (sent.status !== 200) {
    console.log(`        otp/send returned ${sent.status}: ${JSON.stringify(sent.json)}`);
  }
  return { sent, item, code: item?.code as string | undefined };
}

const createdUsers: string[] = [];
await client.connect();

try {
  console.log("LOGIN-3.5  OTP delivery through the self-hosted gateway");

  const { sent, item: queued, code } = await loginAndGetCode(PHONE_MAIN);
  check("otp/send returns 200", sent.status === 200, `status ${sent.status}`);

  const outbox = await client.query(
    `select id, payload, status from sms_outbox where phone_number = $1 order by created_at desc limit 1`,
    [PHONE_MAIN],
  );
  const row = outbox.rows[0];
  check("sms_outbox row written", !!row);
  check(
    "payload is ciphertext, not the code",
    typeof row?.payload === "string" && row.payload.startsWith("v1."),
    String(row?.payload ?? "").slice(0, 12),
  );

  const noAuth = await post(`${SMS}/outbox/poll`, {});
  check("poll without token → 401", noAuth.status === 401, `status ${noAuth.status}`);
  const badAuth = await post(`${SMS}/outbox/poll`, {}, "wrong-token");
  check("poll with wrong token → 401", badAuth.status === 401, `status ${badAuth.status}`);

  check("gateway poll returns the queued row", !!queued);
  check("gateway receives a 6-digit code", /^\d{6}$/.test(String(code)), String(code));

  // A backlog must not turn into SMS spam: OTPs expire long before 10 minutes.
  const stalePhone = "+919000000799";
  const stale = await client.query(
    `insert into sms_outbox (phone_number, otp_hash, payload, status, created_at)
     values ($1, 'sha256-placeholder', 'v1.stale', 'pending', now() - interval '2 hours')
     returning id`,
    [stalePhone],
  );
  const stalePoll = await post(`${SMS}/outbox/poll`, { limit: 50 }, GATEWAY);
  check(
    "stale pending rows are not dispatched",
    !stalePoll.json?.items?.some((i: any) => i.id === stale.rows[0].id),
  );
  await client.query(`delete from sms_outbox where id = $1`, [stale.rows[0].id]);

  const badAck = await post(`${SMS}/outbox/${row?.id}/ack`, { status: "maybe" }, GATEWAY);
  check("ack with invalid status → 400", badAck.status === 400, `status ${badAck.status}`);
  const ack = await post(`${SMS}/outbox/${row?.id}/ack`, { status: "sent" }, GATEWAY);
  check("ack sent → 200", ack.status === 200, `status ${ack.status}`);
  const reAck = await post(`${SMS}/outbox/${row?.id}/ack`, { status: "sent" }, GATEWAY);
  check("re-ack → 404 (no double dispatch)", reAck.status === 404, `status ${reAck.status}`);

  const afterAck = await client.query(`select payload, status from sms_outbox where id = $1`, [
    row.id,
  ]);
  check("payload cleared after ack", afterAck.rows[0]?.payload === null);
  check("status recorded as sent", afterAck.rows[0]?.status === "sent");

  console.log("\nLOGIN-3.7  handoff stores real device facts and revokes the old device");

  const verified = await post(`${API}/otp/verify`, {
    phoneNumber: PHONE_MAIN,
    code,
    deviceInfo: { platform: "ios", identityPublicKey: KEY_A },
  });
  check(
    "otp/verify succeeds",
    verified.status === 200 && verified.json?.status === "success",
    JSON.stringify(verified.json),
  );
  createdUsers.push(verified.json?.userId);

  const deviceA: string = verified.json?.deviceId;
  check(
    "verify returns the server device id",
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(deviceA)),
    String(deviceA),
  );

  const devA = await client.query(
    `select platform, identity_public_key, is_active from devices where id = $1`,
    [deviceA],
  );
  check("device stores the real platform (ios)", devA.rows[0]?.platform === "ios", devA.rows[0]?.platform);
  check("device stores the real identity key", devA.rows[0]?.identity_public_key === KEY_A);
  check(
    "no pf_<deviceId> placeholder key",
    !String(devA.rows[0]?.identity_public_key ?? "").startsWith("pf_"),
  );

  const badPlatform = await post(`${API}/login/handoff`, {
    refreshToken: verified.json?.refreshToken,
    deviceInfo: { deviceId: randomUUID(), deviceName: "Odd Phone", platform: "symbian" },
  });
  check("unknown platform rejected → 400", badPlatform.status === 400, `status ${badPlatform.status}`);

  const missingPlatform = await post(`${API}/login/handoff`, {
    refreshToken: verified.json?.refreshToken,
    deviceInfo: { deviceId: randomUUID(), deviceName: "No Platform" },
  });
  check("missing platform rejected → 400", missingPlatform.status === 400, `status ${missingPlatform.status}`);

  // Resume-time validation must work on the session that was just created,
  // before any handoff revokes it (LOGIN-3.9).
  const fresh = await post(`${API}/session/check`, { deviceId: deviceA }, verified.json?.accessToken);
  check("session/check on the fresh session → valid", fresh.json?.isValid === true, JSON.stringify(fresh.json));

  const deviceB = randomUUID();
  const handoff = await post(`${API}/login/handoff`, {
    refreshToken: verified.json?.refreshToken,
    deviceInfo: {
      deviceId: deviceB,
      deviceName: "Second Phone",
      platform: "android",
      identityPublicKey: KEY_B,
    },
  });
  check(
    "handoff succeeds",
    handoff.status === 200 && handoff.json?.success === true,
    JSON.stringify(handoff.json),
  );
  check("handoff echoes the device id", handoff.json?.deviceId === deviceB, String(handoff.json?.deviceId));

  const devAAfter = await client.query(`select is_active, revoked_at from devices where id = $1`, [
    deviceA,
  ]);
  check(
    "superseded device row is revoked",
    devAAfter.rows[0]?.is_active === false && devAAfter.rows[0]?.revoked_at !== null,
    JSON.stringify(devAAfter.rows[0] ?? null),
  );

  const devB = await client.query(
    `select device_type, platform, identity_public_key from devices where id = $1`,
    [deviceB],
  );
  check(
    "new device stored with its real platform",
    devB.rows[0]?.platform === "android" && devB.rows[0]?.identity_public_key === KEY_B,
    JSON.stringify(devB.rows[0] ?? null),
  );

  console.log("\nLOGIN-3.9  resume-time session validation");

  const live = await post(`${API}/session/check`, { deviceId: deviceB }, handoff.json?.accessToken);
  check("session/check on the new device → valid", live.json?.isValid === true, JSON.stringify(live.json));

  const staleSession = await post(`${API}/session/check`, { deviceId: deviceA }, verified.json?.accessToken);
  check(
    "old device's session reported revoked",
    staleSession.json?.isValid === false,
    JSON.stringify(staleSession.json),
  );

  const liveSessions = await client.query(
    `select count(*)::int as n from sessions where user_id = $1 and revoked_at is null`,
    [verified.json?.userId],
  );
  check("exactly one live session after handoff", liveSessions.rows[0].n === 1, `live=${liveSessions.rows[0].n}`);

  console.log("\nLOGIN-3.8  force_logout reaches the superseded device");

  const socketLogin = await loginAndGetCode(PHONE_SOCKET);
  const socketVerify = await post(`${API}/otp/verify`, {
    phoneNumber: PHONE_SOCKET,
    code: socketLogin.code,
    deviceInfo: { platform: "android", identityPublicKey: KEY_A },
  });
  check("second account logged in", socketVerify.json?.status === "success", JSON.stringify(socketVerify.json));
  createdUsers.push(socketVerify.json?.userId);

  const socketA = io(BASE, {
    path: "/realtime",
    transports: ["websocket", "polling"],
    auth: {
      userId: socketVerify.json?.userId,
      deviceId: socketVerify.json?.deviceId,
      token: socketVerify.json?.accessToken,
    },
  });

  const connected = await new Promise<boolean>((done) => {
    const timer = setTimeout(() => done(false), 8000);
    socketA.on("connect", () => {
      clearTimeout(timer);
      done(true);
    });
    socketA.on("connect_error", (err: Error) => {
      console.log(`        connect_error: ${err.message}`);
      clearTimeout(timer);
      done(false);
    });
  });
  check("socket connects on /realtime", connected);

  const forced = new Promise<boolean>((done) => {
    const timer = setTimeout(() => done(false), 10000);
    socketA.on("force_logout", () => {
      clearTimeout(timer);
      done(true);
    });
  });

  const socketHandoff = await post(`${API}/login/handoff`, {
    refreshToken: socketVerify.json?.refreshToken,
    deviceInfo: {
      deviceId: randomUUID(),
      deviceName: "Replacement Phone",
      platform: "android",
      identityPublicKey: KEY_B,
    },
  });
  check("handoff to the replacement device succeeds", socketHandoff.json?.success === true);
  check("old device receives force_logout", (await forced) === true);

  socketA.disconnect();
} catch (err) {
  fail++;
  console.error("UNEXPECTED:", err);
} finally {
  for (const userId of createdUsers) {
    if (userId) await purgeUser(userId).catch(() => {});
  }
  await purgePhone(PHONE_MAIN).catch(() => {});
  await purgePhone(PHONE_SOCKET).catch(() => {});
  const leftovers = await client
    .query(`select count(*)::int as n from users where phone_number in ($1, $2)`, [
      PHONE_MAIN,
      PHONE_SOCKET,
    ])
    .catch(() => ({ rows: [{ n: -1 }] }));
  check("throwaway accounts removed", leftovers.rows[0].n === 0, `remaining=${leftovers.rows[0].n}`);
  await client.end();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
