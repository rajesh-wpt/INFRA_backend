#!/usr/bin/env node
/**
 * Simulates the PHONE half of BE-6.1 until the mobile app implements it.
 * Usage:
 *   PHONE_ACCESS_TOKEN=<phone bearer> node scripts/phone-scan.mjs '<QR text copied from Web>' [backendOrigin]
 *
 * Accepts the QR JSON ({"version":1,"type":"sealine_web_link","token":"...","wsUrl":"..."}) or a raw token.
 * Sends: POST {origin}/api/v1/linking/scan  { token }  with Authorization: Bearer <phone access token>.
 */
const [, , qr, originArg] = process.argv;
const bearer = process.env.PHONE_ACCESS_TOKEN;
if (!qr || !bearer) {
  console.error("Usage: PHONE_ACCESS_TOKEN=... node scripts/phone-scan.mjs '<qr text>' [origin]");
  process.exit(2);
}

let token = qr.trim();
let origin = originArg;
try {
  const p = JSON.parse(qr);
  if (p.type !== "sealine_web_link") throw new Error("QR is not a sealine_web_link payload");
  token = p.token;
  origin ??= p.wsUrl;
} catch (e) {
  if (e instanceof SyntaxError === false) throw e; // JSON but wrong type -> real error; plain token -> fine
}
if (!origin) { console.error("No backend origin (QR had no wsUrl). Pass it as the 2nd argument."); process.exit(2); }

const res = await fetch(`${origin.replace(/\/+$/, "")}/api/v1/linking/scan`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` },
  body: JSON.stringify({ token })
});
const body = await res.text();
console.log(res.status, body);
const hints = {
  400: "INVALID_TOKEN: token must be 32-256 chars of A-Z a-z 0-9 _ -",
  401: "Phone bearer token is invalid/expired (log the phone in again).",
  410: "Token unknown, older than 60s, or already used. Refresh the Web QR and scan again.",
  429: "Rate limit: 10 scans/min per account."
};
if (hints[res.status]) console.log("→", hints[res.status]);
process.exit(res.ok ? 0 : 1);
