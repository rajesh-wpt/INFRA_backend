# Sprint 2 — Backend (Login and Encryption): status

Date: 14 Nov 2026
Branch: `Team-Beta` (commits `94352fc`, `4df23ce`, `eee564b`)
Scope: the Sprint 2 "Not Done" list in the Team Beta task report.

## 1. Result at a glance

| Card | Was | Now | Evidence |
|---|---|---|---|
| LOGIN-3.5 OTP + SMS gateway | Error (Twilio) | **Fixed** | `scripts/sprint2-login.e2e.mts` |
| LOGIN-3.7 New-device handoff transaction | Partial | **Fixed** | same suite |
| LOGIN-3.8 force_logout push | Error | **Fixed + proven on a real phone** | e2e suite, then adb |
| LOGIN-3.9 Resume-time validation | "Done" | **Re-verified + 2 bugs fixed** | same suite |
| LOGIN-3.10 Dashboard auth | Partial | **Not fixed** — port required | see §4 |
| LOGIN-3.12 Platform verification audit log | Partial | **Not fixed** — port required | see §4 |
| ENC-4.1 Prekey tables + rotation | Partial | **Not fixed** — port + design change | see §4 |
| ENC-4.3 sender_key_epoch | Partial | **Not fixed** — port required | see §4 |
| ENC-4.4 Group key ciphertext storage | Partial | **Not fixed** — port required | see §4 |
| ENC-4.5 Group icon via encrypted media | Partial | **Not fixed** — port required | see §4 |
| ENC-4.6 Server-blind audit | Unknown | **Not done** — blocked on the ports | see §4 |

The login half is done, tested on the e2e suite and on a real Android device,
and committed. The encryption half cannot be fixed from this branch: none of
that code exists on `Team-Beta` or `main`; it lives only on
`origin/enc/prekey-bundle`. Section 4 is a concrete port plan.

`pnpm lint` (0 errors; it was 31), `pnpm typecheck`, `pool-guard.test.ts`
(12/12) and the new Sprint 2 suite (33/33) all pass. `apps/web` lint cannot run
in this checkout (`next: command not found` — that app's deps are not
installed); `apps/mobile` lint reports only pre-existing findings.

## 2. What changed (login)

### LOGIN-3.5 — Twilio removed, self-hosted gateway handshake

- `sms/sender.ts` no longer imports or calls Twilio. Delivery is the outbox.
  In non-production it still prints the code to the server console so
  onboarding can be driven without a gateway attached; in production the
  gateway poll is the only path.
- New `POST /api/v1/sms/outbox/poll` and `POST /api/v1/sms/outbox/:id/ack`
  (`routes/sms.ts`), authenticated with a static `SMS_GATEWAY_TOKEN`
  (constant-time compare, `503` when unset — fails closed).
- The code is never stored in plaintext. `sms_outbox.payload` holds
  `v1.<iv>.<tag>.<ciphertext>` (AES-256-GCM, `SMS_PAYLOAD_KEY`), and is set to
  `NULL` on ack. Ack is single-shot: a second ack is `404`, so a gateway
  restart cannot double-send.
- Poll only returns rows younger than 10 minutes. The queue contained pending
  rows from August; a gateway connecting would have sent months-old login
  codes to real numbers. OTPs expire in 5 minutes, so anything older is dead
  weight.
- `.env.example` drops `TWILIO_*` and documents `SMS_GATEWAY_TOKEN` /
  `SMS_PAYLOAD_KEY`.

### LOGIN-3.7 — handoff stores real device facts and revokes the old device

- `parseDeviceInfo()` validates `platform` against `ios|android|web` and an
  `identityPublicKey` as base64/hex when present. `platform` is required on
  `/login/handoff`, optional on `/otp/verify`.
- No more `platform: "android"` default and no more `identityPublicKey:
  pf_<deviceId>`. `devices.platform` and `devices.identity_public_key` are
  nullable (migration 013) and store what the client actually sent. The mobile
  app has no crypto library yet, so the key stays `NULL` — honest, and the
  column no longer requires a fake value.
- The device row is upserted, and every other live device row for the user is
  marked `is_active = false` with `revoked_at`. This matters beyond hygiene:
  `routes/relay.ts` fans out on `devices.isActive`, so a logged-out phone was
  still a delivery target until now.

### LOGIN-3.8 / ONB-1.7 — force_logout now actually arrives

The card blamed the socket path. On `Team-Beta` the path was already
`path: '/realtime'`, so the reported fix would have changed nothing. There
were two real causes underneath:

1. **Device identity disagreed.** The OTP screen invented
   `device_<timestamp>_<random>` and stored it, while the backend bound the
   session to a server-generated uuid. The socket handshake requires the token's
   `deviceId` claim to equal the client's `deviceId`, so the connection was
   rejected (`Token deviceId mismatch`) and no push could be delivered. The
   same mismatch made `/session/check` report "session not found" on every
   resume and would have broken refresh after an hour.
   Fix: the server owns device identity. `/otp/verify` and `/login/handoff`
   return the authoritative `deviceId`; the app persists it and reuses it.
2. **The app never noticed it had logged in.** `SessionProvider` mounts once,
   and `useSession` only re-read storage on mount. After a fresh OTP login the
   provider still held `userId = null`, so `useForceLogout` never opened a
   socket until the next app launch. Fix: `initializeSession` is exposed as
   `refreshSession`, is called by the OTP screen after it writes tokens, and
   sets `isAuthenticated` when a stored session validates.

Verified with two live Socket.IO clients: A connects on `/realtime`, a handoff
to B succeeds, A receives `force_logout`.

### LOGIN-3.9 — resume-time validation

`/session/check` did `LIMIT 1` without `ORDER BY`, so it could pick a revoked
row while a live session existed (exactly what a refresh or handoff leaves
behind) and tell the user they were logged in elsewhere. It now prefers live
sessions, then the newest.

### Two additional bugs found while testing

- **`/otp/send` had a delete/insert race.** The delete and both inserts ran in
  a `Promise.all()`, i.e. on three pool connections concurrently. The delete
  could commit last and remove the verification row just written: the endpoint
  answered `{success:true}` while `/otp/verify` answered `NO_ACTIVE_SESSION`.
  That is an intermittent "the code never works" report with nothing in the
  logs. The three statements now run in one transaction.
- **`assertTls` rejected connection poolers.** It trusted `pg_stat_ssl`, which
  reports `false` when a pooler terminates TLS and forwards in plaintext. It
  now also accepts a verified TLS socket on the client hop. Needed here
  because the direct Supabase host is IPv6-only and this network has no IPv6
  route; the app now connects through the IPv4 pooler
  (`aws-0-ap-southeast-1.pooler.supabase.com:6543`, verified against the
  Supabase root CA).

## 3. Evidence

```
cd apps/backend
../../node_modules/.bin/tsx scripts/sprint2-login.e2e.mts

LOGIN-3.5  OTP delivery through the self-hosted gateway
  PASS  otp/send returns 200
  PASS  sms_outbox row written
  PASS  payload is ciphertext, not the code
  PASS  poll without token → 401
  PASS  poll with wrong token → 401
  PASS  gateway poll returns the queued row
  PASS  gateway receives a 6-digit code
  PASS  stale pending rows are not dispatched
  PASS  ack with invalid status → 400
  PASS  ack sent → 200
  PASS  re-ack → 404 (no double dispatch)
  PASS  payload cleared after ack
  PASS  status recorded as sent

LOGIN-3.7  handoff stores real device facts and revokes the old device
  PASS  otp/verify succeeds
  PASS  verify returns the server device id
  PASS  device stores the real platform (ios)
  PASS  device stores the real identity key
  PASS  no pf_<deviceId> placeholder key
  PASS  unknown platform rejected → 400
  PASS  missing platform rejected → 400
  PASS  session/check on the fresh session → valid
  PASS  handoff succeeds
  PASS  handoff echoes the device id
  PASS  superseded device row is revoked
  PASS  new device stored with its real platform

LOGIN-3.9  resume-time session validation
  PASS  session/check on the new device → valid
  PASS  old device's session reported revoked
  PASS  exactly one live session after handoff

LOGIN-3.8  force_logout reaches the superseded device
  PASS  second account logged in
  PASS  socket connects on /realtime
  PASS  handoff to the replacement device succeeds
  PASS  old device receives force_logout
  PASS  throwaway accounts removed

33 passed, 0 failed
```

The suite creates and deletes its own accounts, sessions, devices, OTPs and
outbox rows; it sends no SMS. It is safe to run against a shared database, but
it needs a running backend and the gateway env vars.

Still to do on hardware: the two-phone test (phone A logged in, log in on
phone B, A must return to the phone-entry screen). The server side is proven;
the remaining risk is native only.

### Real-device verification (vivo 1901, Android 11, Expo Go 54)

Driven over `adb` against the LAN backend (`http://192.168.1.2:4000`); the
device and the laptop were on the same `/24`, so the mobile build used the LAN
URL throughout, never `localhost`.

| Check | Result |
| --- | --- |
| OTP login from the phone (send → verify → profile setup → Chats) | pass |
| `devices` row: `platform=android`, `is_active=true`, server `id` persisted | pass |
| `sessions` row live, no revoked row left behind | pass |
| Log in as the same number from a second device | `force_logout` pushed to 1 socket; phone returned to phone-entry; old device + session revoked |
| Kill the app and relaunch with a valid session | resumes into Chats |

That last row is the reported symptom ("logged out after closing the app") and
it did **not** pass on the first run. Two separate defects came out of the test:

- **Cold start always re-ran onboarding.** `app/legal-acceptance.tsx` never
  read the durable acceptance flag, so every launch was splash → full terms →
  phone-entry, even for a signed-in user; the stored session was never routed
  to. The screen now checks `hasAcceptedLegal()` on mount and resumes to
  `/(tabs)` when a session exists (`/phone-entry` otherwise), rendering nothing
  while that check runs so the terms cannot flash. The `(tabs)` layout still
  re-checks both values, so the gate is not weakened.
- **A same-device re-login logged itself out.** `/otp/verify` correctly revokes
  the superseded device and pushes `force_logout` to its socket, but that socket
  can be the *same* phone if it was still connected while showing phone-entry.
  The handler wiped the tokens the user had just been issued and bounced them
  back to login. `useForceLogout` now compares the stored `deviceId` with the
  identity its socket was opened for and ignores the push when they differ.
  A genuine handoff still logs out immediately (re-tested after the change).

Also fixed while driving the flow: a mistyped OTP digit could not be corrected.
`handleOtpChange` returned early on an empty string, so Backspace did nothing
and `maxLength={1}` rejected a re-typed digit — the only escape was Resend.
Clearing a box is now honoured; verified on the device (typed a wrong digit,
backspaced it, then entered the real code).

## 4. Encryption items — port plan (no code written yet)

`LOGIN-3.10`, `LOGIN-3.12` and all of `ENC-4.x` exist only on
`origin/enc/prekey-bundle`, which forks from `c68ea96` (50 commits behind
`Team-Beta`). Nothing on `main` or `Team-Beta` implements them.

What is on `Team-Beta` today:

- `routes/admin.ts` has `/admin/login` and `/admin/me` but is **not mounted**
  in `app.ts`, and there is no refresh or logout.
- `db/dashboard-admins-schema.ts` and `db/audit-log-schema.ts` exist but
  nothing writes audit rows (`moderation.ts` only mentions it in a comment).

So `LOGIN-3.10`/`3.12` are genuinely partial, not just unmerged.

The six enc commits, in order:

```
a73893c completed 3.10 to 3.12
e011a85 3.12 follow-ups: lint/typecheck fixes, audit logger guard, mobile rename
30ff675 ENC-4.1: prekey tables, weekly replenish+rotate job
4a3753a ENC-4.2: authenticated prekey-bundle endpoint + VERIFY
248fb92 complete ENC 4.1 to 4.4
5bc8d73 complited ENC4.5 to group url ask
```

### Sequencing

Do these in order; each one blocks the next. Owners are roles — put names on
them before the branch is opened.

| # | Task | Owner | Done when |
|---|---|---|---|
| P0 | Decide the storage provider for encrypted media and get its credentials (ENC-4.5). Decide `cron` vs in-process timer for the maintenance job. | team lead | provider + one working dev credential; scheduling choice recorded |
| P1 | Create `sprint2/integration` from `Team-Beta`; cherry-pick the six commits with `-x` and stop at the first conflict. | backend | branch exists, conflict list matches §"Known blockers" below (no surprises) |
| P2 | Renumber the enc migrations to `014`–`016` (`014_dashboard_tables.sql`, `015_audit_logs.sql`, `016_prekey_tables.sql`); update the three `apply-*-migration.ts` scripts and any hardcoded names. | backend | migrations apply cleanly on a scratch DB in numeric order |
| P3 | Normalise the existing duplicate migration numbers (`009`, `010`, `011` each exist twice on `Team-Beta`). Do this **before** adding 014+, so the ledger stays readable. | backend | `ls src/db/migrations` shows one file per number |
| P4 | Pick one auth middleware: keep `middleware/auth.ts` (used by 8 routes) and port only what `auth.middleware.ts` adds; delete the loser. Do not merge both. | backend | `grep -r auth.middleware src` returns nothing; all 8 routes still mount |
| P5 | Merge `devices-schema.ts` by hand: keep the branch's nullable `platform`/`identity_public_key`, add only the prekey columns. Do not take either file wholesale. | backend | `pnpm typecheck` clean; no duplicate column definitions |
| P6 | Reconcile `routes/groups.ts` with the branch's groups/moderation/blocks schema (ENC-4.4/4.5 touch BE-5.7 tables). Keep the moderation fields; add ciphertext/icon columns. | backend | group create/read still works; moderation tests pass |
| P7 | Rework ENC-4.1 to the honest design: the client uploads a fresh **public** prekey bundle when its stock runs low; the server stores, expires and reports. The server never generates or rotates key material it must not know. Schedule the maintenance job (P0) and fix the card wording. | backend + mobile | a seeded low-stock device triggers a replenish prompt; job expires stale bundles on schedule |
| P8 | Mount the admin router and finish LOGIN-3.10 (login, refresh, logout, role check). Write the LOGIN-3.12 audit rows from the auth/middleware path that actually exists after P4. | backend | `/admin/login` → `/admin/me` works with a real admin row; every privileged action writes one audit row |
| P9 | Only now write ENC-4.6 (server-blind audit) — it audits the code above. | backend | audit states, per card, what the server can and cannot see, with evidence |

### Known blockers (they will all bite during P1–P6)

1. **Migration numbers collide.** enc adds `004_dashboard_tables.sql`,
   `005_audit_logs.sql`, `006_prekey_tables.sql`; `Team-Beta` already uses
   004/004b/005/006 for message relay, reports/moderation and the message-type
   enum. See P2/P3.
2. **Two auth middlewares.** enc ships `middleware/auth.middleware.ts`; the
   branch uses `middleware/auth.ts` in eight routes. See P4.
3. **`devices-schema.ts` conflict.** enc adds prekey columns and makes
   `platform` nullable; `Team-Beta` already made `platform`/
   `identity_public_key` nullable. See P5.
4. **`routes/groups.ts` overlap** with groups/moderation/blocks. See P6.
5. **`storage/signed-url.ts` needs storage credentials** for encrypted media
   (ENC-4.5). Without P0 the group-icon path cannot be tested.
6. **ENC-4.1's design is wrong as written.** The server cannot rotate keys it
   must not know. See P7.
7. **Lockfile/`package.json` conflicts** (`cron`, storage SDK). Do not touch
   `apps/mobile/package-lock.json` — it is independently modified.

### Verification gate (must hold before the branch is offered for review)

```
pnpm -C apps/backend typecheck && pnpm -C apps/backend lint
pnpm -C apps/backend test            # pool-guard etc.
tsx apps/backend/scripts/sprint2-login.e2e.mts   # 33 checks, must stay green
```

Plus one manual pass on the Android device: login, kill/relaunch (must resume),
second-device login (must kick), and — once ENC-4.2 lands — fetch a prekey
bundle for a fresh device.

### Estimate and risk

1–2 days of focused work, mostly P2/P3 numbering and P4/P5 reconciliation.
The high-risk items are P6 (shared tables with moderation) and P7 (a design
change, not a merge). Do not accept a "just cherry-pick it" merge: the
duplicate auth middleware and the prekey rotation job both need a decision,
and hauling both middlewares in would leave two ways to authenticate.


## 5. Deployment notes

Applied to the shared Supabase project (`ukmsgzvkvcsbhtlmvswr`):

```sql
-- 012_sms_outbox_payload.sql
ALTER TABLE sms_outbox ADD COLUMN IF NOT EXISTS payload text;

-- 013_devices_nullable_identity.sql
ALTER TABLE devices ALTER COLUMN platform DROP NOT NULL;
ALTER TABLE devices ALTER COLUMN identity_public_key DROP NOT NULL;
```

Both are additive/nullable and were run against the live database. Any
environment that has not run them must do so before this backend starts:
Drizzle selects `payload` unconditionally, so `/otp/send` fails on a database
without it.

Required env (backend):

```
SMS_GATEWAY_TOKEN=<shared secret with the gateway; unset = 503>
SMS_PAYLOAD_KEY=<32 random bytes, hex or base64>
```

The gateway and the backend must hold the same token; the backend alone holds
the payload key. `TWILIO_*` can be deleted.

Local network note: the direct Supabase host is IPv6-only and this network has
no IPv6 route, so `.env` uses the IPv4 pooler with `sslmode=verify-full` and
`DATABASE_CA_CERT=./certs/supabase-root-2021-ca.crt`. The machine's LAN
address also changed (`10.88.62.51` → `192.168.1.2`), so
`apps/mobile/.env` now points at `http://192.168.1.2:4000` — still a LAN
address, never `localhost`. Re-check with `ip -4 addr` after any network move.

## 6. Commits

```
(this commit) fix(mobile): resume the stored session on cold start; harden force-logout
eee564b fix(backend): make OTP send atomic; add Sprint 2 login e2e
4df23ce fix(mobile): persist the server-issued device id and refresh session state
94352fc fix(backend): Sprint 2 login — SMS gateway, device identity, force-logout
```

Not committed on purpose: `apps/mobile/package-lock.json` (independently
modified), and the untracked BE-6.1 web-linking e2e + Postman collection,
which belong to the other workstream.
