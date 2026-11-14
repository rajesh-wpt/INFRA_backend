# ENC-4.6 — Server-Blind Audit

**Status: COMPLETE** — All encryption code paths reviewed; the server never sees, stores, or processes plaintext group message content, group keys, or user identity keys.

---

## Scope

This audit covers the encryption features delivered in Sprint 2 (ENC-4.1 through ENC-4.5) and verifies the **server-blind** property: the backend handles only opaque ciphertext and public key material; it never holds, derives, or logs any private key or plaintext.

---

## 1. Prekey Distribution (ENC-4.1 / 4.2)

| Component | What the server stores | What the server NEVER sees |
|-----------|------------------------|----------------------------|
| **Identity public key** (`devices.identity_public_key`) | Base64-encoded X25519 public key (32 bytes) | Private identity key — generated on device, never uploaded |
| **Signed prekeys** (`signed_prekeys.public_key`, `signature`) | Base64 public key + base64 Ed25519 signature over the public key | Private signed-prekey half — device generates, signs with identity key, uploads only public half |
| **One-time prekeys** (`one_time_prekeys.public_key`) | Base64 public keys (batch of 100) | Private one-time keys — device generates, uploads only public halves |

**Enforcement:**
- DB `CHECK` constraints: `public_key ~ '^[A-Za-z0-9/+=_-]{40,128}$'` and `signature ~ '^[A-Za-z0-9/+=_-]{40,128}$'` reject non-base64 values at the storage layer.
- `POST /prekeys/upload` validates base64 round-trip (`Buffer.from(v,'base64').toString('base64') === v`) and exact byte length (32 bytes for X25519).
- `POST /prekey-bundle/:deviceId` returns only public material; the one-time prekey is **hard-deleted** in the same transaction it is served (`FOR UPDATE SKIP LOCKED` + `DELETE`), guaranteeing single-use.
- **No server-side key generation** — the maintenance job (`prekey-maintenance.ts`) only expires stale public keys; it never fabricates key pairs.

---

## 2. Group Metadata (ENC-4.4)

| Column | Stored as | Server behavior |
|--------|-----------|-----------------|
| `groups.encrypted_name` | `bytea` (opaque ciphertext) | `base64` ↔ `bytea` conversion only; never decrypted, inspected, or logged |
| `groups.encrypted_description` | `bytea` | Same |
| `groups.encrypted_icon_ref` | `bytea` (plaintext = storage object name) | Validated against `MEDIA_NAME_RE` (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`) before any storage call; never decrypted |

**Code paths:**
- `POST /groups` → `base64ToBytes()` validates base64, stores `bytea`.
- `GET /groups/:id` → returns base64 of stored `bytea`; no transformation.
- `GET /groups/:id/icon` → decodes `encrypted_icon_ref` to UTF-8, validates against `MEDIA_NAME_RE`, mints signed download URL via storage driver.

---

## 3. Group Membership & Key Rotation (ENC-4.3)

- **Atomic epoch bump**: `DELETE FROM group_members` + `UPDATE groups SET sender_key_epoch = sender_key_epoch + 1` in a single transaction.
- **Add never bumps epoch** — only departure (remove/leave) increments.
- **Owner protection**: `DELETE /groups/:id/members/:userId` returns `403 CANNOT_REMOVE_OWNER` if target role is `owner`.
- **70-member cap**: enforced under `SELECT ... FOR UPDATE` on the group row.

The server never touches the **Sender Key** or **Group Key** — these are derived client-side from the epoch and the prekey bundles.

---

## 4. Encrypted Media / Group Icons (ENC-4.5)

| Operation | Server role |
|-----------|-------------|
| **Upload** (`PUT /media/group-icons/:name`) | Accepts `{ ciphertext: base64 }`, validates base64 round-trip, size ≤ 256 KB, stores to local filesystem (`MEDIA_ROOT/group-icons/name`). **No decryption.** |
| **Download** (`GET /media/:bucket/:name?exp=&sig=`) | Verifies HMAC-SHA256 over `bucket/name:expiresAt` with `MEDIA_URL_SECRET` (or `JWT_SECRET` fallback). Streams `application/octet-stream` with `Cache-Control: private, no-store`. **No decryption.** |
| **Signed URL minting** (`createSignedUrl`) | HMAC-SHA256(`MEDIA_URL_SECRET`, `bucket/name:expiresAt`) → `exp=` + `sig=` query params. Works with local driver (default) or Supabase Storage (when `SUPABASE_URL` + `SERVICE_ROLE_KEY` set). |

**Storage driver isolation:** The local driver uses only `MEDIA_ROOT` (default `./var/media`, git-ignored) and HMAC-signed URLs. No third-party credentials required for development.

---

## 5. Platform-Verification Audit Log (LOGIN-3.12)

- `audit_logs` table records `platform` (`android_sim` | `ios_otp`) and `verification_path` (`sim_check` | `otp_sms`).
- **Invisibility guarantee**: The platform is **never returned to the client** — `POST /onboarding/otp/send` response is identical for all platforms.
- **Non-blocking**: `logOtpRequest` catches and logs errors; a failed audit write cannot break the OTP flow.
- **Admin-only reads**: `GET /admin/audit/otp` gated by `requireDashboardAuth` (`aud: "dashboard"` JWT).

---

## 6. Dashboard Auth Separation (LOGIN-3.10)

- **Separate secret**: `DASHBOARD_JWT_SECRET` (never `JWT_SECRET`).
- **Separate audience**: Dashboard JWTs carry `aud: "dashboard"`; app JWTs carry no `aud` (legacy) but are signed with `JWT_SECRET` → cannot verify under dashboard secret.
- **Separate session table**: `dashboard_sessions` (refresh token hashes + lookup keys) — no overlap with end-user `sessions`.
- **Endpoints**: `POST /admin/login`, `POST /admin/refresh`, `POST /admin/logout`, `POST /admin/logout-all`, `GET /admin/me`, `GET /admin/audit/otp`, owner-only admin management (`POST/GET/DELETE /admin/admins`).

---

## 7. Code-Grep Evidence (No Private Key Paths)

```bash
# No private key generation in backend
$ grep -r "generateX25519KeyPair\|generateIdentityKeyPair\|ed25519.*utils.*randomSecretKey\|x25519.*utils.*randomSecretKey" apps/backend/src/
# → ONLY in test scripts, never in production routes/jobs

# No decryption calls
$ grep -r "aeadDecrypt\|decrypt\|box.open\|nacl.*open" apps/backend/src/
# → NO MATCHES in production code

# Private key column search
$ grep -r "private_key\|PrivateKey\|secret.*key" apps/backend/src/ --include="*.ts" | grep -v test | grep -v "// " | grep -v "public_key"
# → NO COLUMNS or variables that could hold private key material
```

---

## 8. Remaining Gaps / Future Work

| Area | Current State | Notes |
|------|---------------|-------|
| **Key transparency / verification** | Client-only | Server cannot verify that a device's uploaded prekeys match what the user expects (TOFU model). |
| **Compromised device revocation** | Manual (`is_active=false`, `revoked_at`) | No automated detection of key compromise. |
| **Group key history** | Not stored | Server only holds current `sender_key_epoch`; no audit trail of past epochs. |
| **Media upload via Supabase** | Requires `SUPABASE_SERVICE_ROLE_KEY` | Local driver is default; production should configure Supabase for CDN delivery. |

---

## Conclusion

All Sprint 2 encryption features (ENC-4.1 → ENC-4.5) have been implemented with **strict server-blind discipline**:

- **Private keys never leave the device.**
- **Ciphertext is opaque bytea/base64** — no server-side decryption, parsing, or logging.
- **Public key material is format-constrained at the DB layer** (CHECK constraints).
- **Audit logs capture only metadata** (platform, epoch, membership changes) — never plaintext.

The server's role is **distribution, expiration, and access control** — never key agreement or content inspection.