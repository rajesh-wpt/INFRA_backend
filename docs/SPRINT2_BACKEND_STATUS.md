# Team Beta: Sprint 2 Backend Status

Source: WPT Chat App Task Status Report, Sprint 2 - Backend (Login and Encryption), as of 14 November 2026

## Part 1: Not Done

### Sprint 2: Backend (Login and Encryption)

| Task | Status | Issue and next step |
|---|---|---|

## Part 2: Done

| Task | Sprint | Note |
|---|---|---|
| LOGIN-3.1 JWT access token (1 hour) | Sprint 2 (Backend) | On main |
| LOGIN-3.2 Refresh token hashing + revocation | Sprint 2 (Backend) | Rotation and reuse detection |
| LOGIN-3.3 Server-side legal gate | Sprint 2 (Backend) | On main |
| LOGIN-3.4 Existing-account branch | Sprint 2 (Backend) | On main |
| LOGIN-3.5 OTP + SMS gateway | Sprint 2 (Backend) | Twilio removed; authenticated poll/ack on sms_outbox; code stored as AES-256-GCM ciphertext and cleared on ack; 13/13 gateway checks |
| LOGIN-3.6 Attempts / lockout / resend | Sprint 2 (Backend) | OTP row deleted in handoff transaction; /otp/send now atomic |
| LOGIN-3.7 New-device handoff transaction | Sprint 2 (Backend) | Real platform and key, server-owned device id, superseded device revoked; 12/12 checks plus a real phone |
| LOGIN-3.8 force_logout push | Sprint 2 (Backend) | Socket path fixed; verified on hardware - a second-device login returns the phone to phone-entry |
| LOGIN-3.9 Resume-time validation | Sprint 2 (Backend) | Retested after ONB-1.7; also fixed cold-start re-onboarding and self-logout on same-device re-login |
| LOGIN-3.10 Dashboard auth | Sprint 2 (Backend) | Login, refresh, logout, /me, admin management (create/list/delete), audit log read — mounted at /api/v1/admin behind requireDashboardAuth (separate secret DASHBOARD_JWT_SECRET, aud: "dashboard"). |
| LOGIN-3.11 Audience rejection at endpoints | Sprint 2 (Backend) | Separate signing keys |
| LOGIN-3.12 Platform verification audit log | Sprint 2 (Backend) | audit_logs table + audit-logger.ts; POST /onboarding/otp/send writes platform/verification_path (android_sim/sim_check vs ios_otp/otp_sms) — never client-visible; admin read via GET /admin/audit/otp. |
| ENC-4.1 Prekey tables + device upload + maintenance | Sprint 2 (Backend) | signed_prekeys, one_time_prekeys (public halves only, CHECK constraints); POST /prekeys/upload (identity key, signed prekey, one-time batch), GET /prekeys/status; in-process maintenance job (prekey-maintenance.ts + scheduler) expires stale keys, prunes superseded signed prekeys, reports devices needing refill/rotation — no server-side key generation. |
| ENC-4.2 Prekey-bundle fetch | Sprint 2 (Backend) | POST /prekey-bundle/:deviceId returns identity key + current signed prekey + ONE one-time prekey (deleted atomically with FOR UPDATE SKIP LOCKED); remainingOneTimePrekeys + recipientNeedsReplenish hint. |
| ENC-4.3 sender_key_epoch on departure | Sprint 2 (Backend) | Atomic DELETE group_members + UPDATE groups SET sender_key_epoch = sender_key_epoch + 1 in single transaction; add never bumps epoch; owner cannot be removed; 70-member cap under row lock. |
| ENC-4.4 Group key ciphertext storage | Sprint 2 (Backend) | groups.encrypted_name/description/icon_ref stored/returned as opaque bytea (base64 on wire); encrypted_icon_ref validated against MEDIA_NAME_RE before storage use; who_can_send enum. |
| ENC-4.5 Group icon via encrypted media | Sprint 2 (Backend) | PUT /media/group-icons/:name (app auth, local driver stores ciphertext), GET /media/:bucket/:name?exp=&sig= (HMAC-SHA256 signed URL, application/octet-stream, no-store); local filesystem driver default (no creds), Supabase driver when SUPABASE_URL+SERVICE_ROLE_KEY set. |
| ENC-4.6 Server-blind audit | Sprint 2 (Backend) | Written audit at docs/ENC_SERVER_BLIND_AUDIT.md — code paths reviewed: prekey routes, group metadata, media, bundle fetch, maintenance job; DB CHECK constraints enforce public-only; no private key generation, no decryption, no plaintext logging. |

Sprint 2 backend: 18 of 18 cards done. All encryption cards (ENC-4.1 ENC-4.6) and dashboard/audit cards (LOGIN-3.10, LOGIN-3.12) implemented, tested, and verified on Team-Beta branch. The port from enc/prekey-bundle was completed by hand (no blind merge), with corrections: server-side key rotation removed (devices upload public prekeys; maintenance only expires stale keys), group enum unified to group_role (live DB) with idempotent migration 016_groups_encryption_alignment.sql, media driver abstraction (local filesystem for dev, Supabase when credentials present), dashboard auth uses separate secret (DASHBOARD_JWT_SECRET) and audience (aud: "dashboard") mounted at /api/v1/admin. All 33 login E2E tests + 50+ encryption E2E tests pass.
