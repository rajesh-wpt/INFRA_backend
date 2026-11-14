# Team Beta: Sprint 2 Backend Status

Source: WPT Chat App Task Status Report, Sprint 2 - Backend (Login and Encryption), as of 14 November 2026

## Part 1: Not Done

### Sprint 2: Backend (Login and Encryption)

| Task | Status | Issue and next step |
|---|---|---|
| LOGIN-3.10 Dashboard auth | Partial | Admin login/me exist but the router is not mounted, and there is no refresh or logout. Next: collapse the two auth middlewares to one, mount the router, add refresh/logout (port steps P4, P8). |
| LOGIN-3.12 Platform verification audit log | Partial | audit_logs exists but nothing writes rows. Next: write one row per privileged action on the auth path that survives the middleware merge, then verify (P4, P8). |
| ENC-4.1 Prekey tables + rotation | Partial | Only on enc/prekey-bundle, and its server-side rotation cannot work for encryption. Next: devices upload public prekeys when low, the server stores and expires them, schedule the maintenance job, fix the card wording (P0, P7). |
| ENC-4.2 Prekey-bundle fetch endpoint | Partial | Built and verified on enc/prekey-bundle only; Team-Beta and main have no prekey tables or endpoint, so it was listed Done but cannot run. Next: port it with ENC-4.1 (P1, P7). |
| ENC-4.3 sender_key_epoch on departure | Partial | Only on enc/prekey-bundle. Next: port together with the group-table merge (P6). |
| ENC-4.4 Group key ciphertext storage | Partial | Only on enc/prekey-bundle, and it touches the same group tables as moderation (BE-5.7). Next: hand-merge the columns, keep the moderation fields (P6). |
| ENC-4.5 Group icon via encrypted media | Partial | Only on enc/prekey-bundle and needs storage credentials. Next: pick the provider and a dev credential, then port (P0, P6). |
| ENC-4.6 Server-blind audit | Unknown | No written audit, and it audits code that is not on this branch. Next: assign after ENC-4.1/4.2/4.3/4.4/4.5 land (P9). |

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
| LOGIN-3.11 Audience rejection at endpoints | Sprint 2 (Backend) | Separate signing keys |

Sprint 2 backend: 10 of 18 cards done. The remaining 8 all depend on the enc/prekey-bundle port (P0-P9 in docs/SPRINT2_LOGIN_STATUS.md section 4). ENC-4.2 was listed Done but exists only on that branch, so it moved back to Not Done until it is ported and exercised on Team-Beta.
