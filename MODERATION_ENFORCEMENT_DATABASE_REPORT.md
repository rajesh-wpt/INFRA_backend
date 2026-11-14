# Moderation Enforcement Database Migration Report

**Project:** Team Beta Backend  
**Date:** 2026-10-03  
**Database:** Supabase PostgreSQL (postgres.ukmsgzvkvcsbhtlmvswr)  
**Status:** Migrations prepared, pending execution (auth issue to resolve)

---

## Executive Summary

This report documents the database schema changes required to implement **real enforcement** of moderation actions (warn/restrict/ban/dismiss) as specified in the Trello card. The current `moderate_report()` function only logs to `audit_log` and updates report status — it does **not** enforce any real-world effects on user accounts or sessions.

Two migrations have been prepared:
1. **010_add_account_status.sql** — Adds `account_status` enum column to `users` table
2. **011_moderation_enforcement.sql** — Updates `moderate_report()` to enforce ban/restrict/warn/dismiss

---

## 1. PRE-MIGRATION DATABASE STATE (Current)

### 1.1 Users Table (`public.users`)

| Column | Type | Nullable | Default | Notes |
|--------|------|----------|---------|-------|
| id | varchar(64) | NO | — | Primary key |
| phone_number | varchar(20) | NO | — | Unique index |
| name | varchar(100) | NO | '' | |
| photo | text | YES | NULL | |
| about | text | YES | NULL | |
| created_at | timestamptz | NO | now() | |
| updated_at | timestamptz | NO | now() | Auto-updated |

**Missing:** `account_status` column — no way to track banned/restricted/warned state

### 1.2 Sessions Table (`public.sessions`)

| Column | Type | Nullable | Default | Notes |
|--------|------|----------|---------|-------|
| id | uuid | NO | gen_random_uuid() | Primary key |
| user_id | varchar(64) | NO | — | FK to users.id |
| device_id | varchar(64) | NO | — | |
| token_lookup | varchar(32) | NO | — | SHA-256 prefix for indexing |
| refresh_token_hash | varchar(60) | NO | — | bcrypt hash |
| refresh_token_expires_at | timestamptz | NO | — | 30 days from issuance |
| revoked_at | timestamptz | YES | NULL | **Kill-switch** — non-null = revoked |
| created_at | timestamptz | NO | now() | |

**Indexes:** `sessions_user_id_idx`, `sessions_token_lookup_idx`

### 1.3 Reports Table (`public.reports`)

| Column | Type | Nullable | Default | Notes |
|--------|------|----------|---------|-------|
| id | uuid | NO | gen_random_uuid() | Primary key |
| reporter_phone_hash | text | NO | — | |
| reported_phone_hash | text | NO | — | |
| status | report_status enum | NO | 'pending' | Enum: pending, reviewed, actioned, dismissed |
| created_at | timestamptz | NO | now() | |
| reviewed_at | timestamptz | YES | NULL | |
| actioned_at | timestamptz | YES | NULL | |
| decrypted_message_snapshot | jsonb | YES | NULL | |

### 1.4 Audit Log Table (`public.audit_log`)

| Column | Type | Nullable | Default | Notes |
|--------|------|----------|---------|-------|
| id | uuid | NO | gen_random_uuid() | Primary key |
| dashboard_admin_id | uuid | YES | NULL | FK to dashboard_admins (SET NULL) |
| report_id | uuid | YES | NULL | FK to reports (SET NULL) |
| action | audit_action enum | NO | — | Enum: warn, restrict, ban, dismiss |
| acted_at | timestamptz | NO | now() | |

### 1.5 Current `moderate_report()` Function (LIMITED)

```sql
CREATE OR REPLACE FUNCTION public.moderate_report(
    p_report_id      uuid,
    p_admin_id       uuid,
    p_action         public.audit_action
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    v_reported_hash text;
BEGIN
    -- Load the reported phone hash for this report.
    SELECT reported_phone_hash INTO v_reported_hash
    FROM public.reports
    WHERE id = p_report_id;

    IF v_reported_hash IS NULL THEN
        RAISE EXCEPTION 'report % not found', p_report_id
            USING ERRCODE = 'P0002';
    END IF;

    -- Update the report row itself.
    UPDATE public.reports
    SET status = CASE p_action
            WHEN 'dismiss' THEN 'dismissed'::public.report_status
            ELSE 'actioned'::public.report_status
        END,
        actioned_at = now(),
        reviewed_at = COALESCE(reviewed_at, now())
    WHERE id = p_report_id;

    -- Write the audit trail in the SAME transaction.
    INSERT INTO public.audit_log (dashboard_admin_id, report_id, action, acted_at)
    VALUES (p_admin_id, p_report_id, p_action, now());

    RETURN;
END;
$$;
```

**GAPS IDENTIFIED:**
- ❌ Does NOT update `users.account_status` (column doesn't exist)
- ❌ Does NOT revoke sessions on ban
- ❌ Does NOT block login for banned users
- ❌ Does NOT enforce restrictions on restricted users
- ❌ Only updates `reports.status` and logs to `audit_log`

---

## 2. MIGRATIONS TO APPLY

### 2.1 Migration 010: Add Account Status Column

```sql
-- Create enum type for account status
CREATE TYPE public.account_status AS ENUM ('active', 'banned', 'restricted', 'warned');

-- Add account_status column to users table
ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS account_status public.account_status NOT NULL DEFAULT 'active';

-- Add index for fast lookups on banned/restricted users
CREATE INDEX IF NOT EXISTS users_account_status_idx ON public.users (account_status);

-- Same for test_users if it exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'test_users') THEN
        ALTER TABLE public.test_users
            ADD COLUMN IF NOT EXISTS account_status public.account_status NOT NULL DEFAULT 'active';
        CREATE INDEX IF NOT EXISTS test_users_account_status_idx ON public.test_users (account_status);
    END IF;
END $$;
```

### 2.2 Migration 011: Update moderate_report() with Enforcement

```sql
CREATE OR REPLACE FUNCTION public.moderate_report(
    p_report_id      uuid,
    p_admin_id       uuid,
    p_action         public.audit_action
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    v_reported_hash text;
    v_target_user_id varchar(64);
    v_revoked_count integer;
BEGIN
    -- Load the reported phone hash for this report.
    SELECT reported_phone_hash INTO v_reported_hash
    FROM public.reports
    WHERE id = p_report_id;

    IF v_reported_hash IS NULL THEN
        RAISE EXCEPTION 'report % not found', p_report_id
            USING ERRCODE = 'P0002';
    END IF;

    -- Find the target user by phone hash
    SELECT id INTO v_target_user_id
    FROM public.users
    WHERE public.phone_hash(phone_number) = v_reported_hash
    LIMIT 1;

    IF v_target_user_id IS NULL THEN
        RAISE EXCEPTION 'target user not found for phone hash %', v_reported_hash
            USING ERRCODE = 'P0002';
    END IF;

    -- Update the report row itself.
    UPDATE public.reports
    SET status = CASE p_action
            WHEN 'dismiss' THEN 'dismissed'::public.report_status
            ELSE 'actioned'::public.report_status
        END,
        actioned_at = now(),
        reviewed_at = COALESCE(reviewed_at, now())
    WHERE id = p_report_id;

    -- Write the audit trail in the SAME transaction.
    INSERT INTO public.audit_log (dashboard_admin_id, report_id, action, acted_at)
    VALUES (p_admin_id, p_report_id, p_action, now());

    -- ENFORCEMENT LOGIC: Apply real-world effects based on action
    CASE p_action
        WHEN 'ban' THEN
            -- Ban: set account_status to banned AND revoke all active sessions
            UPDATE public.users
            SET account_status = 'banned'::public.account_status,
                updated_at = now()
            WHERE id = v_target_user_id;

            -- Revoke all active sessions for the banned user
            UPDATE public.sessions
            SET revoked_at = now()
            WHERE user_id = v_target_user_id
              AND revoked_at IS NULL;

            GET DIAGNOSTICS v_revoked_count = ROW_COUNT;
            RAISE NOTICE 'BAN enforced: user % banned, % sessions revoked', v_target_user_id, v_revoked_count;

        WHEN 'restrict' THEN
            -- Restrict: set account_status to restricted (capabilities limited)
            UPDATE public.users
            SET account_status = 'restricted'::public.account_status,
                updated_at = now()
            WHERE id = v_target_user_id;

            RAISE NOTICE 'RESTRICT enforced: user % restricted', v_target_user_id;

        WHEN 'warn' THEN
            -- Warn: set account_status to warned (visible but non-blocking)
            UPDATE public.users
            SET account_status = 'warned'::public.account_status,
                updated_at = now()
            WHERE id = v_target_user_id;

            RAISE NOTICE 'WARN enforced: user % warned', v_target_user_id;

        WHEN 'dismiss' THEN
            -- Dismiss: no effect on user account (report closed)
            RAISE NOTICE 'DISMISS: report % dismissed, no user effect', p_report_id;
    END CASE;

    RETURN;
END;
$$;
```

---

## 3. POST-MIGRATION DATABASE STATE (Expected)

### 3.1 Users Table (`public.users`) — UPDATED

| Column | Type | Nullable | Default | Notes |
|--------|------|----------|---------|-------|
| id | varchar(64) | NO | — | Primary key |
| phone_number | varchar(20) | NO | — | Unique index |
| name | varchar(100) | NO | '' | |
| photo | text | YES | NULL | |
| about | text | YES | NULL | |
| **account_status** | **account_status enum** | **NO** | **'active'** | **NEW** |
| created_at | timestamptz | NO | now() | |
| updated_at | timestamptz | NO | now() | Auto-updated |

**New Index:** `users_account_status_idx` on `account_status`

### 3.2 Sessions Table (`public.sessions`) — UNCHANGED (but enforcement now uses it)

Same schema. The `revoked_at` column will now be actively set by `moderate_report()` on ban actions.

### 3.3 Updated `moderate_report()` Function — ENFORCEMENT COMPLETE

**New Behavior per Action:**

| Action | Report Status | Audit Log | User account_status | Sessions Revoked | Login Blocked | API Access |
|--------|---------------|-----------|---------------------|------------------|---------------|------------|
| **ban** | 'actioned' | ✅ 'ban' | **'banned'** | ✅ **All active** | ✅ **Yes** | ❌ 401 |
| **restrict** | 'actioned' | ✅ 'restrict' | **'restricted'** | No | No* | ❌ 403 |
| **warn** | 'actioned' | ✅ 'warn' | **'warned'** | No | No | ✅ 200 |
| **dismiss** | 'dismissed' | ✅ 'dismiss' | **Unchanged** | No | No | ✅ 200 |

*Restricted users can login but get 403 on API calls (handled by middleware)

### 3.4 Application-Layer Enforcement (Already Implemented)

#### Auth Middleware (`src/middleware/auth.ts`)
```typescript
// Checks account_status on EVERY authenticated request
if (user.accountStatus === "banned") {
  return res.status(401).json({ error: "ACCOUNT_BANNED" });
}
if (user.accountStatus === "restricted") {
  return res.status(403).json({ error: "ACCOUNT_RESTRICTED" });
}
```

#### OTP Verify (`src/routes/onboarding.ts`)
```typescript
// Rejects login for banned accounts BEFORE issuing tokens
const [existingUser] = await db
  .select({ id: users.id, accountStatus: users.accountStatus })
  .from(users)
  .where(eq(users.phoneNumber, phoneNumber))
  .limit(1);

if (existingUser && existingUser.accountStatus === "banned") {
  return res.status(401).json({ error: "ACCOUNT_BANNED" });
}
```

#### Refresh Token Validation (`src/auth/refresh-token.ts`)
```typescript
// Rejects token refresh for banned accounts
const [user] = await db
  .select({ accountStatus: users.accountStatus })
  .from(users)
  .where(eq(users.id, row.userId))
  .limit(1);

if (!user || user.accountStatus === "banned") {
  return null; // Causes 401 on refresh endpoint
}
```

---

## 4. VERIFICATION TEST PLAN

The verification script `verify-moderation-enforcement-final.sql` tests all four actions:

### Test Cases

| Test | Action | Expected User Status | Expected Sessions | Expected API Response |
|------|--------|---------------------|-------------------|----------------------|
| 1 | BAN | 'banned' | All revoked (`revoked_at` set) | 401 ACCOUNT_BANNED |
| 2 | RESTRICT | 'restricted' | Unchanged (active) | 403 ACCOUNT_RESTRICTED |
| 3 | WARN | 'warned' | Unchanged (active) | 200 OK |
| 4 | DISMISS | 'active' (unchanged) | Unchanged (active) | 200 OK |
| 5 | CONTROL | 'active' (unchanged) | Unchanged (active) | 200 OK |

### Verification Queries (Post-Migration)

```sql
-- Check ban enforcement
SELECT u.account_status, s.revoked_at
FROM users u
LEFT JOIN sessions s ON s.user_id = u.id
WHERE u.id = 'target_user_id';

-- Expected for banned user:
-- account_status = 'banned'
-- revoked_at = <timestamp> (not null)

-- Check audit log
SELECT * FROM audit_log WHERE report_id = 'report_id';
-- Should have 1 row with action = 'ban'/'restrict'/'warn'/'dismiss'
```

---

## 5. EDGE CASES COVERED

| Edge Case | Handling |
|-----------|----------|
| **Banned user with active session** | Sessions revoked in same transaction as ban; refresh token validation checks `account_status` |
| **Banned user tries to login (OTP verify)** | Rejected before token issuance with `ACCOUNT_BANNED` |
| **Banned user tries to refresh token** | `validateRefreshToken()` returns null → 401 |
| **Restricted user makes API call** | Auth middleware returns 403 `ACCOUNT_RESTRICTED` |
| **Warned user makes API call** | Allowed (200) — warn is non-blocking |
| **Dismissed report** | No user changes; report status = 'dismissed' |
| **Concurrent ban + active request** | Next request hits auth middleware → 401 |

---

## 6. DEPLOYMENT CHECKLIST

- [ ] Resolve Supabase authentication issue (password auth failed)
- [ ] Run migration 010: `010_add_account_status.sql`
- [ ] Run migration 011: `011_moderation_enforcement.sql`
- [ ] Verify `account_status` column exists: `SELECT column_name FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'account_status';`
- [ ] Verify `moderate_report()` updated: `\df+ public.moderate_report`
- [ ] Run verification script: `verify-moderation-enforcement-final.sql`
- [ ] Confirm all 4 actions produce expected enforcement
- [ ] Test banned user login rejection
- [ ] Test restricted user API rejection
- [ ] Test warned user access allowed
- [ ] Test dismissed report no-effect
- [ ] Deploy backend code changes (middleware, onboarding, refresh-token)

---

## 7. FILES MODIFIED IN TEAM BETA FOLDER

### New Migration Files
- `apps/backend/src/db/migrations/010_add_account_status.sql`
- `apps/backend/src/db/migrations/011_moderation_enforcement.sql`
- `apps/backend/src/db/run-migrations.ts` (migration runner)

### Modified Source Files
- `apps/backend/src/db/users-schema.ts` — Added `accountStatus` field + enum
- `apps/backend/src/middleware/auth.ts` — Added banned/restricted checks
- `apps/backend/src/routes/onboarding.ts` — Added banned check on OTP verify
- `apps/backend/src/auth/refresh-token.ts` — Added banned check on token refresh

### Verification Script
- `verify-moderation-enforcement-final.sql` (in DB test folder)

---

## 8. NEXT STEPS

1. **Fix Supabase connection** — The password in `.env` may need updating or use Supabase dashboard SQL Editor directly
2. **Run migrations** — Execute both SQL files in order
3. **Run verification** — Execute the verification script to confirm enforcement works
4. **Deploy backend** — The TypeScript changes are ready; just need database schema updated

---

**Prepared by:** Automated migration preparation  
**Review required:** Database admin to execute migrations and run verification