# POST-MIGRATION DATABASE STATE REPORT (Expected)

**Project:** Team Beta Backend  
**Date:** 2026-10-03  
**Status:** Expected state after running 010_add_account_status.sql and 011_moderation_enforcement.sql

---

## Schema After Migrations

### 1. users table — UPDATED
```sql
CREATE TABLE public.users (
    id varchar(64) PRIMARY KEY NOT NULL,
    phone_number varchar(20) NOT NULL,
    name varchar(100) NOT NULL DEFAULT '',
    photo text,
    about text,
    account_status account_status NOT NULL DEFAULT 'active',  -- NEW
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_phone_number_unique ON public.users (phone_number);
CREATE INDEX users_phone_number_idx ON public.users (phone_number);
CREATE INDEX users_account_status_idx ON public.users (account_status);  -- NEW
```

### 2. sessions table — UNCHANGED (but now actively used for enforcement)
```sql
-- Same as pre-migration, but revoked_at will be SET by moderate_report() on ban
```

### 3. reports table — UNCHANGED
```sql
-- Same as pre-migration
```

### 4. audit_log table — UNCHANGED
```sql
-- Same as pre-migration
```

### 5. New Enum
```sql
CREATE TYPE public.account_status AS ENUM ('active', 'banned', 'restricted', 'warned');
```

### 6. Updated moderate_report() Function — FULL ENFORCEMENT
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
    -- Load the reported phone hash
    SELECT reported_phone_hash INTO v_reported_hash
    FROM public.reports
    WHERE id = p_report_id;

    IF v_reported_hash IS NULL THEN
        RAISE EXCEPTION 'report % not found', p_report_id
            USING ERRCODE = 'P0002';
    END IF;

    -- Find target user by phone hash
    SELECT id INTO v_target_user_id
    FROM public.users
    WHERE public.phone_hash(phone_number) = v_reported_hash
    LIMIT 1;

    IF v_target_user_id IS NULL THEN
        RAISE EXCEPTION 'target user not found for phone hash %', v_reported_hash
            USING ERRCODE = 'P0002';
    END IF;

    -- Update report status
    UPDATE public.reports
    SET status = CASE p_action
            WHEN 'dismiss' THEN 'dismissed'::public.report_status
            ELSE 'actioned'::public.report_status
        END,
        actioned_at = now(),
        reviewed_at = COALESCE(reviewed_at, now())
    WHERE id = p_report_id;

    -- Write audit log (same transaction)
    INSERT INTO public.audit_log (dashboard_admin_id, report_id, action, acted_at)
    VALUES (p_admin_id, p_report_id, p_action, now());

    -- ENFORCEMENT LOGIC
    CASE p_action
        WHEN 'ban' THEN
            UPDATE public.users
            SET account_status = 'banned'::public.account_status,
                updated_at = now()
            WHERE id = v_target_user_id;

            UPDATE public.sessions
            SET revoked_at = now()
            WHERE user_id = v_target_user_id
              AND revoked_at IS NULL;

            GET DIAGNOSTICS v_revoked_count = ROW_COUNT;
            RAISE NOTICE 'BAN enforced: user % banned, % sessions revoked', v_target_user_id, v_revoked_count;

        WHEN 'restrict' THEN
            UPDATE public.users
            SET account_status = 'restricted'::public.account_status,
                updated_at = now()
            WHERE id = v_target_user_id;

            RAISE NOTICE 'RESTRICT enforced: user % restricted', v_target_user_id;

        WHEN 'warn' THEN
            UPDATE public.users
            SET account_status = 'warned'::public.account_status,
                updated_at = now()
            WHERE id = v_target_user_id;

            RAISE NOTICE 'WARN enforced: user % warned', v_target_user_id;

        WHEN 'dismiss' THEN
            RAISE NOTICE 'DISMISS: report % dismissed, no user effect', p_report_id;
    END CASE;

    RETURN;
END;
$$;
```

---

## Enforcement Behavior Matrix

| Action | Report Status | Audit Log | User account_status | Sessions | Login | API Access |
|--------|--------------|-----------|---------------------|----------|-------|------------|
| **BAN** | 'actioned' | ✅ 'ban' | **'banned'** | **ALL REVOKED** | ❌ 401 | ❌ 401 |
| **RESTRICT** | 'actioned' | ✅ 'restrict' | **'restricted'** | Unchanged | ✅ 200* | ❌ 403 |
| **WARN** | 'actioned' | ✅ 'warn' | **'warned'** | Unchanged | ✅ 200 | ✅ 200 |
| **DISMISS** | 'dismissed' | ✅ 'dismiss' | Unchanged ('active') | Unchanged | ✅ 200 | ✅ 200 |

*Restricted users can authenticate but get 403 on API calls

---

## Application Layer Enforcement Points

### 1. Auth Middleware (`src/middleware/auth.ts`)
```typescript
// Runs on EVERY authenticated API request
const [user] = await db
  .select({ accountStatus: users.accountStatus })
  .from(users)
  .where(eq(users.id, payload.sub))
  .limit(1);

if (user.accountStatus === "banned") {
  return res.status(401).json({ error: "ACCOUNT_BANNED" });
}
if (user.accountStatus === "restricted") {
  return res.status(403).json({ error: "ACCOUNT_RESTRICTED" });
}
```

### 2. OTP Verify (`src/routes/onboarding.ts`)
```typescript
// Runs BEFORE issuing any tokens
const [existingUser] = await db
  .select({ id: users.id, accountStatus: users.accountStatus })
  .from(users)
  .where(eq(users.phoneNumber, phoneNumber))
  .limit(1);

if (existingUser && existingUser.accountStatus === "banned") {
  return res.status(401).json({ error: "ACCOUNT_BANNED" });
}
```

### 3. Refresh Token Validation (`src/auth/refresh-token.ts`)
```typescript
// Runs on EVERY token refresh attempt
const [user] = await db
  .select({ accountStatus: users.accountStatus })
  .from(users)
  .where(eq(users.id, row.userId))
  .limit(1);

if (!user || user.accountStatus === "banned") {
  return null; // Causes 401 on /onboarding/refresh
}
```

---

## Expected Verification Results

Running `verify-moderation-enforcement-final.sql` should produce:

### Test 1: BAN
```
Report status: 'actioned' ✅
Audit log: action='ban' ✅
Session revoked_at: <timestamp> (NOT NULL) ✅
User account_status: 'banned' ✅
```

### Test 2: RESTRICT
```
Report status: 'actioned' ✅
Audit log: action='restrict' ✅
User account_status: 'restricted' ✅
Session revoked_at: NULL (unchanged) ✅
```

### Test 3: WARN
```
Report status: 'actioned' ✅
Audit log: action='warn' ✅
User account_status: 'warned' ✅
Session revoked_at: NULL (unchanged) ✅
```

### Test 4: DISMISS
```
Report status: 'dismissed' ✅
Audit log: action='dismiss' ✅
User account_status: 'active' (unchanged) ✅
Session revoked_at: NULL (unchanged) ✅
```

### Test 5: CONTROL (no action)
```
User account_status: 'active' ✅
Session revoked_at: NULL ✅
```

---

## Edge Case: Banned User with Active Session

**Scenario:** User has active session, admin issues BAN

**Before Migration:**
- Session stays active until expiry (30 days)
- User can continue using API with valid access token
- Refresh token works until expiry

**After Migration:**
1. `moderate_report(..., 'ban')` executes in single transaction:
   - `users.account_status = 'banned'`
   - `sessions.revoked_at = now()` for ALL active sessions
2. Next API request:
   - Access token still valid (1hr expiry) → middleware checks `account_status` → **401 ACCOUNT_BANNED**
3. Next refresh attempt:
   - `validateRefreshToken()` checks `account_status` → returns null → **401 INVALID_REFRESH_TOKEN**
4. Next login attempt:
   - OTP verify checks `account_status` before issuing tokens → **401 ACCOUNT_BANNED**

---

## Indexes for Performance

```sql
-- New index for fast banned/restricted user lookups
CREATE INDEX users_account_status_idx ON public.users (account_status);

-- Existing indexes still used:
-- sessions_user_id_idx — for revokeAllUserSessions()
-- sessions_token_lookup_idx — for validateRefreshToken()
-- audit_log_admin_idx, audit_log_report_idx — for audit queries
```

---

## Rollback Plan (if needed)

```sql
-- 1. Drop updated function, restore original
DROP FUNCTION public.moderate_report(uuid, uuid, public.audit_action);
DROP FUNCTION public.admin_warn(uuid, uuid);
DROP FUNCTION public.admin_restrict(uuid, uuid);
DROP FUNCTION public.admin_ban(uuid, uuid);
DROP FUNCTION public.admin_dismiss(uuid, uuid);

-- Run original from 005_fix_reports_and_moderation.sql

-- 2. Drop account_status column
ALTER TABLE public.users DROP COLUMN IF EXISTS account_status;
DROP INDEX IF EXISTS users_account_status_idx;

-- 3. Drop enum type
DROP TYPE IF EXISTS public.account_status;
```

---

## Deployment Order

1. **Run 010_add_account_status.sql** — Adds column + enum
2. **Run 011_moderation_enforcement.sql** — Updates function
3. **Verify** — Run verification script
4. **Deploy backend code** — TypeScript changes already in place
5. **Test** — Manual verification of each action

---

**Note:** The backend TypeScript code changes are already implemented and will work immediately once the database migrations are applied. No additional code deployment is needed beyond the standard build/deploy process.