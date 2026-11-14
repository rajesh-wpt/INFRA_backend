# PRE-MIGRATION DATABASE STATE REPORT

**Project:** Team Beta Backend  
**Date:** 2026-10-03  
**Database:** Supabase PostgreSQL  
**Connection:** postgres.ukmsgzvkvcsbhtlmvswr @ aws-0-ap-southeast-1.pooler.supabase.com:6543

---

## Current Schema (from TypeScript definitions + existing migrations)

### 1. users table
```sql
-- From migrate-users.ts + users-schema.ts
CREATE TABLE public.users (
    id varchar(64) PRIMARY KEY NOT NULL,
    phone_number varchar(20) NOT NULL,
    name varchar(100) NOT NULL DEFAULT '',
    photo text,
    about text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_phone_number_unique ON public.users (phone_number);
CREATE INDEX users_phone_number_idx ON public.users (phone_number);
```
**Missing:** `account_status` column

### 2. sessions table
```sql
-- From sessions-schema.ts
CREATE TABLE public.sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id varchar(64) NOT NULL,
    device_id varchar(64) NOT NULL,
    token_lookup varchar(32) NOT NULL,
    refresh_token_hash varchar(60) NOT NULL,
    refresh_token_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user_id_idx ON public.sessions (user_id);
CREATE INDEX sessions_token_lookup_idx ON public.sessions (token_lookup);
```

### 3. reports table
```sql
-- From reports-schema.ts + 005_fix_reports_and_moderation.sql
CREATE TABLE public.reports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_phone_hash text NOT NULL,
    reported_phone_hash text NOT NULL,
    status report_status NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    reviewed_at timestamptz,
    actioned_at timestamptz,
    decrypted_message_snapshot jsonb
);

CREATE INDEX reports_reporter_phone_hash_idx ON public.reports (reporter_phone_hash);
CREATE INDEX reports_reported_phone_hash_idx ON public.reports (reported_phone_hash);
CREATE INDEX reports_status_idx ON public.reports (status);
```

### 4. audit_log table
```sql
-- From audit-log-schema.ts + 005_fix_reports_and_moderation.sql
CREATE TABLE public.audit_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    dashboard_admin_id uuid REFERENCES public.dashboard_admins(id) ON DELETE SET NULL,
    report_id uuid REFERENCES public.reports(id) ON DELETE SET NULL,
    action audit_action NOT NULL,
    acted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_admin_idx ON public.audit_log (dashboard_admin_id);
CREATE INDEX audit_log_report_idx ON public.audit_log (report_id);
CREATE INDEX audit_log_acted_at_idx ON public.audit_log (acted_at);
```

### 5. Current moderate_report() function
```sql
-- From 005_fix_reports_and_moderation.sql (lines 321-362)
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
    SELECT reported_phone_hash INTO v_reported_hash
    FROM public.reports
    WHERE id = p_report_id;

    IF v_reported_hash IS NULL THEN
        RAISE EXCEPTION 'report % not found', p_report_id
            USING ERRCODE = 'P0002';
    END IF;

    UPDATE public.reports
    SET status = CASE p_action
            WHEN 'dismiss' THEN 'dismissed'::public.report_status
            ELSE 'actioned'::public.report_status
        END,
        actioned_at = now(),
        reviewed_at = COALESCE(reviewed_at, now())
    WHERE id = p_report_id;

    INSERT INTO public.audit_log (dashboard_admin_id, report_id, action, acted_at)
    VALUES (p_admin_id, p_report_id, p_action, now());

    RETURN;
END;
$$;
```

**Current Behavior:**
- ✅ Updates report status (pending → actioned/dismissed)
- ✅ Sets actioned_at / reviewed_at timestamps
- ✅ Writes audit_log row in same transaction
- ❌ Does NOT update user account status
- ❌ Does NOT revoke sessions
- ❌ Does NOT block future logins
- ❌ Does NOT enforce restrictions

### 6. Enums
```sql
CREATE TYPE public.report_status AS ENUM ('pending', 'reviewed', 'actioned', 'dismissed');
CREATE TYPE public.audit_action AS ENUM ('warn', 'restrict', 'ban', 'dismiss');
```
**Missing:** `account_status` enum

### 7. Other relevant tables

#### dashboard_admins
```sql
-- From dashboard-admins-schema.ts
CREATE TABLE public.dashboard_admins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'admin')),
    is_test_account boolean NOT NULL DEFAULT false,
    owner_reset_token_hash text
);
```

#### blocks
```sql
-- From blocks-schema.ts
CREATE TABLE public.blocks (
    blocker_phone_hash text NOT NULL,
    blocked_phone_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_phone_hash, blocked_phone_hash)
);
```

---

## Current Sample Data (from SQL editor output)

### sessions table (10 rows)
| id | user_id | revoked_at |
|----|---------|------------|
| 64b30dd4... | f59b23d0... | 2026-10-02 07:50:36.712+00 |
| 3c065c80... | f59b23d0... | 2026-10-02 08:22:18.686+00 |
| 4fad4558... | b14db3f5... | 2026-10-02 08:26:13.731+00 |
| da4bb463... | b14db3f5... | 2026-10-02 08:37:27.784+00 |
| 2640c1d8... | b14db3f5... | 2026-10-02 08:56:47.215+00 |
| 570b9bee... | 463b1f9d... | NULL (ACTIVE) |
| 1c31b21d... | 5dcbd3d3... | NULL (ACTIVE) |
| df57af6d... | 5dcbd3d3... | 2026-10-02 16:55:05.387+00 |
| bb400696... | 74a71f8e... | 2026-10-03 06:38:48.631+00 |
| d46dfbb5... | f59b23d0... | 2026-10-02 07:53:37.952+00 |

**Active sessions:** 2 (user_ids: 463b1f9d..., 5dcbd3d3...)

---

## What Will Change After Migrations

### New Column: users.account_status
```sql
ALTER TABLE public.users ADD COLUMN account_status account_status NOT NULL DEFAULT 'active';
```

### New Enum
```sql
CREATE TYPE account_status AS ENUM ('active', 'banned', 'restricted', 'warned');
```

### Updated moderate_report() - Will Add Enforcement
```sql
-- Ban: account_status = 'banned' + revoke all sessions
-- Restrict: account_status = 'restricted'
-- Warn: account_status = 'warned'
-- Dismiss: no user changes
```

### Application Layer (already coded)
- Auth middleware: rejects banned (401) / restricted (403)
- OTP verify: rejects banned before token issuance
- Refresh token: rejects banned on token validation

---

## Verification Queries to Run Post-Migration

```sql
-- 1. Verify account_status column exists
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'account_status';

-- 2. Verify enum type
SELECT enumlabel FROM pg_enum
JOIN pg_type ON pg_enum.enumtypid = pg_type.oid
WHERE pg_type.typname = 'account_status'
ORDER BY enumsortorder;

-- 3. Verify moderate_report function updated
SELECT prosrc FROM pg_proc WHERE proname = 'moderate_report';

-- 4. Test enforcement (run verification script)
-- \i verify-moderation-enforcement-final.sql
```