-- ============================================================
-- 010_add_account_status.sql
-- Add account_status column to users table for moderation enforcement
-- ============================================================

BEGIN;

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

COMMIT;

-- Verification
-- SELECT column_name, data_type, column_default
-- FROM information_schema.columns
-- WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'account_status';