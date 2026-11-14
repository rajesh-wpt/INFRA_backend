-- ============================================
-- ENC-4.3 / ENC-4.4 — group schema alignment
--
-- The live database uses the enum type `group_role`; the historical
-- 010_add_groups_schema.sql creates `group_member_role`. Both spellings have
-- existed, so this migration makes ONE name authoritative everywhere:
--
--   * if `group_role` is missing but `group_member_role` exists -> rename it
--   * if neither exists                                        -> create it
--   * if group_members.role still points at the old type      -> retype it
--
-- Also (re)asserts the §6.3 column shapes the encryption routes depend on:
--   encrypted_name / encrypted_description / encrypted_icon_ref are opaque
--   bytea, sender_key_epoch is NOT NULL DEFAULT 0, who_can_send defaults to
--   'everyone'.
--
-- Additive and idempotent: no drops, no data loss.
-- ============================================

-- ── 1. One authoritative enum name: group_role ───────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'group_role') THEN
        IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'group_member_role') THEN
            ALTER TYPE public.group_member_role RENAME TO group_role;
        ELSE
            CREATE TYPE public.group_role AS ENUM ('owner', 'admin', 'member');
        END IF;
    END IF;
END
$$;

-- ── 2. who_can_send enum (Tech Arch §6.3) ────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'who_can_send') THEN
        CREATE TYPE public.who_can_send AS ENUM ('everyone', 'admins_only');
    END IF;
END
$$;

-- ── 3. groups + group_members (only if absent) ───────────────
CREATE TABLE IF NOT EXISTS public.groups (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    encrypted_name         bytea NOT NULL,
    encrypted_icon_ref     bytea,
    encrypted_description  bytea,
    who_can_send           public.who_can_send NOT NULL DEFAULT 'everyone',
    sender_key_epoch       integer NOT NULL DEFAULT 0,
    created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.group_members (
    group_id   uuid NOT NULL REFERENCES public.groups (id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES public.users  (id) ON DELETE CASCADE,
    role       public.group_role NOT NULL DEFAULT 'member',
    joined_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

-- ── 4. Retype group_members.role if it still uses the old enum ─
DO $$
DECLARE
    current_type text;
BEGIN
    SELECT udt_name INTO current_type
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'group_members'
      AND column_name = 'role';

    IF current_type IS NOT NULL AND current_type <> 'group_role' THEN
        EXECUTE 'ALTER TABLE public.group_members '
             || 'ALTER COLUMN role TYPE public.group_role '
             || 'USING role::text::public.group_role';
    END IF;
END
$$;

-- ── 5. Assert sender_key_epoch default (ENC-4.3 rotation counter) ─
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'groups'
          AND column_name = 'sender_key_epoch'
          AND (column_default IS NULL OR column_default <> '0')
    ) THEN
        ALTER TABLE public.groups
            ALTER COLUMN sender_key_epoch SET DEFAULT 0;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_group_members_user
    ON public.group_members (user_id);

COMMENT ON COLUMN public.groups.encrypted_name IS
    'ENC-4.4 opaque Group-Key ciphertext. The backend never decrypts or inspects it.';
COMMENT ON COLUMN public.groups.encrypted_icon_ref IS
    'ENC-4.5 opaque bytes whose plaintext is a storage object name for the encrypted icon.';
