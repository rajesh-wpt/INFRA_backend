-- ============================================
-- LOGIN-3.10 — Dashboard (admin) auth tables
-- LOGIN-3.12 — Platform-verification audit log
--
-- Additive and idempotent: nothing is dropped. These tables are completely
-- separate from the end-user `users` / `sessions` tables — the two auth
-- systems never share rows or secrets.
--
-- Naming note: `audit_logs` (plural) holds OTP platform-verification events.
-- The moderation log is `audit_log` (singular), a different table with a
-- different writer; do not merge them.
-- ============================================

-- ── 1. dashboard_admins (DB-2.5) ─────────────────────────────
CREATE TABLE IF NOT EXISTS public.dashboard_admins (
    id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email                       varchar(255) NOT NULL,
    password_hash               text NOT NULL,
    role                        varchar(16) NOT NULL DEFAULT 'admin'
                                  CHECK (role IN ('owner', 'admin')),
    is_test_account             boolean NOT NULL DEFAULT false,
    owner_reset_token_hash      text,
    owner_reset_token_expires_at timestamptz,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS dashboard_admins_email_unique
    ON public.dashboard_admins (email);

-- ── 2. dashboard_sessions (DB-2.6) ───────────────────────────
CREATE TABLE IF NOT EXISTS public.dashboard_sessions (
    id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id                  uuid NOT NULL
                                REFERENCES public.dashboard_admins (id) ON DELETE CASCADE,
    token_lookup              varchar(32) NOT NULL,
    refresh_token_hash        varchar(60) NOT NULL,
    refresh_token_expires_at  timestamptz NOT NULL,
    revoked_at                timestamptz,
    ip_address                varchar(45),
    user_agent                text,
    created_at                timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dashboard_sessions_admin_id_idx
    ON public.dashboard_sessions (admin_id);
CREATE INDEX IF NOT EXISTS dashboard_sessions_token_lookup_idx
    ON public.dashboard_sessions (token_lookup);
CREATE INDEX IF NOT EXISTS dashboard_sessions_revoked_at_idx
    ON public.dashboard_sessions (revoked_at);

-- ── 3. audit_logs (LOGIN-3.12) ───────────────────────────────
-- `platform` and `verification_path` are internal only: they are never
-- returned by any non-admin endpoint (the OTP response is identical for all
-- platforms — PRD §5.2 "invisibility requirement").
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type         text NOT NULL,
    phone_number       text,
    platform           text,
    verification_path  text,
    timestamp          timestamptz NOT NULL DEFAULT now(),
    ip_address         text,
    user_agent         text,
    session_id         text,
    metadata           jsonb,
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_logs_timestamp_idx
    ON public.audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS audit_logs_phone_number_idx
    ON public.audit_logs (phone_number);
CREATE INDEX IF NOT EXISTS audit_logs_platform_idx
    ON public.audit_logs (platform);
CREATE INDEX IF NOT EXISTS audit_logs_event_type_idx
    ON public.audit_logs (event_type);

COMMENT ON TABLE public.audit_logs IS
    'LOGIN-3.12 OTP platform-verification audit log. Admin-read only; platform is never client-visible.';
