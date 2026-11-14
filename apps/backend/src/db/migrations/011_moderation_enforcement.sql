-- ============================================================
-- 011_moderation_enforcement.sql
-- Update moderate_report() to enforce moderation actions
-- ============================================================

BEGIN;

-- Drop and recreate the moderate_report function with enforcement logic
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
    -- If this insert fails, the entire statement rolls back
    -- (including the report UPDATE above).
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

-- Wrappers for clarity.
CREATE OR REPLACE FUNCTION public.admin_warn(p_report_id uuid, p_admin_id uuid)
RETURNS void LANGUAGE sql AS $$
    SELECT public.moderate_report(p_report_id, p_admin_id, 'warn');
$$;

CREATE OR REPLACE FUNCTION public.admin_restrict(p_report_id uuid, p_admin_id uuid)
RETURNS void LANGUAGE sql AS $$
    SELECT public.moderate_report(p_report_id, p_admin_id, 'restrict');
$$;

CREATE OR REPLACE FUNCTION public.admin_ban(p_report_id uuid, p_admin_id uuid)
RETURNS void LANGUAGE sql AS $$
    SELECT public.moderate_report(p_report_id, p_admin_id, 'ban');
$$;

CREATE OR REPLACE FUNCTION public.admin_dismiss(p_report_id uuid, p_admin_id uuid)
RETURNS void LANGUAGE sql AS $$
    SELECT public.moderate_report(p_report_id, p_admin_id, 'dismiss');
$$;

COMMIT;