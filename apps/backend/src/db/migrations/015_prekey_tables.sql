-- ============================================
-- ENC-4.1 — Prekey tables (PUBLIC halves only)
-- ENC-4.2 — Bundle fetch consumes these rows
--
-- The server stores, serves and expires public prekeys that the DEVICES
-- generate and upload. It never generates, receives or processes private key
-- material (Tech Arch §8.8). The format CHECK constraints make the "public
-- only" rule structural: a value that is not base64 of the right shape cannot
-- be stored at all, so there is no column anywhere that could hold a private
-- key.
--
--   signed_prekeys    device_id, key_id, public_key, signature, created_at
--                     — rotated weekly by the device (§8.3); exactly one row
--                       per device is served (highest key_id).
--   one_time_prekeys  device_id, key_id, public_key, consumed_at, created_at
--                     — batch of 100 per device, refilled below 20 (§8.3);
--                       hard-deleted the moment a bundle serves it.
--
-- Additive and idempotent: the `devices` prerequisite already exists
-- (DB-2.2). Nothing is dropped.
-- ============================================

-- ── 1. signed_prekeys ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.signed_prekeys (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   uuid NOT NULL
                  REFERENCES public.devices (id) ON DELETE CASCADE,
    key_id      integer NOT NULL CHECK (key_id > 0),
    public_key  text NOT NULL
                  CHECK (public_key ~ '^[A-Za-z0-9/+=_-]{40,128}$'),
    signature   text NOT NULL
                  CHECK (signature ~ '^[A-Za-z0-9/+=_-]{40,128}$'),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (device_id, key_id)
);

CREATE INDEX IF NOT EXISTS signed_prekeys_device_id_idx
    ON public.signed_prekeys (device_id, key_id);
CREATE INDEX IF NOT EXISTS signed_prekeys_created_at_idx
    ON public.signed_prekeys (device_id, created_at);

-- ── 2. one_time_prekeys ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.one_time_prekeys (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   uuid NOT NULL
                  REFERENCES public.devices (id) ON DELETE CASCADE,
    key_id      integer NOT NULL CHECK (key_id > 0),
    public_key  text NOT NULL
                  CHECK (public_key ~ '^[A-Za-z0-9/+=_-]{40,128}$'),
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (device_id, key_id)
);

CREATE INDEX IF NOT EXISTS one_time_prekeys_device_id_idx
    ON public.one_time_prekeys (device_id, key_id);
CREATE INDEX IF NOT EXISTS one_time_prekeys_unconsumed_idx
    ON public.one_time_prekeys (device_id, consumed_at);

COMMENT ON TABLE public.signed_prekeys IS
    'ENC-4.1 public signed prekeys uploaded by devices. No private key material is ever stored.';
COMMENT ON TABLE public.one_time_prekeys IS
    'ENC-4.1 public one-time prekeys uploaded by devices; deleted when a bundle serves them.';
