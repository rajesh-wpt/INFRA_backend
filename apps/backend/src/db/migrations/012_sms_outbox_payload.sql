-- LOGIN-3.5 — self-hosted SMS gateway.
--
-- The outbox previously carried only the OTP hash, which a gateway cannot put
-- in an SMS. Add an encrypted payload column (AES-256-GCM, key in
-- SMS_PAYLOAD_KEY) that is cleared when the gateway acknowledges dispatch.
--
-- Nullable and additive: existing rows and older writers keep working, and
-- environments without a key simply leave it NULL.

ALTER TABLE sms_outbox
  ADD COLUMN IF NOT EXISTS payload text;

COMMENT ON COLUMN sms_outbox.payload IS
  'AES-256-GCM ciphertext of the OTP (v1.<iv>.<tag>.<ct>); NULL once dispatched or when SMS_PAYLOAD_KEY is unset.';
