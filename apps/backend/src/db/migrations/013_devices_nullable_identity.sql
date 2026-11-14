-- LOGIN-3.7 — stop fabricating device identity.
--
-- The handoff transaction used to write `platform = 'android'` for every
-- device and an `identityPublicKey` of `pf_<deviceId>`, which is not a key at
-- all. Both values are now taken from the client; when a client has not
-- provisioned an identity key yet, the honest value is NULL, not a fake one.
--
-- Dropping NOT NULL is additive for readers and keeps older writers working.

ALTER TABLE devices ALTER COLUMN platform DROP NOT NULL;
ALTER TABLE devices ALTER COLUMN identity_public_key DROP NOT NULL;

COMMENT ON COLUMN devices.platform IS
  'Client-reported platform (android/ios/web). NULL = not reported by the device.';

COMMENT ON COLUMN devices.identity_public_key IS
  'Device E2E identity public key. NULL = not yet provisioned by the client (never a placeholder).';
