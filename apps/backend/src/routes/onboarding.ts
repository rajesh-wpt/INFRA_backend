/**
 * ONB — Onboarding API routes.
 *
 * Security hardening applied:
 *   - OTP hash comparison uses timing-safe equal (CWE-208)
 *   - Raw OTP code never logged (removed from console.log)
 *   - Phone numbers validated against E.164 format
 *   - Rate limiting on OTP send and verify endpoints
 *   - session/check requires valid JWT (prevents session enumeration)
 *   - login/handoff requires valid refresh token (prevents account takeover)
 *   - OTP attempts use atomic SQL increment (prevents race condition)
 */

import { Router, type Request, type Response } from "express";
import {
  createHash,
  randomUUID,
  randomInt,
  timingSafeEqual,
} from "node:crypto";
import { and, desc, eq, isNull, ne, sql } from "drizzle-orm";
import {
  recordLegalAcceptance,
  requireLegalAcceptance,
  LegalAcceptanceRequiredError,
  issueAccessToken,
  issueRefreshToken,
  validateRefreshToken,
} from "../auth/index.js";
import { getDb, type AppDb } from "../db/index.js";
import { sessions } from "../db/sessions-schema.js";
import { users } from "../db/users-schema.js";
import { devices } from "../db/devices-schema.js";
import { otpVerifications } from "../db/otp-verifications-schema.js";
import { smsOutbox } from "../db/sms-outbox-schema.js";
import { contactHashes } from "../db/contact-hashes-schema.js";
import { pushForceLogout } from "../ws/socket-registry.js";
import { deliverOtpCode } from "../sms/sender.js";
import { encryptOtpPayload } from "../sms/payload-crypto.js";
import { requireAuth } from "../middleware/auth.js";
import { rateLimit } from "../middleware/rate-limit.js";
import { phoneHash } from "../utils/phone-hash.js";
import { normalizePhoneNumber } from "../utils/phone-normalize.js";

const router: Router = Router();

// ── OTP config (matches ONB-1.0 mock exactly) ──
const OTP_LENGTH = 6;
const OTP_TTL_MS = 5 * 60_000; // 5 minutes
const MAX_ATTEMPTS = 3;
const LOCKOUT_MS = 30_000; // 30 seconds
const RESEND_COOLDOWN_MS = 30_000; // 30 seconds (independent of lockout)

// ── Device identity (LOGIN-3.7) ──
type DevicePlatform = "android" | "ios" | "web";
const DEVICE_PLATFORMS: ReadonlySet<string> = new Set(["android", "ios", "web"]);

type ParsedDeviceInfo = {
  platform: DevicePlatform | null;
  identityPublicKey: string | null;
};

type DeviceInfoInput = {
  deviceId?: unknown;
  deviceName?: unknown;
  platform?: unknown;
  identityPublicKey?: unknown;
};

/**
 * Validate the device block a client reports.
 *
 * LOGIN-3.7 removed the two values this endpoint used to invent:
 * `platform: "android"` for every device and an `identityPublicKey` of
 * `pf_<deviceId>`. Whatever the client proves about itself is stored; what it
 * does not send is stored as NULL rather than fabricated.
 */
function parseDeviceInfo(
  input: unknown,
): { ok: true; value: ParsedDeviceInfo } | { ok: false; error: string } {
  if (input === undefined || input === null) {
    return { ok: true, value: { platform: null, identityPublicKey: null } };
  }
  if (typeof input !== "object") {
    return { ok: false, error: "DEVICE_INFO_INVALID" };
  }

  const info = input as DeviceInfoInput;

  let platform: DevicePlatform | null = null;
  if (info.platform !== undefined && info.platform !== null) {
    if (typeof info.platform !== "string" || !DEVICE_PLATFORMS.has(info.platform)) {
      return { ok: false, error: "DEVICE_PLATFORM_INVALID" };
    }
    platform = info.platform as DevicePlatform;
  }

  let identityPublicKey: string | null = null;
  if (info.identityPublicKey !== undefined && info.identityPublicKey !== null) {
    if (typeof info.identityPublicKey !== "string") {
      return { ok: false, error: "IDENTITY_KEY_INVALID" };
    }
    const key = info.identityPublicKey.trim();
    // Base64/base64url or hex — the encodings an E2E client will use.
    if (!/^[A-Za-z0-9+/=_-]{32,4096}$/.test(key)) {
      return { ok: false, error: "IDENTITY_KEY_INVALID" };
    }
    identityPublicKey = key;
  }

  return { ok: true, value: { platform, identityPublicKey } };
}

/**
 * OTP helper functions.
 */
function generateOtpCode(): string {
  // Uniform digits via crypto.randomInt — avoids the modulo bias of byte % 10
  // (which made digits 0-5 ~4% more likely than 6-9 and shrank the search space).
  let code = "";
  for (let i = 0; i < OTP_LENGTH; i++) {
    code += String(randomInt(0, 10));
  }
  return code;
}

function hashOtpCode(code: string): string {
  return createHash("sha256").update(code).digest("hex");
}

/**
 * Normalize/validate the phone number in the body ahead of rate limiting,
 * so the rate-limit key is the canonical E.164 form (not attacker-varable
 * formatting). Stores the result in res.locals.normalizedPhone.
 */
function withNormalizedPhone(req: Request, res: Response, next: () => void): void {
  const raw = (req.body as { phoneNumber?: unknown } | null)?.phoneNumber;
  if (typeof raw !== "string") {
    res.status(400).json({ error: "phoneNumber is required" });
    return;
  }
  const normalized = normalizePhoneNumber(raw);
  if (!normalized) {
    res.status(400).json({ error: "INVALID_PHONE" });
    return;
  }
  res.locals.normalizedPhone = normalized;
  next();
}

/** Rate-limit key from the normalized phone stored by withNormalizedPhone. */
function normalizedPhoneKey(prefix: string) {
  return (req: Request) => {
    const locals = (req.res?.locals ?? {}) as { normalizedPhone?: string };
    return locals.normalizedPhone ? `${prefix}:${locals.normalizedPhone}` : req.ip ?? req.socket.remoteAddress ?? "unknown";
  };
}

/**
 * Timing-safe comparison of two hex-encoded SHA-256 hashes.
 * Prevents CWE-208 (timing side-channel) on OTP verification.
 */
function timingSafeHashCompare(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "hex");
  const bBuf = Buffer.from(b, "hex");
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}

/**
 * LOGIN-3.4 + §7.3 — Atomic new-device handoff transaction.
 *
 * Called by:
 *   - POST /otp/verify   (OTP success path)
 *   - POST /login/handoff (new-device login, requires valid refresh token)
 */
async function executeHandoffTransaction({
  userId,
  deviceId,
  phoneNumber,
  deviceInfo,
}: {
  userId: string;
  deviceId: string;
  phoneNumber?: string;
  deviceInfo?: ParsedDeviceInfo;
}): Promise<{
  sessionId: string;
  accessToken: string;
  refreshToken: string;
  revokedCount: number;
  deviceId: string;
  userId: string;
  routing?: "chats" | "profile_setup";
}> {
  const db = getDb();

  const result = await db.transaction(async (tx) => {
    let routing: "chats" | "profile_setup" | undefined;

    if (phoneNumber) {
      const [, [existingUser]] = await Promise.all([
        tx
          .delete(otpVerifications)
          .where(eq(otpVerifications.phoneNumber, phoneNumber)),
        tx
          .select({ id: users.id })
          .from(users)
          .where(eq(users.phoneNumber, phoneNumber))
          .limit(1),
      ]);

      if (existingUser) {
        userId = existingUser.id;
        routing = "chats";
      } else {
        // New user registration — create user + contact_hashes row in same transaction (Tech Arch §14.4)
        userId = randomUUID();
        const hash = phoneHash(phoneNumber);

        await Promise.all([
          tx.insert(users).values({
            id: userId,
            phoneNumber,
            name: "",
          }),
          tx.insert(contactHashes).values({
            phoneHash: hash,
            userId,
          }),
        ]);

        routing = "profile_setup";
      }
    }

    // Register (or refresh) this device with the values the client actually
    // reported. LOGIN-3.7: no fabricated platform, no `pf_<id>` placeholder.
    const deviceUpdate: Partial<typeof devices.$inferInsert> = {
      isActive: true,
      revokedAt: null,
      lastSeenAt: new Date(),
    };
    if (deviceInfo?.platform) deviceUpdate.platform = deviceInfo.platform;
    if (deviceInfo?.identityPublicKey) {
      deviceUpdate.identityPublicKey = deviceInfo.identityPublicKey;
    }

    await tx
      .insert(devices)
      .values({
        id: deviceId,
        userId,
        deviceType: deviceInfo?.platform === "web" ? "web" : "phone",
        platform: deviceInfo?.platform ?? null,
        identityPublicKey: deviceInfo?.identityPublicKey ?? null,
      })
      .onConflictDoUpdate({
        target: devices.id,
        set: deviceUpdate,
      });

    // LOGIN-3.7: the superseded phones must stop being delivery targets.
    // Sessions were revoked below, but the device rows stayed `is_active`, so
    // relay/poll kept fanning messages out to devices that were logged out.
    await tx
      .update(devices)
      .set({ isActive: false, revokedAt: new Date() })
      .where(
        and(
          eq(devices.userId, userId),
          ne(devices.id, deviceId),
          isNull(devices.revokedAt),
        ),
      );

    const revokeResult = await tx
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(sessions.userId, userId),
          isNull(sessions.revokedAt),
        ),
      );
    const revokedCount = revokeResult.rowCount ?? 0;

    const { refreshToken, sessionId } = await issueRefreshToken({
      userId,
      deviceId,
      db: tx as unknown as AppDb,
    });

    const accessToken = await issueAccessToken({
      userId,
      deviceId,
      sessionId,
    });

    return { sessionId, accessToken, refreshToken, revokedCount, deviceId, userId, routing };
  });

  pushForceLogout(userId, deviceId);

  return result;
}

// ──────────────────────────────────────────────────
// POST /onboarding/accept-legal
// ──────────────────────────────────────────────────
router.post("/accept-legal", async (req: Request, res: Response) => {
  try {
    const { phoneNumber: rawPhoneNumber } = req.body as { phoneNumber?: string };

    if (!rawPhoneNumber || typeof rawPhoneNumber !== "string") {
      res.status(400).json({ error: "phoneNumber is required" });
      return;
    }

    // Normalize and validate — without this, an arbitrary string would be
    // stored and later fail to match the E.164 form used by OTP verify
    // (causing a self-DoS) and opens the door to garbage rows.
    const phoneNumber = normalizePhoneNumber(rawPhoneNumber);
    if (!phoneNumber) {
      res.status(400).json({ error: "INVALID_PHONE" });
      return;
    }

    await recordLegalAcceptance({
      phoneNumber,
      legalVersion: "v1.0-2024-01-15",
    });

    res.json({ success: true });
  } catch {
    console.error("POST /accept-legal error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ──────────────────────────────────────────────────
// POST /onboarding/otp/send
// Rate limited: max 3 sends per phone per 60 seconds
// ──────────────────────────────────────────────────
router.post(
  "/otp/send",
  withNormalizedPhone,
  rateLimit({
    maxRequests: 3,
    windowMs: 60_000,
    keyFn: normalizedPhoneKey("otp-send"),
    message: "Too many OTP requests. Please wait before retrying.",
  }),
  async (_req: Request, res: Response) => {
    try {
      const phoneNumber = (res.locals as { normalizedPhone?: string }).normalizedPhone as string;
      const db = getDb();
      const now = new Date();

      // Resend cooldown check (independent 30s timer, §7.2)
      const [existing] = await db
        .select({ sentAt: otpVerifications.sentAt })
        .from(otpVerifications)
        .where(eq(otpVerifications.phoneNumber, phoneNumber))
        .limit(1);

      if (existing) {
        const elapsed = now.getTime() - existing.sentAt.getTime();
        if (elapsed < RESEND_COOLDOWN_MS) {
          res.status(429).json({
            error: "RESEND_COOLDOWN_ACTIVE",
            secondsRemaining: Math.ceil((RESEND_COOLDOWN_MS - elapsed) / 1000),
          });
          return;
        }
      }

      const rawCode = generateOtpCode();
      const codeHash = hashOtpCode(rawCode);
      const expiresAt = new Date(now.getTime() + OTP_TTL_MS);

      // Delete old row + insert new verification + queue SMS outbox row.
      // SECURITY: raw OTP code is NEVER stored in DB — only the SHA-256 hash.
      await Promise.all([
        db
          .delete(otpVerifications)
          .where(eq(otpVerifications.phoneNumber, phoneNumber)),
        db.insert(otpVerifications).values({
          phoneNumber,
          codeHash,
          expiresAt,
          sentAt: now,
        }),
        db.insert(smsOutbox).values({
          phoneNumber,
          otpHash: codeHash,
          // Encrypted for the self-hosted gateway; NULL when no key is set.
          payload: encryptOtpPayload(rawCode),
          status: "pending",
        }),
      ]);

      // Local-dev console delivery. Production delivery happens when the
      // gateway polls /api/v1/sms/outbox/poll (LOGIN-3.5) — no Twilio.
      await deliverOtpCode(phoneNumber, rawCode);

      res.json({ success: true });
    } catch {
      console.error("POST /otp/send error");
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ──────────────────────────────────────────────────
// POST /onboarding/otp/verify
// Rate limited: max 5 verify attempts per phone per 60 seconds
// ──────────────────────────────────────────────────
router.post(
  "/otp/verify",
  withNormalizedPhone,
  rateLimit({
    maxRequests: 5,
    windowMs: 60_000,
    keyFn: normalizedPhoneKey("otp-verify"),
    message: "Too many verification attempts. Please wait.",
  }),
  async (req: Request, res: Response) => {
    try {
      const phoneNumber = (res.locals as { normalizedPhone?: string }).normalizedPhone as string;
      const { code, deviceInfo } = req.body as { code?: string; deviceInfo?: unknown };

      if (!code) {
        res.status(400).json({ error: "phoneNumber and code are required" });
        return;
      }

      const parsedDevice = parseDeviceInfo(deviceInfo);
      if (!parsedDevice.ok) {
        res.status(400).json({ error: parsedDevice.error });
        return;
      }

      if (typeof code !== "string" || code.length !== OTP_LENGTH) {
        res.status(400).json({ error: "INVALID_CODE_FORMAT" });
        return;
      }

      // Legal gate check
      try {
        await requireLegalAcceptance(phoneNumber);
      } catch (err) {
        if (err instanceof LegalAcceptanceRequiredError) {
          res.status(err.statusCode).json({ error: err.code });
          return;
        }
        throw err;
      }

      const db = getDb();
      const now = new Date();

      // Check if user exists and is banned — reject login for banned accounts
      const [existingUser] = await db
        .select({ id: users.id, accountStatus: users.accountStatus })
        .from(users)
        .where(eq(users.phoneNumber, phoneNumber))
        .limit(1);

      if (existingUser && existingUser.accountStatus === "banned") {
        res.status(401).json({ error: "ACCOUNT_BANNED" });
        return;
      }

      const [record] = await db
        .select()
        .from(otpVerifications)
        .where(eq(otpVerifications.phoneNumber, phoneNumber))
        .limit(1);

      if (!record) {
        res.status(400).json({ error: "NO_ACTIVE_SESSION" });
        return;
      }

      // Lockout check
      if (record.lockedUntil && now < record.lockedUntil) {
        res.json({
          status: "locked_out",
          secondsRemaining: Math.ceil(
            (record.lockedUntil.getTime() - now.getTime()) / 1000,
          ),
        });
        return;
      }

      // Expiry check
      if (now.getTime() - record.sentAt.getTime() > OTP_TTL_MS) {
        await db
          .delete(otpVerifications)
          .where(eq(otpVerifications.phoneNumber, phoneNumber));
        res.json({ status: "expired" });
        return;
      }

      // Timing-safe code comparison (CWE-208)
      const presentedHash = hashOtpCode(code);

      if (!timingSafeHashCompare(presentedHash, record.codeHash)) {
        // Wrong code — atomic increment (SET attempts = attempts + 1). A
        // plain per-request read+GREATEST() collapses concurrent guesses into
        // one increment, letting attackers race past the 3-attempt lockout.
        const [updated] = await db
          .update(otpVerifications)
          .set({ attempts: sql`${otpVerifications.attempts} + 1` })
          .where(eq(otpVerifications.phoneNumber, phoneNumber))
          .returning({ attempts: otpVerifications.attempts });

        const attempts = updated?.attempts ?? record.attempts + 1;

        if (attempts >= MAX_ATTEMPTS) {
          const lockedUntil = new Date(now.getTime() + LOCKOUT_MS);
          await db
            .update(otpVerifications)
            .set({ lockedUntil })
            .where(eq(otpVerifications.phoneNumber, phoneNumber));

          res.json({ status: "attempts_exhausted" });
          return;
        }

        res.json({ status: "wrong_code", attemptsRemaining: MAX_ATTEMPTS - attempts });
        return;
      }

      // SUCCESS — Atomic handoff transaction
      const deviceId = randomUUID();
      const result = await executeHandoffTransaction({
        userId: "",
        deviceId,
        phoneNumber,
        deviceInfo: parsedDevice.value,
      });

      res.json({
        status: "success",
        routing: result.routing!,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        userId: result.userId,
        sessionId: result.sessionId,
        // The server owns device identity (devices.id is a uuid). The client
        // must persist this exact value — inventing its own id made
        // /session/check, socket auth and handoff disagree about the device.
        deviceId: result.deviceId,
      });
    } catch {
      console.error("POST /otp/verify error");
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ──────────────────────────────────────────────────
// POST /onboarding/check-existing-user
// Returns boolean only (no userId) to prevent enumeration
// ──────────────────────────────────────────────────
router.post("/check-existing-user", async (req: Request, res: Response) => {
  try {
    const { phoneNumber: rawPhoneNumber } = req.body as { phoneNumber?: string };

    if (!rawPhoneNumber || typeof rawPhoneNumber !== "string") {
      res.status(400).json({ error: "phoneNumber is required" });
      return;
    }

    const phoneNumber = normalizePhoneNumber(rawPhoneNumber);

    if (!phoneNumber) {
      res.status(400).json({ error: "INVALID_PHONE" });
      return;
    }

    const db = getDb();
    const [existingUser] = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.phoneNumber, phoneNumber))
      .limit(1);

    // Only return boolean — never leak userId here
    res.json({ exists: !!existingUser });
  } catch {
    console.error("POST /check-existing-user error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ──────────────────────────────────────────────────
// POST /onboarding/refresh
// ──────────────────────────────────────────────────
router.post("/refresh", async (req: Request, res: Response) => {
  try {
    const { refreshToken: presentedToken } = req.body as {
      refreshToken?: string;
    };

    if (!presentedToken) {
      res.status(400).json({ error: "refreshToken is required" });
      return;
    }

    const session = await validateRefreshToken(presentedToken);

    if (!session) {
      res.status(401).json({ error: "INVALID_REFRESH_TOKEN" });
      return;
    }

    const accessToken = await issueAccessToken({
      userId: session.userId,
      deviceId: session.deviceId,
      sessionId: session.sessionId,
    });

    res.json({ accessToken });
  } catch {
    console.error("POST /refresh error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ──────────────────────────────────────────────────
// POST /onboarding/login/handoff
//
// SECURITY: Requires a valid refresh token proving the caller owns
// the account. Without this, anyone could mint tokens for any userId.
// ──────────────────────────────────────────────────
router.post("/login/handoff", async (req: Request, res: Response) => {
  try {
    const { refreshToken: presentedToken, deviceInfo } = req.body as {
      refreshToken?: string;
      deviceInfo?: {
        deviceId?: string;
        deviceName?: string;
        platform?: string;
        identityPublicKey?: string;
      };
    };

    if (!presentedToken || !deviceInfo) {
      res.status(400).json({
        error: "refreshToken and deviceInfo are required",
      });
      return;
    }

    if (!deviceInfo.deviceId || !deviceInfo.deviceName) {
      res.status(400).json({ error: "deviceInfo must include deviceId and deviceName" });
      return;
    }

    const parsedDevice = parseDeviceInfo(deviceInfo);
    if (!parsedDevice.ok) {
      res.status(400).json({ error: parsedDevice.error });
      return;
    }
    if (!parsedDevice.value.platform) {
      // The caller must state its platform; defaulting to "android" is the
      // behaviour LOGIN-3.7 exists to remove.
      res.status(400).json({ error: "DEVICE_PLATFORM_REQUIRED" });
      return;
    }

    // devices.id is a uuid column — coerce arbitrary client device ids to a
    // uuid so the handoff can bind relay/send (FK on sender_device_id).
    const clientDeviceId = deviceInfo.deviceId;
    const deviceId =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(clientDeviceId)
        ? clientDeviceId
        : randomUUID();

    // Validate the refresh token — proves the caller owns this account
    const session = await validateRefreshToken(presentedToken);
    if (!session) {
      res.status(401).json({ error: "INVALID_REFRESH_TOKEN" });
      return;
    }

    const handoff = await executeHandoffTransaction({
      userId: session.userId,
      deviceId,
      deviceInfo: parsedDevice.value,
    });

    res.json({
      success: true,
      sessionId: handoff.sessionId,
      accessToken: handoff.accessToken,
      refreshToken: handoff.refreshToken,
      deviceId: handoff.deviceId,
      message: `You're now logged in here on ${deviceInfo.deviceName}`,
      previousDevicesLoggedOut: handoff.revokedCount,
    });
  } catch {
    console.error("POST /login/handoff error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ──────────────────────────────────────────────────
// POST /onboarding/session/check
//
// SECURITY: Requires valid JWT — prevents session enumeration by
// unauthenticated callers.
// ──────────────────────────────────────────────────
router.post("/session/check", requireAuth, async (req: Request, res: Response) => {
  try {
    const authUserId = res.locals.auth!.sub;
    const { deviceId } = req.body as { deviceId?: string };

    if (!deviceId) {
      res.status(400).json({ error: "deviceId is required" });
      return;
    }

    const db = getDb();
    const [row] = await db
      .select({ id: sessions.id, revokedAt: sessions.revokedAt })
      .from(sessions)
      .where(and(eq(sessions.userId, authUserId), eq(sessions.deviceId, deviceId)))
      // Prefer a live session over a revoked one, then the most recent. A plain
      // `LIMIT 1` picked an arbitrary row, so after a refresh/handoff (which
      // leaves several rows per device) a valid session could be reported as
      // "Logged in on another device". LOGIN-3.9 resume-time validation.
      .orderBy(sql`${sessions.revokedAt} is null desc`, desc(sessions.createdAt))
      .limit(1);

    if (!row) {
      res.json({ isValid: false, message: "Session not found" });
      return;
    }

    if (row.revokedAt !== null) {
      res.json({ isValid: false, message: "Logged in on another device" });
      return;
    }

    res.json({ isValid: true });
  } catch {
    console.error("POST /session/check error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
