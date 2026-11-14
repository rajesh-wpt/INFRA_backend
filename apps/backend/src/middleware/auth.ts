/**
 * JWT authentication middleware.
 *
 * Verifies the Bearer token from the Authorization header,
 * extracts userId/deviceId/sessionId from the validated JWT payload,
 * checks account moderation status, and attaches them to res.locals.auth for downstream handlers.
 */

import type { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../auth/jwt.js";
import { getDb } from "../db/index.js";
import { eq } from "drizzle-orm";
import { users } from "../db/users-schema.js";
import type { AccessTokenPayload } from "../auth/types.js";

declare global {
  namespace Express {
    interface Locals {
      auth?: AccessTokenPayload;
    }
  }
}

/**
 * Require a valid JWT access token AND an active (non-banned) account.
 *
 * Responds 401 if:
 *   - No Authorization header
 *   - Not a Bearer token
 *   - Token is invalid, expired, or tampered
 *   - User account is banned (account_status = 'banned')
 *
 * Responds 403 if:
 *   - User account is restricted (account_status = 'restricted')
 *
 * On success, sets `res.locals.auth` with the verified payload
 * containing `{ sub: userId, deviceId, sid: sessionId }`.
 */
export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    res.status(401).json({ error: "MISSING_TOKEN" });
    return;
  }

  const token = header.slice(7);
  if (!token) {
    res.status(401).json({ error: "EMPTY_TOKEN" });
    return;
  }

  try {
    const payload = await verifyAccessToken(token);
    
    // Check account moderation status
    const db = getDb();
    const [user] = await db
      .select({ accountStatus: users.accountStatus })
      .from(users)
      .where(eq(users.id, payload.sub))
      .limit(1);

    if (!user) {
      res.status(401).json({ error: "USER_NOT_FOUND" });
      return;
    }

    if (user.accountStatus === "banned") {
      res.status(401).json({ error: "ACCOUNT_BANNED" });
      return;
    }

    if (user.accountStatus === "restricted") {
      res.status(403).json({ error: "ACCOUNT_RESTRICTED" });
      return;
    }

    res.locals.auth = payload;
    next();
  } catch {
    res.status(401).json({ error: "INVALID_TOKEN" });
  }
}
