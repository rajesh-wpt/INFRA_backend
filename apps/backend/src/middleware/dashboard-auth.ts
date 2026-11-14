/**
 * Dashboard authentication middleware (LOGIN-3.10 / LOGIN-3.11).
 *
 * Dashboard tokens are signed with DASHBOARD_JWT_SECRET and carry
 * `aud: "dashboard"`. End-user access tokens are signed with JWT_SECRET and
 * can never verify here, so the two credential families are separated by key
 * material, not by a claim the caller controls.
 *
 * Response semantics:
 *   - 401 — missing / malformed / invalid / expired token
 *   - 403 — valid signature but the `aud` claim is not "dashboard"
 *
 * On success the verified payload is attached to `res.locals.dashboardAuth`.
 */

import type { Request, Response, NextFunction } from "express";
import {
  verifyDashboardAccessToken,
  DashboardAudienceError,
  type DashboardAccessTokenPayload,
  type DashboardAdminRole,
} from "../auth/dashboard-jwt.js";

declare global {
  namespace Express {
    interface Locals {
      dashboardAuth?: DashboardAccessTokenPayload;
    }
  }
}

/** Extract the raw Bearer token, or null if absent / malformed. */
function extractBearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header) return null;
  const parts = header.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return null;
  return parts[1] || null;
}

/** Require a valid dashboard access token (aud: "dashboard"). */
export async function requireDashboardAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const token = extractBearerToken(req);
  if (!token) {
    res.status(401).json({
      success: false,
      error: "TOKEN_REQUIRED",
      message: "Please provide a valid dashboard Bearer token",
    });
    return;
  }

  try {
    const payload = await verifyDashboardAccessToken(token);
    res.locals.dashboardAuth = payload;
    next();
  } catch (err) {
    if (err instanceof DashboardAudienceError) {
      res.status(403).json({
        success: false,
        error: "INVALID_AUDIENCE",
        expectedAudience: "dashboard",
        receivedAudience: err.receivedAudience,
        message: `This endpoint expects audience "dashboard" but received "${err.receivedAudience}"`,
      });
      return;
    }
    res.status(401).json({
      success: false,
      error: "INVALID_TOKEN",
      expectedAudience: "dashboard",
      message: "Dashboard token signature verification failed or token expired",
    });
  }
}

/**
 * Require the dashboard admin to be an owner.
 *
 * Must run AFTER `requireDashboardAuth`. Non-owner roles get 403.
 */
export function requireOwnerRole(
  _req: Request,
  res: Response,
  next: NextFunction,
): void {
  const role: DashboardAdminRole | undefined = res.locals.dashboardAuth?.role;
  if (role === undefined) {
    res.status(401).json({ error: "UNAUTHORIZED" });
    return;
  }
  if (role !== "owner") {
    res.status(403).json({ error: "OWNER_ROLE_REQUIRED" });
    return;
  }
  next();
}
