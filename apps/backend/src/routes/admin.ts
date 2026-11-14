/**
 * LOGIN-3.10 — Dashboard (Admin) routes.
 *
 * Completely separate login system for the WPT Admin Dashboard:
 *   - POST /admin/login        — dashboard login, issues aud:"dashboard" tokens
 *   - POST /admin/refresh      — refresh a dashboard access token
 *   - POST /admin/logout       — revoke the current dashboard session
 *   - POST /admin/logout-all   — revoke every session for this admin
 *   - GET  /admin/me           — current admin profile
 *   - GET  /admin/audit/otp    — platform-verification audit log (LOGIN-3.12)
 *   - GET/POST/DELETE /admin/admins — owner-only admin management
 *
 * Public routes: login, refresh. Everything else requires a dashboard token
 * with `aud: "dashboard"` (enforced below, not in the mount).
 */

import { Router, type Request, type Response } from "express";
import { eq } from "drizzle-orm";
import bcrypt from "bcryptjs";
import { getDb } from "../db/index.js";
import { dashboardAdmins } from "../db/dashboard-admins-schema.js";
import {
  dashboardLogin,
  dashboardRefresh,
  dashboardLogout,
  dashboardLogoutAll,
  getDashboardAdminById,
} from "../auth/dashboard.js";
import {
  requireDashboardAuth,
  requireOwnerRole,
} from "../middleware/dashboard-auth.js";
import { rateLimit } from "../middleware/rate-limit.js";
import { getOtpAuditLogs, toLocalIsoTimestamp } from "../audit/audit-logger.js";

const router: Router = Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_PASSWORD_LENGTH = 200;

// ──────────────────────────────────────────────────
// POST /admin/login
// ──────────────────────────────────────────────────
router.post(
  "/login",
  rateLimit({
    maxRequests: 10,
    windowMs: 60_000,
    keyFn: (req) => `admin-login:${req.ip ?? "unknown"}`,
    message: "Too many login attempts. Please wait before retrying.",
  }),
  async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body as { email?: string; password?: string };

      if (!email || typeof email !== "string" || !password || typeof password !== "string") {
        res.status(400).json({ error: "EMAIL_AND_PASSWORD_REQUIRED" });
        return;
      }

      const ipAddress = req.ip ?? req.socket.remoteAddress ?? undefined;
      const userAgent = req.headers["user-agent"] ?? undefined;

      const result = await dashboardLogin(
        { email, password },
        { ipAddress, userAgent },
      );

      if (!result.success) {
        res.status(401).json({ success: false, error: result.error });
        return;
      }

      res.json({
        success: true,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        sessionId: result.sessionId,
        admin: result.admin,
        tokenAudience: "dashboard",
      });
    } catch (err) {
      console.error("POST /admin/login error", err);
      res.status(500).json({ success: false, error: "INTERNAL_SERVER_ERROR" });
    }
  },
);

// ──────────────────────────────────────────────────
// POST /admin/refresh (public: it verifies the refresh token itself)
// ──────────────────────────────────────────────────
router.post(
  "/refresh",
  rateLimit({
    maxRequests: 30,
    windowMs: 60_000,
    keyFn: (req) => `admin-refresh:${req.ip ?? "unknown"}`,
    message: "Too many refresh attempts. Please wait before retrying.",
  }),
  async (req: Request, res: Response) => {
    try {
      const { refreshToken } = req.body as { refreshToken?: string };

      if (!refreshToken || typeof refreshToken !== "string") {
        res.status(400).json({ error: "REFRESH_TOKEN_REQUIRED" });
        return;
      }

      const result = await dashboardRefresh(refreshToken);
      if (!result.success) {
        res.status(401).json({ success: false, error: result.error });
        return;
      }

      res.json({ success: true, accessToken: result.accessToken });
    } catch (err) {
      console.error("POST /admin/refresh error", err);
      res.status(500).json({ success: false, error: "INTERNAL_SERVER_ERROR" });
    }
  },
);

// ──────────────────────────────────────────────────
// LOGIN-3.11 — audience gate (aud: "dashboard").
// All routes defined AFTER this point require a valid dashboard token.
// login/refresh above remain public (they mint the tokens).
// ──────────────────────────────────────────────────
router.use(requireDashboardAuth);

// ──────────────────────────────────────────────────
// POST /admin/logout (dashboard auth required)
// ──────────────────────────────────────────────────
router.post("/logout", async (_req: Request, res: Response) => {
  try {
    const sessionId = res.locals.dashboardAuth!.sid;
    const done = await dashboardLogout(sessionId);
    res.json({ success: done });
  } catch (err) {
    console.error("POST /admin/logout error", err);
    res.status(500).json({ success: false, error: "INTERNAL_SERVER_ERROR" });
  }
});

// ──────────────────────────────────────────────────
// POST /admin/logout-all (dashboard auth required)
// ──────────────────────────────────────────────────
router.post("/logout-all", async (_req: Request, res: Response) => {
  try {
    const adminId = res.locals.dashboardAuth!.sub;
    const revoked = await dashboardLogoutAll(adminId);
    res.json({ success: true, revoked });
  } catch (err) {
    console.error("POST /admin/logout-all error", err);
    res.status(500).json({ success: false, error: "INTERNAL_SERVER_ERROR" });
  }
});

// ──────────────────────────────────────────────────
// GET /admin/me (dashboard auth required)
// ──────────────────────────────────────────────────
router.get("/me", async (_req: Request, res: Response) => {
  try {
    const adminId = res.locals.dashboardAuth!.sub;
    const admin = await getDashboardAdminById(adminId);

    if (!admin) {
      res.status(404).json({ success: false, error: "ADMIN_NOT_FOUND" });
      return;
    }

    res.json({
      success: true,
      admin: {
        id: admin.id,
        email: admin.email,
        role: admin.role,
        isTestAccount: admin.isTestAccount,
        createdAt: admin.createdAt,
      },
    });
  } catch (err) {
    console.error("GET /admin/me error", err);
    res.status(500).json({ success: false, error: "INTERNAL_SERVER_ERROR" });
  }
});

// ──────────────────────────────────────────────────
// GET /admin/audit/otp — OTP platform-detection audit log (admin only)
// LOGIN-3.12. Dashboard auth gate applies (see router.use above).
// ──────────────────────────────────────────────────
router.get("/audit/otp", async (req: Request, res: Response) => {
  try {
    const limitRaw = Number(req.query.limit);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 50;

    const logs = await getOtpAuditLogs({ limit });
    // Report timestamps in local time (APP_TIMEZONE or server TZ). Storage
    // remains UTC (timestamptz); this is the display representation.
    const view = logs.map((l) => ({
      ...l,
      timestamp: toLocalIsoTimestamp(l.timestamp),
    }));
    res.json({ success: true, count: view.length, logs: view });
  } catch (err) {
    console.error("GET /admin/audit/otp error", err);
    res.status(500).json({ success: false, error: "INTERNAL_SERVER_ERROR" });
  }
});

// ──────────────────────────────────────────────────
// Owner-only admin management
// ──────────────────────────────────────────────────

// GET /admin/admins — list dashboard admins (owner only)
router.get("/admins", requireOwnerRole, async (_req: Request, res: Response) => {
  try {
    const db = getDb();
    const rows = await db
      .select({
        id: dashboardAdmins.id,
        email: dashboardAdmins.email,
        role: dashboardAdmins.role,
        isTestAccount: dashboardAdmins.isTestAccount,
        createdAt: dashboardAdmins.createdAt,
      })
      .from(dashboardAdmins)
      .orderBy(dashboardAdmins.createdAt);
    res.json({ success: true, admins: rows });
  } catch (err) {
    console.error("GET /admin/admins error", err);
    res.status(500).json({ success: false, error: "INTERNAL_SERVER_ERROR" });
  }
});

// POST /admin/admins — create a dashboard admin (owner only)
router.post("/admins", requireOwnerRole, async (req: Request, res: Response) => {
  try {
    const body = req.body as {
      email?: unknown;
      password?: unknown;
      role?: unknown;
      isTestAccount?: unknown;
    };

    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const role = body.role === "owner" ? "owner" : body.role === "admin" ? "admin" : null;
    const isTestAccount = body.isTestAccount === true;

    if (!EMAIL_RE.test(email) || email.length > 255) {
      res.status(400).json({ success: false, error: "INVALID_EMAIL" });
      return;
    }
    if (password.length < 12 || password.length > MAX_PASSWORD_LENGTH) {
      res.status(400).json({
        success: false,
        error: "INVALID_PASSWORD",
        message: `password must be ${12}-${MAX_PASSWORD_LENGTH} characters`,
      });
      return;
    }
    if (role === null) {
      res.status(400).json({ success: false, error: "INVALID_ROLE" });
      return;
    }

    const db = getDb();
    const [existing] = await db
      .select({ id: dashboardAdmins.id })
      .from(dashboardAdmins)
      .where(eq(dashboardAdmins.email, email))
      .limit(1);
    if (existing) {
      res.status(409).json({ success: false, error: "EMAIL_ALREADY_EXISTS" });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const [created] = await db
      .insert(dashboardAdmins)
      .values({ email, passwordHash, role, isTestAccount })
      .returning({
        id: dashboardAdmins.id,
        email: dashboardAdmins.email,
        role: dashboardAdmins.role,
        isTestAccount: dashboardAdmins.isTestAccount,
      });

    res.status(201).json({ success: true, admin: created });
  } catch (err) {
    console.error("POST /admin/admins error", err);
    res.status(500).json({ success: false, error: "INTERNAL_SERVER_ERROR" });
  }
});

// DELETE /admin/admins/:id — delete a dashboard admin (owner only)
router.delete("/admins/:id", requireOwnerRole, async (req: Request, res: Response) => {
  try {
    const id = String(req.params.id ?? "");
    const callerId = res.locals.dashboardAuth!.sub;

    if (id === callerId) {
      res.status(409).json({
        success: false,
        error: "CANNOT_DELETE_SELF",
        message: "Use another owner account to remove this one",
      });
      return;
    }

    const db = getDb();
    const deleted = await db
      .delete(dashboardAdmins)
      .where(eq(dashboardAdmins.id, id))
      .returning({ id: dashboardAdmins.id });

    if (deleted.length === 0) {
      res.status(404).json({ success: false, error: "ADMIN_NOT_FOUND" });
      return;
    }
    res.json({ success: true, deletedId: deleted[0]!.id });
  } catch (err) {
    // A malformed uuid surfaces as a Postgres 22P02 rather than a 500.
    if ((err as { code?: string })?.code === "22P02") {
      res.status(400).json({ success: false, error: "INVALID_ADMIN_ID" });
      return;
    }
    console.error("DELETE /admin/admins/:id error", err);
    res.status(500).json({ success: false, error: "INTERNAL_SERVER_ERROR" });
  }
});

export default router;
