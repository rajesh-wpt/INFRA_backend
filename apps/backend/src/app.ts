import express from "express";
import cors from "cors";
import helmet from "helmet";
import { createServer, type Server as HttpServer } from "node:http";
import { Server as SocketServer } from "socket.io";
import { API_VERSION, SOCKET_NAMESPACE } from "@wpt/shared";
import onboardingRoutes from "./routes/onboarding.js";
import profileRoutes from "./routes/profile.js";
import debugRoutes from "./routes/debug.js";
import blocksRoutes from "./routes/blocks.js";
import reportsRoutes from "./routes/reports.js";
import moderationRoutes from "./routes/moderation.js";
import relayRoutes from "./routes/relay.js";
import smsRoutes from "./routes/sms.js";
import adminRoutes from "./routes/admin.js";
import groupsRoutes from "./routes/groups.js";
import mediaRoutes from "./routes/media.js";
import { prekeysRouter, bundleRouter } from "./routes/prekey.js";
import {
  initSocketRegistry,
  registerSocket,
  unregisterSocket,
} from "./ws/socket-registry.js";
import { verifyAccessToken } from "./auth/jwt.js";
import { requireAuth } from "./middleware/auth.js";

export type BackendServer = {
  httpServer: HttpServer;
  io: SocketServer;
};

/**
 * Builds the Express app + Socket.io server. Configuration comes from
 * the environment (DATABASE_URL, JWT_SECRET, CORS_ORIGIN), which is set
 * either by dotenv (dev entry) or by the embedded entry point before
 * calling this factory.
 *
 * Deliberately does NOT `listen()` — callers decide the bind address.
 */
export function createApp(): BackendServer {
  const app = express();

  // ── Security headers ──
  app.use(helmet());

  // ── CORS: never wildcard in production ──
  const allowedOrigins = (process.env.CORS_ORIGIN ?? "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);

  app.use(
    cors({
      origin: allowedOrigins.length > 0 ? allowedOrigins : false,
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization"],
    }),
  );

  // ── Real client IP behind a reverse proxy ──
  // Off by default: trusting X-Forwarded-For when nothing infront of the
  // process rewrites it lets a caller spoof the audit-log IP.
  const trustProxy = process.env.TRUST_PROXY?.trim();
  if (trustProxy === "true") {
    app.set("trust proxy", 1);
  } else if (trustProxy && Number.isInteger(Number(trustProxy)) && Number(trustProxy) > 0) {
    app.set("trust proxy", Number(trustProxy));
  }

  // ── Body parsing with size limit (100 KB max) ──
  app.use(express.json({ limit: "100kb" }));

  app.get(`/api/${API_VERSION}/health`, (_req, res) => {
    res.json({ ok: true });
  });

  app.use(`/api/${API_VERSION}/onboarding`, onboardingRoutes);
  app.use(`/api/${API_VERSION}/profile`, profileRoutes);
  app.use(`/api/${API_VERSION}/debug`, debugRoutes);
  app.use(`/api/${API_VERSION}/blocks`, blocksRoutes);
  app.use(`/api/${API_VERSION}/reports`, reportsRoutes);
  app.use(`/api/${API_VERSION}/moderation`, moderationRoutes);
  app.use(`/api/${API_VERSION}/relay`, relayRoutes);
  app.use(`/api/${API_VERSION}/sms`, smsRoutes);

  // ── LOGIN-3.10 — dashboard auth (login/refresh are public; the router
  //    applies requireDashboardAuth to everything past them) ──
  app.use(`/api/${API_VERSION}/admin`, adminRoutes);

  // ── ENC-4.1 / ENC-4.2 — prekey upload, status and bundle distribution.
  //    App-audience auth: neither endpoint is public. ──
  app.use(`/api/${API_VERSION}/prekeys`, requireAuth, prekeysRouter);
  app.use(`/api/${API_VERSION}/prekey-bundle`, requireAuth, bundleRouter);

  // ── ENC-4.3 / ENC-4.4 / ENC-4.5 — groups + encrypted icon URLs ──
  app.use(`/api/${API_VERSION}/groups`, requireAuth, groupsRoutes);

  // ── ENC-4.5 — encrypted media. GET is public by design (the signed URL is
  //    the capability); PUT carries requireAuth inside the router. ──
  app.use(`/api/${API_VERSION}/media`, mediaRoutes);

  const httpServer = createServer(app);

  const io = new SocketServer(httpServer, {
    path: SOCKET_NAMESPACE,
  });

  initSocketRegistry(io);

  io.use(async (socket, next) => {
    const token = socket.handshake.auth?.token as string | undefined;
    const userId = socket.handshake.auth?.userId as string | undefined;
    const deviceId = socket.handshake.auth?.deviceId as string | undefined;

    if (!token || !userId || !deviceId) {
      next(new Error("Authentication required"));
      return;
    }

    try {
      const payload = await verifyAccessToken(token);
      if (payload.sub !== userId) {
        next(new Error("Token userId mismatch"));
        return;
      }
      // The socket must claim the exact device that the token was issued to.
      if (typeof payload.deviceId === "string" && payload.deviceId !== deviceId) {
        next(new Error("Token deviceId mismatch"));
        return;
      }
      next();
    } catch {
      next(new Error("Invalid token"));
    }
  });

  io.on("connection", (socket) => {
    const userId = socket.handshake.auth?.userId as string;
    const deviceId = socket.handshake.auth?.deviceId as string;

    registerSocket(socket, userId, deviceId);

    socket.on("disconnect", () => {
      unregisterSocket(socket, userId);
    });
  });

  return { httpServer, io };
}