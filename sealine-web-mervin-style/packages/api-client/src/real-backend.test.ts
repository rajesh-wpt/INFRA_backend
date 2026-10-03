/**
 * Regression test for the BE-6.1 register contract.
 * Uses a tiny stand-in for the backend's /linking "register" handler (same validation as apps/backend/src/app.ts):
 * the token must look like a linking token AND a FLAT identityPublicKey string must be present.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Server } from "socket.io";
import { RealBackendClient } from "./index";

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
let http: HttpServer;
let io: Server;
let origin = "";
const open: Array<{ close: () => void }> = [];

beforeEach(async () => {
  http = createServer();
  io = new Server(http, { path: "/realtime" });
  io.of("/linking").on("connection", (socket) => {
    socket.on("register", (data: any, ack: any) => {
      const ok = typeof data?.token === "string" && /^[A-Za-z0-9_-]{32,256}$/.test(data.token) &&
        typeof data?.identityPublicKey === "string" && data.identityPublicKey.length > 0;
      ack?.(ok ? { ok: true } : { ok: false, error: "INVALID_REGISTRATION" });
      if (ok) setTimeout(() => socket.emit("accountLinked", { accessToken: "a", refreshToken: "r", userId: "u", deviceId: "d", sessionId: "s" }), 50);
    });
  });
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  origin = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
});
afterEach(() => { open.splice(0).forEach((c) => c.close()); io.close(); });

describe("RealBackendClient.register (BE-6.1)", () => {
  it("sends the flat payload the backend accepts and receives accountLinked", async () => {
    const c = new RealBackendClient(origin);
    let rejected = "";
    const reg = c.register({ token: c.createToken(), identityPublicKey: "AAAA", signingPublicKey: "BBBB" }, (e) => (rejected = e));
    open.push(reg);
    const got: unknown[] = [];
    reg.socket.on("accountLinked", (p) => got.push(p));
    await wait(400);
    expect(rejected).toBe("");
    expect(got).toHaveLength(1);
  });

  it("reports INVALID_REGISTRATION instead of silently looping when the payload is wrong", async () => {
    const c = new RealBackendClient(origin);
    let rejected = "";
    const reg = c.register({ token: c.createToken() } as any, (e) => (rejected = e));
    open.push(reg);
    await wait(400);
    expect(rejected).toBe("INVALID_REGISTRATION");
  });
});
