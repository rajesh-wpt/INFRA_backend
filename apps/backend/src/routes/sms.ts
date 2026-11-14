import { Router, type NextFunction, type Request, type Response } from "express";
import { timingSafeEqual } from "node:crypto";
import { and, asc, eq, gt, sql } from "drizzle-orm";
import { getDb } from "../db/index.js";
import { smsOutbox } from "../db/sms-outbox-schema.js";
import { decryptOtpPayload } from "../sms/payload-crypto.js";

/**
 * LOGIN-3.5 — self-hosted SMS gateway handshake.
 *
 * The gateway is a device we operate (a phone with a SIM), not a SaaS. It
 * authenticates with a shared bearer token and drives the `sms_outbox` queue:
 *
 *   POST /api/v1/sms/outbox/poll   → claim pending rows (+ decrypted code)
 *   POST /api/v1/sms/outbox/:id/ack → mark sent/failed, clear the payload
 *
 * Auth is a static token because the gateway has no user account. The token is
 * compared in constant time. With no token configured the endpoints fail
 * closed (503) rather than exposing the queue unauthenticated.
 */
const router: Router = Router();

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_POLL_LIMIT = 50;
const DEFAULT_POLL_LIMIT = 10;

/**
 * Rows older than this are never handed to the gateway.
 *
 * The OTP itself expires after 5 minutes, so a code queued hours ago is both
 * useless and dangerous: a gateway that drains a backlog would send live
 * login codes for numbers that have moved on. (The queue had months-old
 * pending rows before this filter existed.) 10 minutes leaves room for a
 * gateway that was briefly offline without letting a backlog become SMS spam.
 */
const MAX_DELIVERY_AGE_MS = 10 * 60_000;

function requireGatewayToken(req: Request, res: Response, next: NextFunction): void {
  const configured = process.env.SMS_GATEWAY_TOKEN?.trim();

  if (!configured) {
    res.status(503).json({ error: "SMS_GATEWAY_NOT_CONFIGURED" });
    return;
  }

  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  if (scheme !== "Bearer" || !token) {
    res.status(401).json({ error: "UNAUTHORIZED" });
    return;
  }

  const presented = Buffer.from(token);
  const expected = Buffer.from(configured);
  if (
    presented.length !== expected.length ||
    !timingSafeEqual(presented, expected)
  ) {
    res.status(401).json({ error: "UNAUTHORIZED" });
    return;
  }

  next();
}

router.use(requireGatewayToken);

/**
 * Claim up to `limit` pending messages, oldest first.
 *
 * Polling does not remove a row: the gateway retries until it acks. Rows are
 * ordered by created_at so a backlog drains in the order it was queued.
 */
router.post("/outbox/poll", async (req: Request, res: Response) => {
  try {
    const requested = Number((req.body as { limit?: unknown } | undefined)?.limit);
    const limit = Number.isFinite(requested)
      ? Math.min(Math.max(Math.trunc(requested), 1), MAX_POLL_LIMIT)
      : DEFAULT_POLL_LIMIT;

    const rows = await getDb()
      .select({
        id: smsOutbox.id,
        phoneNumber: smsOutbox.phoneNumber,
        payload: smsOutbox.payload,
        attempts: smsOutbox.attempts,
        createdAt: smsOutbox.createdAt,
      })
      .from(smsOutbox)
      .where(
        and(
          eq(smsOutbox.status, "pending"),
          gt(smsOutbox.createdAt, new Date(Date.now() - MAX_DELIVERY_AGE_MS)),
        ),
      )
      .orderBy(asc(smsOutbox.createdAt))
      .limit(limit);

    res.json({
      items: rows.map((row) => ({
        id: row.id,
        phoneNumber: row.phoneNumber,
        // null when SMS_PAYLOAD_KEY is unset or the ciphertext is unreadable.
        code: decryptOtpPayload(row.payload),
        attempts: row.attempts,
        createdAt: row.createdAt,
      })),
    });
  } catch {
    console.error("POST /sms/outbox/poll error");
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * Acknowledge dispatch.
 *
 * Only a `pending` row can be acked, which makes a retried ack idempotent-ish:
 * the second call gets 404 instead of double-counting the attempt. The payload
 * is cleared so the code does not outlive its delivery.
 */
router.post("/outbox/:id/ack", async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { status } = (req.body ?? {}) as { status?: unknown };

    if (typeof id !== "string" || !UUID_RE.test(id)) {
      res.status(400).json({ error: "INVALID_OUTBOX_ID" });
      return;
    }

    if (status !== "sent" && status !== "failed") {
      res.status(400).json({ error: "STATUS_MUST_BE_SENT_OR_FAILED" });
      return;
    }

    const [updated] = await getDb()
      .update(smsOutbox)
      .set({
        status,
        sentAt: new Date(),
        payload: null,
        attempts: sql`${smsOutbox.attempts} + 1`,
      })
      .where(and(eq(smsOutbox.id, id), eq(smsOutbox.status, "pending")))
      .returning({ id: smsOutbox.id });

    if (!updated) {
      res.status(404).json({ error: "NOT_FOUND_OR_ALREADY_ACKED" });
      return;
    }

    res.json({ success: true, id: updated.id });
  } catch {
    console.error("POST /sms/outbox/:id/ack error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
