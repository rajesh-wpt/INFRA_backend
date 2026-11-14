/**
 * ENC-4.5 — encrypted media serving (local storage driver).
 *
 * Two endpoints:
 *
 *   PUT  /media/group-icons/:name   upload ciphertext (app auth, local driver)
 *   GET  /media/group-icons/:name   download ciphertext (HMAC-signed URL)
 *
 * The bytes are opaque ciphertext produced by the client. The server stores and
 * returns them without inspecting their content, and the download carries
 * `application/octet-stream` plus `no-store` so nothing downstream tries to
 * interpret or cache them.
 *
 * When the Supabase driver is active the upload endpoint is refused: clients
 * upload straight to Supabase Storage and only the download URL is minted by
 * the backend (see storage/signed-url.ts).
 *
 * MOUNTING: PUT is mounted behind requireAuth; GET is public *by design* — the
 * URL itself is the capability (HMAC over bucket/name/expiry). No session is
 * required to fetch a blob, which is what lets an <img> tag / native image
 * loader fetch it directly.
 */

import { Router, type Request, type Response } from "express";
import { requireAuth } from "../middleware/auth.js";
import {
  MEDIA_NAME_RE,
  putLocalObject,
  readLocalObject,
  storageDriver,
  verifyMediaToken,
} from "../storage/signed-url.js";

const ICON_BUCKET = "group-icons";
/** 256 KB is generous for an encrypted 128px icon and keeps the JSON body sane. */
const MAX_ICON_BYTES = 256 * 1024;

export const mediaRouter: Router = Router();

// ──────────────────────────────────────────────────
// PUT /media/group-icons/:name — store ciphertext (app auth)
// Body: { ciphertext: base64 }
// ──────────────────────────────────────────────────
mediaRouter.put("/:bucket/:name", requireAuth, async (req: Request, res: Response) => {
  try {
    if (storageDriver() !== "local") {
      res.status(409).json({
        success: false,
        error: "UPLOAD_DRIVER_REMOTE",
        message: "This deployment uploads media directly to the storage provider",
      });
      return;
    }

    const bucket = req.params.bucket;
    const name = req.params.name;
    if (bucket !== ICON_BUCKET || typeof name !== "string" || !MEDIA_NAME_RE.test(name)) {
      res.status(400).json({ success: false, error: "INVALID_MEDIA_PATH" });
      return;
    }

    const body = req.body as { ciphertext?: unknown };
    if (typeof body.ciphertext !== "string" || body.ciphertext.length === 0) {
      res.status(400).json({
        success: false,
        error: "CIPHERTEXT_REQUIRED",
        message: "ciphertext must be a base64 string",
      });
      return;
    }
    const bytes = Buffer.from(body.ciphertext, "base64");
    if (bytes.length === 0 || bytes.toString("base64") !== body.ciphertext) {
      res.status(400).json({ success: false, error: "INVALID_CIPHERTEXT" });
      return;
    }
    if (bytes.length > MAX_ICON_BYTES) {
      res.status(413).json({
        success: false,
        error: "MEDIA_TOO_LARGE",
        message: `ciphertext exceeds ${MAX_ICON_BYTES} bytes`,
      });
      return;
    }

    const stored = putLocalObject(bucket, name, bytes);
    if (!stored) {
      res.status(400).json({ success: false, error: "INVALID_MEDIA_PATH" });
      return;
    }

    res.status(201).json({
      success: true,
      stored: { bucket, name, bytes: bytes.length },
    });
  } catch (err) {
    console.error("PUT /media error", err);
    res.status(500).json({ success: false, error: "INTERNAL_ERROR" });
  }
});

// ──────────────────────────────────────────────────
// GET /media/:bucket/:name?exp=..&sig=.. — signed download (public)
// ──────────────────────────────────────────────────
mediaRouter.get("/:bucket/:name", (req: Request, res: Response) => {
  try {
    const bucket = req.params.bucket;
    const name = req.params.name;
    const expRaw = req.query.exp;
    const sigRaw = req.query.sig;

    if (
      typeof bucket !== "string" ||
      typeof name !== "string" ||
      !MEDIA_NAME_RE.test(bucket) ||
      !MEDIA_NAME_RE.test(name)
    ) {
      res.status(400).json({ success: false, error: "INVALID_MEDIA_PATH" });
      return;
    }
    if (typeof expRaw !== "string" || typeof sigRaw !== "string") {
      res.status(401).json({ success: false, error: "SIGNATURE_REQUIRED" });
      return;
    }

    const check = verifyMediaToken(bucket, name, Number(expRaw), sigRaw);
    if (!check.ok) {
      res.status(403).json({
        success: false,
        error: check.reason === "expired" ? "URL_EXPIRED" : "INVALID_SIGNATURE",
      });
      return;
    }

    const bytes = readLocalObject(bucket, name);
    if (!bytes) {
      res.status(404).json({ success: false, error: "MEDIA_NOT_FOUND" });
      return;
    }

    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("Content-Length", String(bytes.length));
    res.status(200).send(bytes);
  } catch (err) {
    console.error("GET /media error", err);
    res.status(500).json({ success: false, error: "INTERNAL_ERROR" });
  }
});

export default mediaRouter;
