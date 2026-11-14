/**
 * SMS delivery — self-hosted gateway (LOGIN-3.5).
 *
 * Twilio was removed: it contradicts the self-hosted gateway decision, and a
 * third-party provider is a data processor we do not want holding login codes.
 *
 * Dispatch is now an outbox handshake, not a direct send:
 *   1. `POST /otp/send` writes a `sms_outbox` row (hash + AES-GCM payload).
 *   2. The gateway device polls `POST /api/v1/sms/outbox/poll` with
 *      `Authorization: Bearer $SMS_GATEWAY_TOKEN`.
 *   3. It sends the SMS over its own SIM, then calls
 *      `POST /api/v1/sms/outbox/:id/ack` with `{ status: "sent" | "failed" }`.
 *
 * `deliverOtpCode` is retained as the local-development path only. It never
 * contacts a provider and prints the code to the server console so onboarding
 * can be driven without a gateway attached.
 *
 * SECURITY: the raw code is never written to a plaintext column. The only
 * stored copy is `sms_outbox.payload`, encrypted with SMS_PAYLOAD_KEY and
 * cleared on ack (see sms/payload-crypto.ts).
 */

/**
 * Local-development delivery.
 *
 * @returns { delivered, via } — via is always "console" now.
 */
export async function deliverOtpCode(
  phoneNumber: string,
  rawCode: string,
): Promise<{ delivered: boolean; via: string }> {
  if (process.env.NODE_ENV === "production") {
    // In production the gateway poll is the only delivery path. Printing the
    // code would put it in the platform's log pipeline.
    return { delivered: false, via: "gateway" };
  }

  console.log(`[SMS-DEV] OTP for ${phoneNumber}: ${rawCode}`);
  return { delivered: false, via: "console" };
}
