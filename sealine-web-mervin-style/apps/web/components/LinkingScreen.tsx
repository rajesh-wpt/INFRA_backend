"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { generateWebPublicKeys } from "@wpt/crypto";
import { LINKING_TOKEN_TTL_SECONDS, type AccountLinkedPayload } from "@wpt/shared";
import { useSession } from "../app/providers";
import { useSearchParams } from "next/navigation";
import type { Socket } from "socket.io-client";

export function LinkingScreen() {
  const { backend, linked, saveLinkedSession } = useSession();
  const searchParams = useSearchParams();
  const [token, setToken] = useState("");
  const [expiresAt, setExpiresAt] = useState(0);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const [status, setStatus] = useState("Creating secure linking QR…");
  const [showLogoutPopup, setShowLogoutPopup] = useState(false);
  const socketRef = useRef<Socket | null>(null);
  const linkedRef = useRef(false);
  const registeredAt = useRef(0);

  useEffect(() => {
    const reason = searchParams.get("reason");
    if (reason) {
      setShowLogoutPopup(true);
    }
  }, [searchParams]);

  // Detach a socket completely so none of its late events can trigger a second QR or a reconnect.
  const retire = useCallback((socket: Socket | null) => {
    if (!socket) return;
    socket.removeAllListeners();
    socket.close();
  }, []);

  const createQr = useCallback(() => {
    if (!backend) {
      setStatus("Set API_BASE_URL to the real BE-6.1 backend.");
      return;
    }
    retire(socketRef.current);
    const newToken = backend.createToken();
    const keys = generateWebPublicKeys();
    registeredAt.current = Date.now();
    linkedRef.current = false;
    setToken(newToken);
    setStatus("Waiting for your phone to scan…");

    // BE-6.1: the backend wants a FLAT payload { token, identityPublicKey, signingPublicKey }.
    const registration = backend.register(
      { token: newToken, identityPublicKey: keys.identityPublicKey, signingPublicKey: keys.signingPublicKey },
      (error) => {
        if (socketRef.current !== registration.socket || linkedRef.current) return;
        setToken(""); // never show a QR the server does not know about
        setStatus(`The backend rejected the linking request (${error}). Click Refresh QR.`);
      }
    );
    socketRef.current = registration.socket;

    registration.socket.on("accountLinked", (payload: AccountLinkedPayload) => {
      linkedRef.current = true;
      setStatus("Linked. Opening Sealine…");
      saveLinkedSession(payload);
      // Linking channel is done; closing it also prevents the backend's late linkExpired from ever mattering.
      retire(registration.socket);
      socketRef.current = null;
    });

    registration.socket.on("linkExpired", () => {
      if (linkedRef.current) return; // backend sends linkExpired ~60s even after a successful link
      createQr();
    });

    registration.socket.on("connect_error", (error: Error) => {
      if (linkedRef.current) return;
      setStatus(`Backend connection error: ${error.message}`);
    });
    // No manual reconnect: socket.io reconnects by itself and register() re-sends the SAME token on "connect".
  }, [backend, retire, saveLinkedSession]);

  useEffect(() => {
    createQr();
    return () => retire(socketRef.current);
  }, [createQr, retire]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      const remaining = Math.max(0, Math.ceil((registeredAt.current + LINKING_TOKEN_TTL_SECONDS * 1000 - Date.now()) / 1000));
      setExpiresAt(registeredAt.current + LINKING_TOKEN_TTL_SECONDS * 1000);
      setSecondsLeft(remaining);
      if (remaining === 0 && token && !linkedRef.current) createQr();
    }, 500);
    return () => window.clearInterval(timer);
  }, [createQr, token]);

  if (linked) return <main className="page"><section className="card success"><div style={{ fontSize: 56 }}>👋</div><h1>Welcome to Sealine</h1><p className="muted">Your account has been linked successfully.</p></section></main>;

  return <main className="page">
    <section className="card">
      <div className="brand">Sealine</div>
      <p className="muted">Open Sealine on your phone → Settings → Scan QR Code.</p>
      {token && <>
        <div className="qr"><QRCodeSVG value={token} size={280} level="M" /></div>
        <div className="countdown">QR expires in {secondsLeft}s</div>
      </>}
      <div className="status">{status}</div>
      {expiresAt > 0 && <button className="primary" onClick={() => createQr()}>Refresh QR</button>}
    </section>
    {showLogoutPopup && (
      <div className="popup-overlay" onClick={() => setShowLogoutPopup(false)}>
        <div className="popup" onClick={(e) => e.stopPropagation()}>
          <h2>Session Ended</h2>
          <p>You are logged out or session expired</p>
          <button className="primary" onClick={() => setShowLogoutPopup(false)}>OK</button>
        </div>
      </div>
    )}
  </main>;
}