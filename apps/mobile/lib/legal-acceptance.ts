// lib/legal-acceptance.ts
//
// LEGAL-GATE — Durable legal-acceptance gate (ONB-1.3).
//
// The "I agree, I am 16+" action on legal-acceptance is the ONLY authorized
// path that marks terms as accepted. Acceptance is written to a durable store
// (SecureStore on native, localStorage on web). Every protected business screen
// (phone-entry, otp-entry, device-handoff) and the authenticated (tabs) layout
// must call `requireLegalAccepted()` before doing its work so the gate cannot be
// skipped by navigating straight to a URL or restoring a previous navigation stack.
import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

export const LEGAL_ACCEPTANCE_STORAGE_KEY = 'onb.legalAccepted';
export const LEGAL_ACCEPTED_VALUE = 'true';

const isWeb = Platform.OS === 'web';

type WebStore = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
};

function webStorage(): WebStore | null {
  try {
    if (typeof globalThis !== 'undefined' && 'localStorage' in globalThis) {
      return (globalThis as unknown as { localStorage: WebStore }).localStorage;
    }
  } catch {
    // Access can throw in private mode / blocked storage.
  }
  return null;
}

async function getItem(key: string): Promise<string | null> {
  if (isWeb) {
    try {
      return webStorage()?.getItem(key) ?? null;
    } catch {
      return null;
    }
  }
  return SecureStore.getItemAsync(key);
}

async function setItem(key: string, value: string): Promise<void> {
  if (isWeb) {
    try {
      webStorage()?.setItem(key, value);
    } catch {
      // Ignore storage write failures so the flow can still proceed.
    }
    return;
  }
  await SecureStore.setItemAsync(key, value);
}

export function isLegalAcceptedValue(value: string | null): boolean {
  return value === LEGAL_ACCEPTED_VALUE;
}

export function recordLegalAcceptance(): Promise<void> {
  return setItem(LEGAL_ACCEPTANCE_STORAGE_KEY, LEGAL_ACCEPTED_VALUE);
}

export function clearLegalAcceptance(): Promise<void> {
  return setItem(LEGAL_ACCEPTANCE_STORAGE_KEY, '');
}

export async function hasAcceptedLegal(): Promise<boolean> {
  const raw = await getItem(LEGAL_ACCEPTANCE_STORAGE_KEY);
  return isLegalAcceptedValue(raw);
}

export async function requireLegalAccepted(): Promise<boolean> {
  return hasAcceptedLegal();
}
