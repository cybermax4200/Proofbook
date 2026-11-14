/**
 * Client-Side Ed25519 Key Store for Maker & Checker Personas
 *
 * Persists Ed25519 signing keys in browser localStorage and provides
 * deterministic default keys for seamless Maker-Checker co-signing demos.
 */

import {
  ClientEd25519Keypair,
  derivePublicKeyHex,
  generateClientKeypair,
} from './crypto-client';

export type PortalRole = 'maker' | 'checker';

export interface RoleKeyProfile {
  role: PortalRole;
  label: string;
  email: string;
  keyId: string;
  secretKeyHex: string;
  publicKeyHex: string;
}

const STORAGE_KEY = 'proofbook_client_keystore_v1';

// Deterministic default seeds matching PB1 test vectors for out-of-the-box testing
const DEFAULT_MAKER_SECRET =
  '1111111111111111111111111111111111111111111111111111111111111111';
const DEFAULT_CHECKER_SECRET =
  '2222222222222222222222222222222222222222222222222222222222222222';

export function getDefaultKeyProfiles(): Record<PortalRole, RoleKeyProfile> {
  const makerPub = derivePublicKeyHex(DEFAULT_MAKER_SECRET);
  const checkerPub = derivePublicKeyHex(DEFAULT_CHECKER_SECRET);

  return {
    maker: {
      role: 'maker',
      label: 'Alice Vance (Maker)',
      email: 'maker@acme-treasury.io',
      keyId: 'key_maker_ed25519_01',
      secretKeyHex: DEFAULT_MAKER_SECRET,
      publicKeyHex: makerPub,
    },
    checker: {
      role: 'checker',
      label: 'Marcus Sterling (Checker)',
      email: 'checker@acme-treasury.io',
      keyId: 'key_checker_ed25519_01',
      secretKeyHex: DEFAULT_CHECKER_SECRET,
      publicKeyHex: checkerPub,
    },
  };
}

export function loadKeyProfiles(): Record<PortalRole, RoleKeyProfile> {
  const defaults = getDefaultKeyProfiles();
  if (typeof window === 'undefined' || !window.localStorage) {
    return defaults;
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(defaults));
      return defaults;
    }
    const parsed = JSON.parse(raw);
    if (parsed?.maker?.secretKeyHex && parsed?.checker?.secretKeyHex) {
      return {
        maker: {
          ...defaults.maker,
          ...parsed.maker,
          publicKeyHex: derivePublicKeyHex(parsed.maker.secretKeyHex),
        },
        checker: {
          ...defaults.checker,
          ...parsed.checker,
          publicKeyHex: derivePublicKeyHex(parsed.checker.secretKeyHex),
        },
      };
    }
  } catch {
    // Fallback to defaults if localStorage is unavailable or corrupted
  }
  return defaults;
}

export function rotateRoleKeypair(role: PortalRole): Record<PortalRole, RoleKeyProfile> {
  const current = loadKeyProfiles();
  const fresh: ClientEd25519Keypair = generateClientKeypair();
  const suffix = fresh.publicKeyHex.slice(0, 6);

  const updated: Record<PortalRole, RoleKeyProfile> = {
    ...current,
    [role]: {
      ...current[role],
      keyId: `key_${role}_${suffix}`,
      secretKeyHex: fresh.secretKeyHex,
      publicKeyHex: fresh.publicKeyHex,
    },
  };

  if (typeof window !== 'undefined' && window.localStorage) {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  }

  return updated;
}

export function resetDefaultKeyProfiles(): Record<PortalRole, RoleKeyProfile> {
  const defaults = getDefaultKeyProfiles();
  if (typeof window !== 'undefined' && window.localStorage) {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(defaults));
  }
  return defaults;
}
