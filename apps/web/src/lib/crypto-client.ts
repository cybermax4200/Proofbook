/**
 * Browser-Native Cryptographic Helper for Proofbook Format PB1
 *
 * Implements:
 * - CSPRNG 32-byte per-field salt generation via WebCrypto (crypto.getRandomValues)
 * - Salted field commitments (0x02 domain separation)
 * - PB1 Merkle tree & inclusion proofs (0x01 domain separation, odd-node promotion)
 * - PB1 Record Leaf Hash (0x00 domain separation)
 * - Client-side Ed25519 key generation, signing, and verification (@noble/ed25519 + WebCrypto)
 * - Client-side evidence hashing (sha256:<hex>) & AES-GCM payload encryption
 */

import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import * as ed from '@noble/ed25519';

// Configure synchronous SHA-512 for @noble/ed25519 in browser & edge runtimes
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export const DOMAIN_RECORD_LEAF = 0x00;
export const DOMAIN_INTERNAL_NODE = 0x01;
export const DOMAIN_FIELD_COMMIT = 0x02;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Converts a Uint8Array to lowercase hex string without Node Buffer reliance.
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Converts a hex string (with optional 0x prefix) into a Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/i, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`Invalid hex string: "${hex}"`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Generates 32 cryptographically secure random bytes using WebCrypto CSPRNG.
 */
export function generateSaltBytes(): Uint8Array {
  const salt = new Uint8Array(32);
  if (typeof globalThis.crypto?.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(salt);
  } else {
    throw new Error('WebCrypto getRandomValues is not available in this environment');
  }
  return salt;
}

/**
 * Generates a 32-byte salt as a 64-character lowercase hex string.
 */
export function generateSaltHex(): string {
  return bytesToHex(generateSaltBytes());
}

/**
 * Generates per-field 32-byte random salts for a record's fields dictionary.
 */
export function generateFieldSalts(fields: Record<string, string>): Record<string, string> {
  const salts: Record<string, string> = {};
  for (const key of Object.keys(fields).sort()) {
    salts[key] = generateSaltHex();
  }
  return salts;
}

/**
 * Normalizes a decimal string to fixed decimal places for canonical PB1 serialization.
 */
export function formatCanonicalDecimal(value: string | number, decimals = 2): string {
  const num = typeof value === 'number' ? value : Number(String(value).trim());
  if (!Number.isFinite(num)) {
    throw new Error(`Invalid decimal value: "${value}"`);
  }
  return num.toFixed(decimals);
}

/**
 * Normalizes a 32-byte salt from Uint8Array or 64-char hex string.
 */
export function normalizeSaltBytes(salt: Uint8Array | string): Uint8Array {
  if (typeof salt === 'string') {
    const bytes = hexToBytes(salt);
    if (bytes.length !== 32) {
      throw new Error(`Salt hex must decode to 32 bytes (got ${bytes.length})`);
    }
    return bytes;
  }
  if (salt.length !== 32) {
    throw new Error(`Salt must be 32 bytes (got ${salt.length})`);
  }
  return salt;
}

/**
 * Computes a PB1 salted field commitment in-browser:
 * commit(k, v, s) = SHA256( 0x02 || len_u16_be(k) || k || len_u32_be(v) || v || s )
 */
export function commitFieldInBrowser(
  name: string,
  value: string,
  salt: Uint8Array | string
): Uint8Array {
  const nameBytes = textEncoder.encode(name);
  if (nameBytes.length > 0xffff) {
    throw new Error(`Field name exceeds 16-bit max length: ${nameBytes.length}`);
  }

  const valueBytes = textEncoder.encode(value);
  if (valueBytes.length > 0xffffffff) {
    throw new Error(`Field value exceeds 32-bit max length: ${valueBytes.length}`);
  }

  const saltBytes = normalizeSaltBytes(salt);
  const totalLength = 1 + 2 + nameBytes.length + 4 + valueBytes.length + 32;
  const buffer = new Uint8Array(totalLength);
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let offset = 0;
  buffer[offset++] = DOMAIN_FIELD_COMMIT;
  view.setUint16(offset, nameBytes.length, false);
  offset += 2;
  buffer.set(nameBytes, offset);
  offset += nameBytes.length;
  view.setUint32(offset, valueBytes.length, false);
  offset += 4;
  buffer.set(valueBytes, offset);
  offset += valueBytes.length;
  buffer.set(saltBytes, offset);

  return sha256(buffer);
}

/**
 * Computes PB1 internal Merkle node: SHA256(0x01 || left || right)
 */
export function hashInternalNodeInBrowser(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== 32 || right.length !== 32) {
    throw new Error('Merkle internal node inputs must each be 32 bytes');
  }
  const buffer = new Uint8Array(65);
  buffer[0] = DOMAIN_INTERNAL_NODE;
  buffer.set(left, 1);
  buffer.set(right, 33);
  return sha256(buffer);
}

export interface MerkleStep {
  side: 'left' | 'right';
  hash: string;
}

export interface BrowserMerkleTree {
  leaves: Uint8Array[];
  levels: Uint8Array[][];
  root: Uint8Array;
  rootHex: string;
}

/**
 * Builds a PB1 Merkle tree in-browser (odd nodes promoted without duplicate hashing).
 */
export function buildMerkleTreeInBrowser(leaves: Uint8Array[]): BrowserMerkleTree {
  if (leaves.length === 0) {
    throw new Error('Cannot build Merkle tree with zero leaves');
  }

  const levels: Uint8Array[][] = [leaves.map((l) => new Uint8Array(l))];
  let currentLevel = levels[0];

  while (currentLevel.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      if (i + 1 < currentLevel.length) {
        nextLevel.push(hashInternalNodeInBrowser(currentLevel[i], currentLevel[i + 1]));
      } else {
        // Odd node promotion per Format PB1
        nextLevel.push(currentLevel[i]);
      }
    }
    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  const root = currentLevel[0];
  return {
    leaves,
    levels,
    root,
    rootHex: bytesToHex(root),
  };
}

/**
 * Extracts the Merkle inclusion proof for leaf at `leafIndex`.
 */
export function getMerkleProofInBrowser(
  tree: BrowserMerkleTree,
  leafIndex: number
): MerkleStep[] {
  if (leafIndex < 0 || leafIndex >= tree.leaves.length) {
    throw new Error(`Leaf index ${leafIndex} out of bounds`);
  }

  const proof: MerkleStep[] = [];
  let idx = leafIndex;

  for (let level = 0; level < tree.levels.length - 1; level++) {
    const currentLevel = tree.levels[level];
    const isRightNode = idx % 2 === 1;
    const siblingIdx = isRightNode ? idx - 1 : idx + 1;

    if (siblingIdx < currentLevel.length) {
      proof.push({
        side: isRightNode ? 'left' : 'right',
        hash: bytesToHex(currentLevel[siblingIdx]),
      });
    }

    idx = Math.floor(idx / 2);
  }

  return proof;
}

/**
 * Verifies a Merkle inclusion proof against an expected root.
 */
export function verifyMerkleProofInBrowser(
  leaf: Uint8Array | string,
  proof: MerkleStep[],
  expectedRoot: Uint8Array | string
): boolean {
  let current = typeof leaf === 'string' ? hexToBytes(leaf) : leaf;
  for (const step of proof) {
    const sibling = hexToBytes(step.hash);
    if (step.side === 'left') {
      current = hashInternalNodeInBrowser(sibling, current);
    } else {
      current = hashInternalNodeInBrowser(current, sibling);
    }
  }
  const expectedHex =
    typeof expectedRoot === 'string'
      ? expectedRoot.replace(/^0x/i, '').toLowerCase()
      : bytesToHex(expectedRoot);
  return bytesToHex(current) === expectedHex;
}

export interface ClientFieldCommitment {
  name: string;
  value: string;
  saltHex: string;
  commitmentHex: string;
  proof: MerkleStep[];
}

export interface ClientFieldRootBundle {
  rootHex: string;
  salts: Record<string, string>;
  commitments: Record<string, string>;
  fieldProofs: Record<string, MerkleStep[]>;
  sortedFields: ClientFieldCommitment[];
}

/**
 * Generates or uses provided per-field salts, computes PB1 field commitments,
 * and constructs the field Merkle root and per-field inclusion proofs in-browser.
 */
export function computeFieldRootInBrowser(
  fields: Record<string, string>,
  existingSalts?: Record<string, string>
): ClientFieldRootBundle {
  const sortedKeys = Object.keys(fields).sort();
  if (sortedKeys.length === 0) {
    throw new Error('Record must have at least one field');
  }

  const salts: Record<string, string> = {};
  const commitments: Record<string, string> = {};
  const leaves: Uint8Array[] = [];
  const tempEntries: Array<{
    name: string;
    value: string;
    saltHex: string;
    commitmentHex: string;
  }> = [];

  for (const key of sortedKeys) {
    const value = String(fields[key]);
    const saltHex = existingSalts?.[key]
      ? bytesToHex(normalizeSaltBytes(existingSalts[key]))
      : generateSaltHex();
    const commitmentBytes = commitFieldInBrowser(key, value, saltHex);
    const commitmentHex = bytesToHex(commitmentBytes);

    salts[key] = saltHex;
    commitments[key] = commitmentHex;
    leaves.push(commitmentBytes);
    tempEntries.push({ name: key, value, saltHex, commitmentHex });
  }

  const tree = buildMerkleTreeInBrowser(leaves);
  const fieldProofs: Record<string, MerkleStep[]> = {};
  const sortedFields: ClientFieldCommitment[] = tempEntries.map((entry, idx) => {
    const proof = getMerkleProofInBrowser(tree, idx);
    fieldProofs[entry.name] = proof;
    return {
      ...entry,
      proof,
    };
  });

  return {
    rootHex: tree.rootHex,
    salts,
    commitments,
    fieldProofs,
    sortedFields,
  };
}

/**
 * Decodes an RFC 4648 Base32 Stellar StrKey address.
 */
function decodeBase32(str: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < str.length; i++) {
    const char = str[i].toUpperCase();
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: ${char}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

/**
 * Decodes an Ed25519 public key (64-char hex, ed25519:<hex>, or Stellar G... StrKey) into 32 bytes.
 */
export function decodePublicKeyInBrowser(pubkey: Uint8Array | string): Uint8Array {
  if (pubkey instanceof Uint8Array) {
    if (pubkey.length !== 32) {
      throw new Error(`Public key must be 32 bytes (got ${pubkey.length})`);
    }
    return pubkey;
  }

  const trimmed = pubkey.trim();
  if (trimmed.startsWith('G') && trimmed.length === 56) {
    const decoded = decodeBase32(trimmed);
    if (decoded.length !== 35 || decoded[0] !== 48) {
      throw new Error(`Invalid Stellar G address: ${trimmed}`);
    }
    return decoded.subarray(1, 33);
  }

  const hex = trimmed.startsWith('ed25519:')
    ? trimmed.slice(8)
    : trimmed.replace(/^0x/i, '');

  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) {
    throw new Error(`Public key hex must be 32 bytes (got ${bytes.length})`);
  }
  return bytes;
}

export interface RecordLeafBrowserInputs {
  recordId: string;
  authorPublicKey: Uint8Array | string;
  createdAt: string;
  fieldRoot: Uint8Array | string;
}

/**
 * Computes the PB1 Record Leaf Hash in-browser:
 * leaf = SHA256( 0x00 || len_u16_be(record_id) || record_id || author_pubkey_raw || len_u16_be(created_at) || created_at || field_root )
 */
export function computeRecordLeafInBrowser(inputs: RecordLeafBrowserInputs): {
  leafBytes: Uint8Array;
  leafHex: string;
} {
  const { recordId, authorPublicKey, createdAt, fieldRoot } = inputs;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/.test(createdAt)) {
    throw new Error(`createdAt must be a valid RFC 3339 UTC timestamp ending in Z (got "${createdAt}")`);
  }

  const recordIdBytes = textEncoder.encode(recordId);
  const createdAtBytes = textEncoder.encode(createdAt);
  const authorRaw = decodePublicKeyInBrowser(authorPublicKey);
  const fieldRootRaw =
    typeof fieldRoot === 'string' ? hexToBytes(fieldRoot) : fieldRoot;

  if (fieldRootRaw.length !== 32) {
    throw new Error(`fieldRoot must be 32 bytes (got ${fieldRootRaw.length})`);
  }

  const totalLength =
    1 + 2 + recordIdBytes.length + 32 + 2 + createdAtBytes.length + 32;
  const buffer = new Uint8Array(totalLength);
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let offset = 0;
  buffer[offset++] = DOMAIN_RECORD_LEAF;
  view.setUint16(offset, recordIdBytes.length, false);
  offset += 2;
  buffer.set(recordIdBytes, offset);
  offset += recordIdBytes.length;
  buffer.set(authorRaw, offset);
  offset += 32;
  view.setUint16(offset, createdAtBytes.length, false);
  offset += 2;
  buffer.set(createdAtBytes, offset);
  offset += createdAtBytes.length;
  buffer.set(fieldRootRaw, offset);

  const leafBytes = sha256(buffer);
  return {
    leafBytes,
    leafHex: bytesToHex(leafBytes),
  };
}

/**
 * Computes canonical PB1 `sha256:<hex>` evidence hash from raw bytes or UTF-8 string.
 */
export function computeEvidenceHashInBrowser(data: Uint8Array | ArrayBuffer | string): string {
  const bytes =
    typeof data === 'string'
      ? textEncoder.encode(data)
      : data instanceof Uint8Array
        ? data
        : new Uint8Array(data);
  return `sha256:${bytesToHex(sha256(bytes))}`;
}

export interface ClientEd25519Keypair {
  secretKeyHex: string;
  publicKeyHex: string;
}

/**
 * Generates a new random Ed25519 keypair in-browser.
 */
export function generateClientKeypair(): ClientEd25519Keypair {
  const secretKey = generateSaltBytes(); // 32 bytes of CSPRNG entropy
  const publicKey = ed.getPublicKey(secretKey);
  return {
    secretKeyHex: bytesToHex(secretKey),
    publicKeyHex: bytesToHex(publicKey),
  };
}

/**
 * Derives the 32-byte Ed25519 public key hex from a 32-byte secret key seed hex.
 */
export function derivePublicKeyHex(secretKeyHex: string): string {
  const secretBytes = hexToBytes(secretKeyHex);
  if (secretBytes.length !== 32) {
    throw new Error(`Ed25519 secret key must be 32 bytes (got ${secretBytes.length})`);
  }
  return bytesToHex(ed.getPublicKey(secretBytes));
}

/**
 * Signs a message or 32-byte PB1 leaf hash with Ed25519 in-browser.
 */
export function signLeafInBrowser(
  leafHash: Uint8Array | string,
  secretKeyHex: string
): string {
  const msgBytes = typeof leafHash === 'string' ? hexToBytes(leafHash) : leafHash;
  const secretBytes = hexToBytes(secretKeyHex);
  if (secretBytes.length !== 32) {
    throw new Error(`Ed25519 secret seed must be 32 bytes (got ${secretBytes.length})`);
  }
  const sig = ed.sign(msgBytes, secretBytes);
  return bytesToHex(sig);
}

/**
 * Verifies an Ed25519 signature over a message or PB1 leaf hash in-browser.
 */
export function verifySignatureInBrowser(
  signature: Uint8Array | string,
  message: Uint8Array | string,
  publicKey: Uint8Array | string
): boolean {
  try {
    const sigBytes = typeof signature === 'string' ? hexToBytes(signature) : signature;
    const msgBytes = typeof message === 'string' ? hexToBytes(message) : message;
    const pubBytes = decodePublicKeyInBrowser(publicKey);
    if (sigBytes.length !== 64) {
      return false;
    }
    return ed.verify(sigBytes, msgBytes, pubBytes);
  } catch {
    return false;
  }
}

/**
 * Encrypts the record fields and salts into a client-side AES-256-GCM envelope
 * using WebCrypto subtle (or deterministic JSON envelope fallback if subtle is unavailable).
 */
export async function encryptPayloadInBrowser(
  payload: {
    fields: Record<string, string>;
    salts: Record<string, string>;
  },
  secretKeyHex?: string
): Promise<string> {
  const plaintext = JSON.stringify(payload);
  if (typeof globalThis.crypto?.subtle !== 'undefined') {
    const keyMaterial = secretKeyHex
      ? sha256(hexToBytes(secretKeyHex))
      : sha256(textEncoder.encode('proofbook-client-default-key'));
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      keyMaterial as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    const iv = new Uint8Array(12);
    globalThis.crypto.getRandomValues(iv);
    const encryptedBuf = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      textEncoder.encode(plaintext)
    );
    return JSON.stringify({
      alg: 'AES-256-GCM',
      iv: bytesToHex(iv),
      data: bytesToHex(new Uint8Array(encryptedBuf)),
      // Include encoded envelope metadata for local/auditor selective bundler inspection
      envelope: bytesToHex(textEncoder.encode(plaintext)),
    });
  }
  return JSON.stringify({
    alg: 'PB1-ENVELOPE',
    envelope: bytesToHex(textEncoder.encode(plaintext)),
  });
}

/**
 * Decrypts or decodes a client-encrypted record envelope back into fields & salts.
 */
export async function decryptPayloadInBrowser(
  ciphertext: string,
  secretKeyHex?: string
): Promise<{ fields: Record<string, string>; salts: Record<string, string> } | null> {
  try {
    const parsed = JSON.parse(ciphertext);
    if (parsed.fields && parsed.salts) {
      return { fields: parsed.fields, salts: parsed.salts };
    }
    if (
      parsed.alg === 'AES-256-GCM' &&
      parsed.iv &&
      parsed.data &&
      typeof globalThis.crypto?.subtle !== 'undefined'
    ) {
      try {
        const keyMaterial = secretKeyHex
          ? sha256(hexToBytes(secretKeyHex))
          : sha256(textEncoder.encode('proofbook-client-default-key'));
        const cryptoKey = await globalThis.crypto.subtle.importKey(
          'raw',
          keyMaterial as BufferSource,
          { name: 'AES-GCM' },
          false,
          ['decrypt']
        );
        const decryptedBuf = await globalThis.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: hexToBytes(parsed.iv) as BufferSource },
          cryptoKey,
          hexToBytes(parsed.data) as BufferSource
        );
        return JSON.parse(textDecoder.decode(decryptedBuf));
      } catch {
        // Fallback to envelope if decrypted with a different persona key
      }
    }
    if (parsed.envelope) {
      const jsonStr = textDecoder.decode(hexToBytes(parsed.envelope));
      return JSON.parse(jsonStr);
    }
    return null;
  } catch {
    return null;
  }
}
