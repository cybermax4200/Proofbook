import { sha256 } from '@noble/hashes/sha256';
import { DOMAIN_RECORD_LEAF } from './merkle.js';
import { isValidRfc3339Utc } from './canonical.js';

const textEncoder = new TextEncoder();
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodes an RFC 4648 Base32 string (e.g., Stellar G... address).
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
 * Normalizes an Ed25519 public key into raw 32 bytes.
 * Supports:
 * - 32-byte Uint8Array or Buffer
 * - 64-character hex string (with optional '0x' or 'ed25519:' prefix)
 * - 56-character Stellar public key (StrKey 'G...')
 */
export function decodePublicKey(pubkey: Uint8Array | string): Uint8Array {
  if (pubkey instanceof Uint8Array || Buffer.isBuffer(pubkey)) {
    if (pubkey.length !== 32) {
      throw new Error(`Public key Uint8Array must be exactly 32 bytes (got ${pubkey.length})`);
    }
    return new Uint8Array(pubkey);
  }

  const s = pubkey.trim();

  // Stellar StrKey address starting with 'G' (56 chars)
  if (s.startsWith('G') && s.length === 56) {
    const decoded = decodeBase32(s);
    if (decoded.length !== 35 || decoded[0] !== 48 /* 6 << 3 */) {
      throw new Error(`Invalid Stellar G address encoding: ${s}`);
    }
    return decoded.subarray(1, 33);
  }

  // Hex string
  let hex = s;
  if (hex.startsWith('ed25519:')) {
    hex = hex.slice(8);
  } else if (hex.startsWith('0x')) {
    hex = hex.slice(2);
  }

  if (hex.length === 64 && /^[0-9a-fA-F]+$/.test(hex)) {
    const buf = Buffer.from(hex, 'hex');
    return new Uint8Array(buf);
  }

  throw new Error(`Unrecognized public key format: "${pubkey}"`);
}

export interface RecordLeafInputs {
  recordId: string;
  author: Uint8Array | string;
  createdAt: string; // RFC 3339 UTC timestamp, e.g. "2026-11-02T09:14:00Z"
  fieldRoot: Uint8Array | string;
}

/**
 * Computes the PB1 record leaf hash:
 *
 * leaf = SHA256( 0x00 || len_u16_be(record_id) || record_id || author_pubkey_raw || len_u16_be(created_at) || created_at || field_root )
 */
export function computeRecordLeaf(inputs: RecordLeafInputs): Uint8Array {
  const { recordId, author, createdAt, fieldRoot } = inputs;

  if (!isValidRfc3339Utc(createdAt)) {
    throw new Error(`createdAt must be a valid RFC 3339 UTC timestamp ending in 'Z' (got: "${createdAt}")`);
  }

  const recordIdBytes = textEncoder.encode(recordId);
  if (recordIdBytes.length > 0xffff) {
    throw new Error(`recordId length exceeds 16-bit unsigned maximum: ${recordIdBytes.length}`);
  }

  const createdAtBytes = textEncoder.encode(createdAt);
  if (createdAtBytes.length > 0xffff) {
    throw new Error(`createdAt length exceeds 16-bit unsigned maximum: ${createdAtBytes.length}`);
  }

  const authorRaw = decodePublicKey(author);

  const fieldRootRaw =
    typeof fieldRoot === 'string'
      ? new Uint8Array(Buffer.from(fieldRoot.startsWith('0x') ? fieldRoot.slice(2) : fieldRoot, 'hex'))
      : fieldRoot;

  if (fieldRootRaw.length !== 32) {
    throw new Error(`fieldRoot must be exactly 32 bytes (got ${fieldRootRaw.length})`);
  }

  // Total buffer length:
  // 1 (domain 0x00) + 2 (recordId len) + recordIdBytes.length + 32 (author) + 2 (createdAt len) + createdAtBytes.length + 32 (fieldRoot)
  const totalLength = 1 + 2 + recordIdBytes.length + 32 + 2 + createdAtBytes.length + 32;
  const buffer = new Uint8Array(totalLength);
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let offset = 0;
  // Domain tag 0x00
  buffer[offset++] = DOMAIN_RECORD_LEAF;

  // len_u16_be(record_id)
  view.setUint16(offset, recordIdBytes.length, false);
  offset += 2;

  // record_id
  buffer.set(recordIdBytes, offset);
  offset += recordIdBytes.length;

  // author_pubkey_raw (32 bytes)
  buffer.set(authorRaw, offset);
  offset += 32;

  // len_u16_be(created_at)
  view.setUint16(offset, createdAtBytes.length, false);
  offset += 2;

  // created_at
  buffer.set(createdAtBytes, offset);
  offset += createdAtBytes.length;

  // field_root (32 bytes)
  buffer.set(fieldRootRaw, offset);
  offset += 32;

  return sha256(buffer);
}

/**
 * Computes record leaf and returns lowercase 64-character hex string.
 */
export function computeRecordLeafHex(inputs: RecordLeafInputs): string {
  const leafBytes = computeRecordLeaf(inputs);
  return Buffer.from(leafBytes).toString('hex');
}
