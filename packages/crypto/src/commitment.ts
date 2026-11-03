import { sha256 } from '@noble/hashes/sha256';
import crypto from 'node:crypto';
import { DOMAIN_FIELD_COMMIT, buildMerkleTree, getMerkleProof, MerkleTree, MerkleProof } from './merkle.js';

const textEncoder = new TextEncoder();

/**
 * Generates 32 cryptographically secure random bytes for field salting.
 */
export function generateSalt(): Uint8Array {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Normalizes a salt representation into a 32-byte Uint8Array.
 */
export function normalizeSalt(salt: Uint8Array | string): Uint8Array {
  if (typeof salt === 'string') {
    const clean = salt.startsWith('0x') ? salt.slice(2) : salt;
    const buf = Buffer.from(clean, 'hex');
    if (buf.length !== 32) {
      throw new Error(`Salt hex must decode to exactly 32 bytes (got ${buf.length})`);
    }
    return new Uint8Array(buf);
  }
  if (salt.length !== 32) {
    throw new Error(`Salt must be exactly 32 bytes (got ${salt.length})`);
  }
  return salt;
}

/**
 * Computes a salted field commitment according to PB1:
 *
 * commit(k, v, s) = SHA256( 0x02 || len_u16_be(k) || k || len_u32_be(v) || v || s )
 */
export function commitField(
  name: string,
  value: string,
  salt: Uint8Array | string
): Uint8Array {
  const nameBytes = textEncoder.encode(name);
  if (nameBytes.length > 0xffff) {
    throw new Error(`Field name length exceeds 16-bit unsigned maximum: ${nameBytes.length}`);
  }

  const valueBytes = textEncoder.encode(value);
  if (valueBytes.length > 0xffffffff) {
    throw new Error(`Field value length exceeds 32-bit unsigned maximum: ${valueBytes.length}`);
  }

  const saltBytes = normalizeSalt(salt);

  // Total buffer length: 1 (domain) + 2 (name len) + nameBytes.length + 4 (value len) + valueBytes.length + 32 (salt)
  const totalLength = 1 + 2 + nameBytes.length + 4 + valueBytes.length + 32;
  const buffer = new Uint8Array(totalLength);
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let offset = 0;
  // Domain tag 0x02
  buffer[offset++] = DOMAIN_FIELD_COMMIT;

  // len_u16_be(name)
  view.setUint16(offset, nameBytes.length, false);
  offset += 2;

  // name
  buffer.set(nameBytes, offset);
  offset += nameBytes.length;

  // len_u32_be(value)
  view.setUint32(offset, valueBytes.length, false);
  offset += 4;

  // value
  buffer.set(valueBytes, offset);
  offset += valueBytes.length;

  // salt
  buffer.set(saltBytes, offset);
  offset += 32;

  return sha256(buffer);
}

export interface FieldCommitmentEntry {
  name: string;
  value: string;
  saltHex: string;
  commitment: Uint8Array;
  commitmentHex: string;
}

export interface FieldRootResult {
  root: Uint8Array;
  rootHex: string;
  tree: MerkleTree;
  sortedFields: FieldCommitmentEntry[];
}

/**
 * Computes the field commitments and Merkle field root for a record's fields.
 * Fields are sorted lexicographically by name before building the Merkle tree.
 */
export function computeFieldRoot(
  fields: Record<string, string>,
  salts: Record<string, Uint8Array | string>
): FieldRootResult {
  const keys = Object.keys(fields).sort();
  if (keys.length === 0) {
    throw new Error('Record must contain at least one field');
  }

  const sortedFields: FieldCommitmentEntry[] = [];
  const leafHashes: Uint8Array[] = [];

  for (const key of keys) {
    const value = fields[key];
    const salt = salts[key];
    if (salt === undefined) {
      throw new Error(`Missing salt for field: "${key}"`);
    }

    const saltBytes = normalizeSalt(salt);
    const commitment = commitField(key, value, saltBytes);

    sortedFields.push({
      name: key,
      value,
      saltHex: Buffer.from(saltBytes).toString('hex'),
      commitment,
      commitmentHex: Buffer.from(commitment).toString('hex'),
    });
    leafHashes.push(commitment);
  }

  const tree = buildMerkleTree(leafHashes);

  return {
    root: tree.root,
    rootHex: tree.rootHex,
    tree,
    sortedFields,
  };
}

/**
 * Generates a Merkle inclusion proof for a single field within the field tree.
 */
export function getFieldProof(
  fieldRootResult: FieldRootResult,
  fieldName: string
): { index: number; proof: MerkleProof } {
  const index = fieldRootResult.sortedFields.findIndex((f) => f.name === fieldName);
  if (index === -1) {
    throw new Error(`Field "${fieldName}" not found in field root`);
  }
  const proof = getMerkleProof(fieldRootResult.tree, index);
  return { index, proof };
}
