import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalJson,
  commitField,
  computeFieldRoot,
  computeRecordLeafHex,
  buildMerkleTree,
  getMerkleProof,
  getPublicKeyFromSecret,
  sign,
} from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '../../..');

// Deterministic test data
const fieldSalts = {
  amount: Buffer.alloc(32, 1).toString('hex'),
  currency: Buffer.alloc(32, 2).toString('hex'),
  payee: Buffer.alloc(32, 3).toString('hex'),
  purpose: Buffer.alloc(32, 4).toString('hex'),
};

const fields = {
  amount: '1250.00',
  currency: 'USD',
  payee: 'Acme Supplies Ltd',
  purpose: 'Classroom materials, batch 4',
};

const fieldRootRes = computeFieldRoot(fields, fieldSalts);

const fixedSecret = Buffer.alloc(32, 7);
const authorPub = getPublicKeyFromSecret(fixedSecret);
const authorPubHex = Buffer.from(authorPub).toString('hex');

const recordInputs = {
  recordId: '01HZX6789ABCDEF0123456789A',
  author: authorPubHex,
  createdAt: '2026-11-02T09:14:00Z',
  fieldRoot: fieldRootRes.rootHex,
};

const recordLeafHex = computeRecordLeafHex(recordInputs);
const signature = Buffer.from(sign(Buffer.from(recordLeafHex, 'hex'), fixedSecret)).toString('hex');

// Merkle trees
const leaves3 = [
  recordLeafHex,
  Buffer.alloc(32, 0x11).toString('hex'),
  Buffer.alloc(32, 0x22).toString('hex'),
];
const tree3 = buildMerkleTree(leaves3.map((l) => Buffer.from(l, 'hex')));

const leaves5 = [
  recordLeafHex,
  Buffer.alloc(32, 0x11).toString('hex'),
  Buffer.alloc(32, 0x22).toString('hex'),
  Buffer.alloc(32, 0x33).toString('hex'),
  Buffer.alloc(32, 0x44).toString('hex'),
];
const tree5 = buildMerkleTree(leaves5.map((l) => Buffer.from(l, 'hex')));

const vectors = {
  version: 'PB1',
  description: 'Proofbook Format PB1 Test Vectors',
  canonical_serialization: {
    input: { z: 1, a: 'hello', m: [3, 2, 1], b: { y: true, x: false } },
    expected: canonicalJson({ z: 1, a: 'hello', m: [3, 2, 1], b: { y: true, x: false } }),
  },
  field_commitments: {
    fields,
    salts: fieldSalts,
    commitments: Object.fromEntries(
      fieldRootRes.sortedFields.map((f) => [f.name, f.commitmentHex])
    ),
    field_root: fieldRootRes.rootHex,
  },
  record_leaf: {
    record_id: recordInputs.recordId,
    author: recordInputs.author,
    created_at: recordInputs.createdAt,
    field_root: recordInputs.fieldRoot,
    expected_leaf: recordLeafHex,
  },
  signatures: {
    secret_key: fixedSecret.toString('hex'),
    public_key: authorPubHex,
    message: recordLeafHex,
    signature,
  },
  merkle_trees: {
    three_leaves: {
      leaves: leaves3,
      root: tree3.rootHex,
      proofs: leaves3.map((_, i) => getMerkleProof(tree3, i)),
    },
    five_leaves: {
      leaves: leaves5,
      root: tree5.rootHex,
      proofs: leaves5.map((_, i) => getMerkleProof(tree5, i)),
    },
  },
};

const specDir = path.join(rootDir, 'spec/test-vectors');
fs.mkdirSync(specDir, { recursive: true });
fs.writeFileSync(path.join(specDir, 'pb1-vectors.json'), JSON.stringify(vectors, null, 2) + '\n');
console.log('Generated spec/test-vectors/pb1-vectors.json successfully!');
