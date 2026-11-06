import fs from 'node:fs';
import path from 'node:path';
import {
  computeFieldRoot,
  getFieldProof,
  sign,
  getPublicKeyFromSecret,
} from '@proofbook/crypto';
import { verifyBundleOffline, verifyProofBundle } from '../src/index.js';

const rootDir = path.resolve(import.meta.dirname, '../../..');
const pb1VectorsPath = path.join(rootDir, 'spec/test-vectors/pb1-vectors.json');
const pb1Vectors = JSON.parse(fs.readFileSync(pb1VectorsPath, 'utf8'));

// Author:
const authorPub = pb1Vectors.signatures.public_key;
const authorSig = pb1Vectors.signatures.signature;

// Approver:
const approverSecret = new Uint8Array(32).fill(8);
const approverPub = Buffer.from(getPublicKeyFromSecret(approverSecret)).toString('hex');
const leafHex = pb1Vectors.record_leaf.expected_leaf;
const leafBytes = Buffer.from(leafHex, 'hex');
const approverSig = Buffer.from(sign(leafBytes, approverSecret)).toString('hex');

// Fields & field proofs:
const fields = pb1Vectors.field_commitments.fields;
const salts = pb1Vectors.field_commitments.salts;
const fieldRootRes = computeFieldRoot(fields, salts);

const proofAmount = getFieldProof(fieldRootRes, 'amount');
const proofCurrency = getFieldProof(fieldRootRes, 'currency');

// Checkpoint tree from pb1Vectors.merkle_trees.three_leaves:
const merklePath = pb1Vectors.merkle_trees.three_leaves.proofs[0];
const expectedRoot = pb1Vectors.merkle_trees.three_leaves.root;

const sampleBundle = {
  version: 'PB1',
  network: 'testnet',
  contract_id: 'CDB4DCLRAIAGILGM4DWIOKOTSWDDY6IGP4X4FF62DA3GUQQ4LEKD5VCD',
  org: 'GDGZW7GAZNBP4NGIPRUTHTIE6JRUEAWNOEXKMSXK6XYWQPRAQP2HHMRQ',
  checkpoint_id: 1,
  auditors: ['GBHTYTJUH6BFBVER5OHDLLYYW4KOYH6J6L7WZVIAWH74H7FSOQCEZHI5'],
  record: {
    record_id: pb1Vectors.record_leaf.record_id,
    created_at: pb1Vectors.record_leaf.created_at,
    author: authorPub,
    field_root: fieldRootRes.rootHex,
    disclosed_fields: {
      amount: fields.amount,
      currency: fields.currency,
    },
    salts: {
      amount: salts.amount,
      currency: salts.currency,
    },
    field_proofs: {
      amount: proofAmount.proof,
      currency: proofCurrency.proof,
    },
  },
  merkle_path: merklePath,
  signatures: {
    author: authorSig,
    approvers: [
      {
        publicKey: approverPub,
        signature: approverSig,
      },
    ],
  },
  expected_root: expectedRoot,
};

console.log('Testing sampleBundle offline...');
const offlineRes = verifyBundleOffline(sampleBundle as any);
console.log('Offline valid?', offlineRes.valid, offlineRes.errors);

if (!offlineRes.valid) {
  process.exit(1);
}

verifyProofBundle(sampleBundle as any)
  .then((res) => {
    console.log('Live testnet valid?', res.valid, res.errors);
    console.log('On-chain report:', res.onChain);
    const outputPath = path.join(rootDir, 'spec/test-vectors/sample-bundle.json');
    fs.writeFileSync(outputPath, JSON.stringify(sampleBundle, null, 2));
    console.log('Wrote', outputPath);
  })
  .catch((err) => {
    console.error('Testnet check error:', err);
    process.exit(1);
  });
