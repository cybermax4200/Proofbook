import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as StellarSdk from '@stellar/stellar-sdk';
import { MockSorobanAnchorClient } from '../src/soroban.js';

describe('MockSorobanAnchorClient Contract Semantics', () => {
  test('handles org registration and idempotency', async () => {
    const client = new MockSorobanAnchorClient();
    const org = StellarSdk.Keypair.random();

    const reg1 = await client.registerOrg(org);
    assert.equal(reg1.alreadyRegistered, false);
    assert.ok(reg1.txHash);

    const reg2 = await client.registerOrg(org);
    assert.equal(reg2.alreadyRegistered, true);
  });

  test('enforces OrgNotRegistered, PeriodRegression, and CountDecreased', async () => {
    const client = new MockSorobanAnchorClient();
    const org = StellarSdk.Keypair.random();
    const root1 = 'aa'.repeat(32);

    // 1. Unregistered org
    await assert.rejects(
      async () => {
        await client.anchorCheckpoint({
          orgKeypair: org,
          rootHex: root1,
          recordCount: 5,
          periodStart: 1000,
          periodEnd: 2000,
        });
      },
      /OrgNotRegistered/
    );

    // Register org
    await client.registerOrg(org);

    // 2. period_end < period_start
    await assert.rejects(
      async () => {
        await client.anchorCheckpoint({
          orgKeypair: org,
          rootHex: root1,
          recordCount: 5,
          periodStart: 2000,
          periodEnd: 1000,
        });
      },
      /PeriodRegression/
    );

    // Successful checkpoint 1
    const cp1 = await client.anchorCheckpoint({
      orgKeypair: org,
      rootHex: root1,
      recordCount: 5,
      periodStart: 1000,
      periodEnd: 2000,
    });
    assert.equal(cp1.checkpointId, 1);
    assert.ok(cp1.txHash);

    // 3. CountDecreased in checkpoint 2
    const root2 = 'bb'.repeat(32);
    await assert.rejects(
      async () => {
        await client.anchorCheckpoint({
          orgKeypair: org,
          rootHex: root2,
          recordCount: 4, // Less than previous 5
          periodStart: 2500,
          periodEnd: 3000,
        });
      },
      /CountDecreased/
    );

    // 4. PeriodRegression in checkpoint 2 (periodStart < prev.periodEnd)
    await assert.rejects(
      async () => {
        await client.anchorCheckpoint({
          orgKeypair: org,
          rootHex: root2,
          recordCount: 7,
          periodStart: 1500, // Less than prev periodEnd 2000
          periodEnd: 3000,
        });
      },
      /PeriodRegression/
    );

    // Successful checkpoint 2
    const cp2 = await client.anchorCheckpoint({
      orgKeypair: org,
      rootHex: root2,
      recordCount: 7,
      periodStart: 2000,
      periodEnd: 3000,
    });
    assert.equal(cp2.checkpointId, 2);

    // Query latest checkpoint
    const latest = await client.getLatestCheckpoint(org.publicKey());
    assert.ok(latest);
    assert.equal(latest.id, 2);
    assert.equal(latest.root, root2);
    assert.equal(latest.prevRoot, root1);
    assert.equal(latest.recordCount, 7n);
  });
});
