import { describe, it } from 'node:test';
import assert from 'node:assert';
import { canonicalJson, canonicalBytes, formatDecimal, isValidRfc3339Utc } from '../src/canonical.js';

describe('PB1 Canonical Serialization', () => {
  it('sorts object keys lexicographically', () => {
    const unordered = { z: 1, a: 'hello', m: [3, 2, 1], b: { y: true, x: false } };
    const expected = '{"a":"hello","b":{"x":false,"y":true},"m":[3,2,1],"z":1}';
    assert.strictEqual(canonicalJson(unordered), expected);
  });

  it('escapes control characters and quotes per RFC 8785', () => {
    const raw = { text: 'Quote: "Hello"\nNewline\tTab\\Backslash' };
    const expected = '{"text":"Quote: \\"Hello\\"\\nNewline\\tTab\\\\Backslash"}';
    assert.strictEqual(canonicalJson(raw), expected);
  });

  it('encodes to UTF-8 canonical bytes deterministically', () => {
    const obj1 = { beta: 'two', alpha: 'one' };
    const obj2 = { alpha: 'one', beta: 'two' };
    const bytes1 = canonicalBytes(obj1);
    const bytes2 = canonicalBytes(obj2);
    assert.deepStrictEqual(bytes1, bytes2);
  });

  it('formats decimals to fixed precision', () => {
    assert.strictEqual(formatDecimal(1250, 2), '1250.00');
    assert.strictEqual(formatDecimal('1250.5', 2), '1250.50');
    assert.strictEqual(formatDecimal('1250.555', 2), '1250.55');
  });

  it('validates RFC 3339 UTC timestamps strictly', () => {
    assert.strictEqual(isValidRfc3339Utc('2026-11-02T09:14:00Z'), true);
    assert.strictEqual(isValidRfc3339Utc('2026-11-02T09:14:00.123Z'), true);
    assert.strictEqual(isValidRfc3339Utc('2026-11-02T09:14:00+01:00'), false); // non-Z UTC rejected
    assert.strictEqual(isValidRfc3339Utc('2026-11-02 09:14:00'), false);
  });
});
