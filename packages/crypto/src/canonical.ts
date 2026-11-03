/**
 * Canonical JSON Serialization (RFC 8785 JCS Subset for PB1)
 *
 * Guarantees that equivalent objects produce byte-for-byte identical UTF-8 encodings.
 * - Object keys are sorted lexicographically by UTF-16 code units.
 * - No insignificant whitespace (no indentation, no space after ':' or ',').
 * - Numbers in records should be formatted as decimal strings (e.g., "1250.00").
 * - Strings are escaped according to JSON standard rules (quotes, backslashes, control characters).
 */

const textEncoder = new TextEncoder();

/**
 * Escapes a string per RFC 8785 JSON Canonicalization Scheme.
 */
export function canonicalEscapeString(str: string): string {
  let result = '"';
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    const char = str[i];

    switch (char) {
      case '"':
        result += '\\"';
        break;
      case '\\':
        result += '\\\\';
        break;
      case '\b':
        result += '\\b';
        break;
      case '\f':
        result += '\\f';
        break;
      case '\n':
        result += '\\n';
        break;
      case '\r':
        result += '\\r';
        break;
      case '\t':
        result += '\\t';
        break;
      default:
        if (code < 0x20) {
          result += '\\u' + code.toString(16).padStart(4, '0');
        } else {
          result += char;
        }
        break;
    }
  }
  result += '"';
  return result;
}

/**
 * Deterministically serializes any JSON-compatible value to a canonical JSON string (RFC 8785).
 */
export function canonicalJson(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Cannot serialize non-finite number: ${value}`);
    }
    // Note: Record amounts in PB1 should be decimal strings (e.g. "1250.00")
    // for exact precision. If raw number is passed, format via standard JSON.stringify.
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    return canonicalEscapeString(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((v) => canonicalJson(v));
    return '[' + items.join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const pairs: string[] = [];
    for (const key of keys) {
      const val = (value as Record<string, unknown>)[key];
      if (val !== undefined && typeof val !== 'function' && typeof val !== 'symbol') {
        pairs.push(canonicalEscapeString(key) + ':' + canonicalJson(val));
      }
    }
    return '{' + pairs.join(',') + '}';
  }
  throw new TypeError(`Unsupported type for canonical JSON serialization: ${typeof value}`);
}

/**
 * Returns the UTF-8 bytes for a canonical JSON representation.
 */
export function canonicalBytes(value: unknown): Uint8Array {
  return textEncoder.encode(canonicalJson(value));
}

/**
 * Validates whether a string matches RFC 3339 UTC format (e.g. "2026-11-02T09:14:00Z").
 */
export function isValidRfc3339Utc(str: string): boolean {
  // Regex strictly matching RFC 3339 with 'Z' suffix (UTC)
  const regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
  if (!regex.test(str)) {
    return false;
  }
  const date = new Date(str);
  return !isNaN(date.getTime());
}

/**
 * Formats a numeric value or string as a fixed-precision decimal string.
 * Example: formatDecimal("1250", 2) -> "1250.00"
 */
export function formatDecimal(val: string | number | bigint, precision = 2): string {
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) throw new TypeError('Invalid number');
    return val.toFixed(precision);
  }
  if (typeof val === 'bigint') {
    if (precision === 0) return val.toString();
    return `${val}.${'0'.repeat(precision)}`;
  }
  const s = val.trim();
  if (!/^-?\d+(\.\d+)?$/.test(s)) {
    throw new Error(`Invalid decimal string: ${s}`);
  }
  const [intPart, fracPart = ''] = s.split('.');
  if (precision === 0) return intPart;
  const padded = fracPart.slice(0, precision).padEnd(precision, '0');
  return `${intPart}.${padded}`;
}
