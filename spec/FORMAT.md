# Proofbook Cryptographic Format Specification (PB1)

**Version:** PB1  
**Status:** Draft / Reference Implementation  

This document specifies the exact byte-level cryptographic encoding, canonical serialization, Merkle tree construction, and signature model for Proofbook records and checkpoints.

---

## 1. Cryptographic Primitives & Constants

| Purpose | Primitive | Specification / Encoding |
|---|---|---|
| **Hashing** | SHA-256 | FIPS 180-4, output is 32 bytes |
| **Signatures** | Ed25519 | RFC 8032 (Ed25519 pure), 64-byte signature over 32-byte leaf hash |
| **Public Keys** | Ed25519 Public Key | 32 raw bytes (compatible with Stellar `G...` StrKey addresses) |
| **Salts** | CSPRNG | Exactly 32 random bytes, independently generated per field |
| **Timestamps** | RFC 3339 UTC | ISO 8601 subset ending strictly in `Z` (e.g., `2026-11-02T09:14:00Z`) |

### Domain Separation Tags

To prevent second-preimage attacks and type confusion between different levels of the Merkle structure, PB1 enforces single-byte domain separation prefixes:

- `0x00`: **Record Leaf**
- `0x01`: **Internal Merkle Tree Node**
- `0x02`: **Salted Field Commitment**

---

## 2. Canonical JSON Serialization (RFC 8785 JCS Subset)

All record JSON bodies must be deterministically serialized prior to hashing or signing:
1. Object keys must be sorted lexicographically by UTF-16 code units.
2. No insignificant whitespace (no indentation, no trailing commas, no space after `:` or `,`).
3. Strings must be encoded in UTF-8 with standard JSON escape sequences (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, `\u00xx`).
4. Monetary amounts and floating-point values must be encoded as fixed-precision decimal strings (e.g. `"1250.00"`).

---

## 3. Salted Field Commitments

Each field within a record is committed independently with a unique 32-byte salt:

$$\text{commit}(k, v, s) = \text{SHA256}(0x02 \parallel \text{len\_u16\_be}(k) \parallel k \parallel \text{len\_u32\_be}(v) \parallel v \parallel s)$$

Where:
- `0x02`: 1 byte domain separation prefix.
- `len_u16_be(k)`: 2-byte big-endian byte-length of UTF-8 field name $k$.
- $k$: UTF-8 byte sequence of field name.
- `len_u32_be(v)`: 4-byte big-endian byte-length of UTF-8 canonical value $v$.
- $v$: UTF-8 canonical byte sequence of field value.
- $s$: 32-byte raw salt.

### Field Merkle Root

The record's **Field Root** is the Merkle root built over the field commitments, sorted lexicographically by field name ($k_0 < k_1 < \dots < k_{n-1}$).

---

## 4. Record Leaf Hash

The record leaf commits to the record ID, author public key, timestamp, and the field root:

$$\text{leaf} = \text{SHA256}(0x00 \parallel \text{len\_u16\_be}(\text{record\_id}) \parallel \text{record\_id} \parallel \text{author\_pubkey\_raw} \parallel \text{len\_u16\_be}(\text{created\_at}) \parallel \text{created\_at} \parallel \text{field\_root})$$

Where:
- `0x00`: 1 byte domain separation tag.
- `len_u16_be(record_id)`: 2-byte big-endian length of UTF-8 record ID.
- `record_id`: UTF-8 byte sequence.
- `author_pubkey_raw`: 32-byte raw Ed25519 public key.
- `len_u16_be(created_at)`: 2-byte big-endian length of RFC 3339 UTC timestamp string.
- `created_at`: UTF-8 byte sequence.
- `field_root`: 32-byte SHA-256 field root.

Author signatures and maker-checker approval signatures sign exactly this 32-byte `leaf` hash.

---

## 5. Checkpoint Merkle Tree

The checkpoint Merkle tree aggregates record leaves ordered by their deterministic sequence number.

### Internal Nodes
$$\text{node} = \text{SHA256}(0x01 \parallel \text{left} \parallel \text{right})$$

- `0x01`: 1 byte domain separation prefix.
- `left`: 32-byte left child hash.
- `right`: 32-byte right child hash.

### Odd-Node Promotion
If a level contains an odd number of nodes, the trailing odd node is **promoted unchanged** to the next level without duplicate hashing. Duplicating odd nodes is forbidden because it introduces Merkle tree ambiguity.

### Single-Leaf Tree
If a tree contains exactly one leaf, the Merkle root is the leaf hash itself:
$$\text{root} = \text{leaf}_0$$

---

## 6. Proof Bundle Structure (`bundle.json`)

```json
{
  "version": "PB1",
  "network": "testnet",
  "contract_id": "C...",
  "org": "G...",
  "checkpoint_id": 1,
  "record": {
    "record_id": "01HZX6789ABCDEF",
    "created_at": "2026-11-02T09:14:00Z",
    "author": "ed25519:4b92b6...",
    "disclosed_fields": {
      "amount": "1250.00",
      "currency": "USD"
    },
    "salts": {
      "amount": "010101...",
      "currency": "020202..."
    },
    "field_proofs": {
      "amount": [{ "side": "right", "hash": "..." }]
    }
  },
  "merkle_path": [
    { "side": "left", "hash": "..." }
  ],
  "signatures": {
    "author": "...",
    "approvers": ["..."]
  },
  "expected_root": "..."
}
```
