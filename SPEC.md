# Custody Chain with Taint — Normative Specification

**Patent reference:** USPTO Provisional 64/055,601, claim C16
**Status:** Layer C reference. Wire format normative; production-grade hardening is Layer B.
**Author:** Stephen A. Rotzin, pro se
**Date:** 2026-05-02

---

## 1. Purpose

Data in agentic pipelines passes through many hands: ingest nodes, transform
nodes, LLM inference calls, tool invocations, and write-back steps. Existing
systems provide no cryptographic record of this traversal. The Custody Chain
with Taint primitive (hereafter "Custody Chain") solves two related problems:

1. **Chain of custody:** Each transform step is appended as a signed node to an
   append-only chain. Any observer can reconstruct and verify the full history of
   how a data artifact was produced.

2. **Taint propagation:** If any node in the chain is marked `tainted`, the
   entire chain's `chain_taint_status` becomes permanently `tainted`. Taint is
   one-way: once set, it cannot be cleared. This allows downstream consumers to
   make trust decisions without inspecting every node individually.

The Custody Chain is designed for use in AI agent pipelines where provenance
and accountability are required for regulatory compliance, audit, or
multi-party trust.

---

## 2. Conformance Terms

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in RFC 2119.

- An **issuer** is the HiveAttest service that appends nodes and signs receipts.
- A **chain** is identified by a `chain_id` string; all nodes sharing a
  `chain_id` form an ordered sequence.
- A **relying party** is any system that verifies node receipts or chain state.
- **Taint propagation rule:** If `chain_taint_status` is `"tainted"` for any
  existing node in a chain, all subsequent appends MUST also produce
  `chain_taint_status = "tainted"` regardless of the new node's
  `taint_status` field.

---

## 3. Wire Format

### 3.1 Append Request

`POST /v1/attest/custody/append`

```json
{
  "chain_id":     "<string, required>",
  "transform_id": "<string, required>",
  "agent_did":    "<string, required>",
  "payload":      "<object | array | string, required>",
  "taint_status": "<\"clean\" | \"tainted\" | \"unknown\", required>"
}
```

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `chain_id` | string | REQUIRED | Identifies the chain. All nodes with this ID form a single custody sequence. Callers choose this value; UUID v4 RECOMMENDED. |
| `transform_id` | string | REQUIRED | Unique identifier for this specific transform step. UUID v4 RECOMMENDED. |
| `agent_did` | string | REQUIRED | DID of the agent performing this transform. |
| `payload` | any JSON value | REQUIRED | The data artifact produced by this step. Stored and hashed as part of the node. |
| `taint_status` | enum | REQUIRED | One of `"clean"`, `"tainted"`, `"unknown"`. If `"tainted"`, the chain is permanently tainted. |

### 3.2 Append Response

```json
{
  "node": {
    "node_id":       "<uuid-v4>",
    "chain_id":      "<echoed>",
    "node_index":    "<integer, 0-based>",
    "transform_id":  "<echoed>",
    "agent_did":     "<echoed>",
    "payload_hash":  "<hex SHA-256 of JCS(payload)>",
    "taint_status":  "<echoed>",
    "appended_at":   "<ISO-8601 UTC>",
    "prev_hash":     "<hex SHA-256 of previous node's canonical form, or null for index 0>",
    "signing": {
      "algorithm": "EdDSA",
      "curve":     "Ed25519",
      "key_id":    "<base64url SHA-256 of issuer public key>",
      "signature": "<base64url Ed25519 signature over JCS of signed body>"
    }
  },
  "chain_id":          "<string>",
  "chain_length":      "<integer>",
  "chain_taint_status":"<\"clean\" | \"tainted\" | \"unknown\">",
  "merkle_root":       "<hex SHA-256 Merkle root over all node hashes in chain>",
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/hive-custody/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C16"
  }
}
```

| Field | Type | Semantics |
|-------|------|-----------|
| `node.node_id` | string (UUID v4) | Issuer-assigned unique node identifier. |
| `node.node_index` | integer | 0-based position in the chain. |
| `node.payload_hash` | string | Lowercase hex SHA-256 of `JCS(payload)`. |
| `node.prev_hash` | string or null | Hash of the immediately preceding node's canonical signed body, providing a cryptographic link. `null` for the first node (`node_index == 0`). |
| `chain_taint_status` | enum | Aggregate taint for the entire chain. Once `"tainted"`, MUST remain `"tainted"`. |
| `merkle_root` | string | Hex SHA-256 Merkle root over all appended node hashes. Enables compact membership proofs. |

### 3.3 Verify Request

`POST /v1/attest/custody/verify`

```json
{
  "nodes": [ "<node object from append response>", "..." ]
}
```

Response:

```json
{
  "valid":   true,
  "errors":  [],
  "_meta":   { "layer": "C", "production_grade": false, "spec_url": "...", "patent": "USPTO 64/055,601", "claim": "C16" }
}
```

### 3.4 Proof Request

`POST /v1/attest/custody/proof`

```json
{
  "chain_id":   "<string, required>",
  "node_index": "<integer, required>"
}
```

Response returns a Merkle inclusion proof for the specified node:

```json
{
  "chain_id":    "<string>",
  "node_index":  "<integer>",
  "node_hash":   "<hex>",
  "merkle_root": "<hex>",
  "proof_path":  [ { "hash": "<hex>", "direction": "left | right" }, "..." ],
  "_meta":       { "layer": "C", "production_grade": false, "spec_url": "...", "patent": "USPTO 64/055,601", "claim": "C16" }
}
```

---

## 4. Cryptography

### 4.1 Algorithms

| Primitive | Algorithm | Reference |
|-----------|-----------|-----------|
| Signing | Ed25519 (EdDSA) | RFC 8032 |
| Canonicalization | JSON Canonicalization Scheme (JCS) | RFC 8785 |
| Hashing | SHA-256 | FIPS 180-4 |
| Key identifier | base64url-no-pad SHA-256 of public key bytes | — |
| Merkle tree | Binary SHA-256 Merkle tree | — |

### 4.2 Payload Hash

```
payload_hash = lowercase_hex( SHA-256( UTF-8( JCS( payload ) ) ) )
```

### 4.3 Signed Body Construction

The issuer signs the following object, JCS-canonicalized:

```json
{
  "agent_did":    "<string>",
  "appended_at":  "<ISO-8601 UTC>",
  "chain_id":     "<string>",
  "node_id":      "<uuid-v4>",
  "node_index":   <integer>,
  "payload_hash": "<hex>",
  "prev_hash":    "<hex or null>",
  "taint_status": "<enum>",
  "transform_id": "<string>"
}
```

```
signature = Ed25519Sign( privKey, UTF-8( JCS( signedBody ) ) )
```

### 4.4 Previous-Node Hash (Chain Link)

```
prev_hash = lowercase_hex( SHA-256( UTF-8( JCS( prevSignedBody ) ) ) )
```

Where `prevSignedBody` is the same signed body object (minus `signing`) of the
immediately preceding node. This forms a hash-linked chain analogous to a
blockchain, but without consensus: the issuer is the sole authority.

### 4.5 Merkle Root

All node hashes are the SHA-256 of each node's JCS-canonical signed body:

```
node_hash[i] = SHA-256( UTF-8( JCS( signedBody[i] ) ) )
merkle_root  = MerkleRoot( [node_hash[0], node_hash[1], ..., node_hash[n-1]] )
```

The Merkle tree uses standard binary pairing with SHA-256 at each level. Odd
leaf counts are handled by duplicating the last leaf.

### 4.6 Taint Propagation

The issuer MUST maintain persistent chain state. On every append:

```
if stored_chain_taint == "tainted" OR incoming.taint_status == "tainted":
    chain_taint_status = "tainted"
elif stored_chain_taint == "unknown" OR incoming.taint_status == "unknown":
    chain_taint_status = "unknown"
else:
    chain_taint_status = "clean"
```

Once `"tainted"`, the chain MUST NOT be reset to `"clean"` or `"unknown"`.

---

## 5. Endpoints (HTTP)

Base URL: `https://hivemorph.onrender.com`

### 5.1 Append a Node

```
POST /v1/attest/custody/append
Content-Type: application/json
```

**Example request:**

```json
{
  "chain_id":     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "transform_id": "txfm-001-ingest",
  "agent_did":    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "payload":      { "source": "s3://raw/file.csv", "rows_read": 10000 },
  "taint_status": "clean"
}
```

**Example response (HTTP 200):**

```json
{
  "node": {
    "node_id":       "9c2f1a3b-4d5e-6f70-8192-a3b4c5d6e7f8",
    "chain_id":      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "node_index":    0,
    "transform_id":  "txfm-001-ingest",
    "agent_did":     "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "payload_hash":  "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b",
    "taint_status":  "clean",
    "appended_at":   "2026-05-02T14:00:00.000Z",
    "prev_hash":     null,
    "signing": {
      "algorithm": "EdDSA",
      "curve":     "Ed25519",
      "key_id":    "ZoRSOrFzpuqyLbCgJLRkpCRB2iSjT7tMmrNV9xWfBQA",
      "signature": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz01"
    }
  },
  "chain_id":           "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "chain_length":       1,
  "chain_taint_status": "clean",
  "merkle_root":        "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b",
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/hive-custody/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C16"
  }
}
```

### 5.2 Verify a Node Set

```
POST /v1/attest/custody/verify
Content-Type: application/json
```

Accepts an array of node objects (as returned by `/append`) and verifies
signatures, chain links, and taint consistency.

### 5.3 Get a Merkle Inclusion Proof

```
POST /v1/attest/custody/proof
Content-Type: application/json
```

Returns a proof that a specific node is included in the chain's Merkle tree.

---

## 6. Layer C Honesty Contract

Every response from this endpoint MUST carry:

- **HTTP header:** `X-Hive-Layer: C-Reference`
- **Body field `_meta.layer`:** `"C"`
- **Body field `_meta.production_grade`:** `false`
- **Body field `_meta.spec_url`:** `"https://raw.githubusercontent.com/srotzin/hive-custody/main/SPEC.md"`
- **Body field `_meta.patent`:** `"USPTO 64/055,601"`
- **Body field `_meta.claim`:** `"C16"`

---

## 7. Receipts and Verifiability

Given only the array of node receipts and the issuer's 32-byte Ed25519 public key,
a third party MUST be able to:

1. **Verify each node's signature** by reconstructing its signed body (Section 4.3),
   JCS-canonicalizing, and verifying the Ed25519 signature.
2. **Verify chain links** by computing `SHA-256(JCS(signedBody[i]))` for each node
   and confirming it equals `node[i+1].prev_hash`.
3. **Verify taint monotonicity:** scan from `node_index = 0` to the final node;
   once `"tainted"` is observed, all subsequent nodes MUST also be `"tainted"`.
4. **Verify Merkle inclusion** using the proof returned by `/proof`: reconstruct
   the root from the proof path and compare to `merkle_root`.
5. **Verify payload integrity:** re-hash `payload` using `JCS + SHA-256` and
   compare to `payload_hash`.

All five verifications are purely local; no network call is required.

---

## 8. Security Considerations

1. **In-process key storage.** The Ed25519 private key is held in process memory
   with no HSM backing. Process compromise exposes the signing key and allows
   retroactive forgery of custody nodes.

2. **No key rotation.** A single key pair signs all nodes. There is no rotation
   protocol; `key_id` acts as a version identifier but the issuer provides no
   signed key-rotation statement.

3. **Server-side taint enforcement only.** Taint monotonicity is enforced by the
   issuer's in-memory or in-process chain state. If the server is restarted
   without durable storage, chain state may be lost, and a `"tainted"` chain
   could be re-created as `"clean"` under the same `chain_id`.

4. **No transparency log.** Appended nodes are not published to an external
   tamper-evident log. The issuer can silently drop or reorder nodes.

5. **No revocation.** Individual nodes cannot be revoked. If a node was signed
   with a compromised key, there is no mechanism to invalidate it short of
   re-issuing the entire chain.

6. **Merkle tree without external anchor.** The `merkle_root` is computed by the
   issuer and returned in the same response. Without an external anchor (e.g.,
   a blockchain timestamp or notary service), the root is only as trustworthy as
   the issuer.

7. **No DID resolution.** `agent_did` is stored verbatim without validation
   against a DID registry. Any syntactically valid DID is accepted.

8. **Chain ID collisions.** If two callers use the same `chain_id`, their nodes
   will be interleaved on the server. Callers MUST use UUIDs or other globally
   unique identifiers to avoid unintentional chain merges.

---

## 9. References

- USPTO Provisional Application No. 64/055,601 — HiveAttest patent family
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- FIPS 180-4 — Secure Hash Standard (SHA-256)

---

## Appendix A. Test Vectors

The following two-node sequence can be replayed against the live endpoint.
Server-computed values (signatures, timestamps) are shown as placeholders.

**Step 1 — First node (clean):**

```
POST https://hivemorph.onrender.com/v1/attest/custody/append
Content-Type: application/json

{
  "chain_id":     "00000000-0000-0000-0000-000000000002",
  "transform_id": "test-txfm-001",
  "agent_did":    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8siQmFe2BCM7",
  "payload":      { "step": 1, "data": "hello" },
  "taint_status": "clean"
}
```

Expected: `node_index = 0`, `prev_hash = null`, `chain_taint_status = "clean"`.

**Step 2 — Second node (tainted):**

```
POST https://hivemorph.onrender.com/v1/attest/custody/append
Content-Type: application/json

{
  "chain_id":     "00000000-0000-0000-0000-000000000002",
  "transform_id": "test-txfm-002",
  "agent_did":    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8siQmFe2BCM7",
  "payload":      { "step": 2, "data": "compromised" },
  "taint_status": "tainted"
}
```

Expected: `node_index = 1`, `prev_hash = <SHA-256 of step 1 signed body>`,
`chain_taint_status = "tainted"`.

**Step 3 — Third node (attempt to clean, MUST still be tainted):**

```json
{ "taint_status": "clean", ... }
```

Expected: `chain_taint_status = "tainted"` (taint is irreversible).

**Payload hash for step 1 (`{"data":"hello","step":1}` in JCS key order):**
SHA-256 of `{"data":"hello","step":1}` (UTF-8, JCS-sorted) is deterministic
and MUST match `node.payload_hash` for this vector.
