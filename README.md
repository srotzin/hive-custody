# @hivecivilization/hive-custody

<div align="center">
<img src="https://img.shields.io/badge/license-Apache%202.0-FFB800?style=flat-square" />
<img src="https://img.shields.io/badge/patent%20pending-USPTO%2064%2F055%2C601-FFB800?style=flat-square" />
<img src="https://img.shields.io/badge/tests-45%20passing-FFB800?style=flat-square" />
</div>

**Custody-chain tainting and Merkle proofs for agent data lineage.**

Every data transform appends a signed `CustodyNode` with `prev_hash + transform_id + agent_did + timestamp + payload_hash + taint_status + sig`. If any node is tainted, all downstream nodes are automatically flagged `TAINTED`. A Merkle tree over the chain lets endpoints prove a fragment without revealing the whole chain.

---

## Claim Reference

**USPTO 64/055,601 — HiveAttest Claim C16**

> *A custody-chain tainting method for agent data lineage: each data transform appends a cryptographically-signed node containing the previous-node hash, transform identifier, agent DID, timestamp, payload hash, and taint status; taint propagates forward so that if any ancestral node is tainted all downstream nodes are automatically marked tainted; a Merkle tree over the chain enables fragment disclosure with O(log n) proof size.*

---

## Quick Start

```typescript
import { CustodyChain, verifyMerkleProof } from "@hivecivilization/hive-custody";
import * as ed from "@noble/ed25519";

const privKey = ed.utils.randomPrivateKey();
const chain = new CustodyChain();

// Append transforms
chain.append({ transformId: "ingest", agentDid: "did:hive:agent:ingester", payload: rawDoc, privKey });
chain.append({ transformId: "summarize", agentDid: "did:hive:agent:summarizer", payload: summary, privKey });

// Inject taint from an untrusted source
chain.append({ transformId: "enrich", agentDid: "did:hive:agent:enricher", payload: enriched, privKey,
  taintStatus: "tainted" });

// All subsequent nodes are automatically tainted
chain.append({ transformId: "route", agentDid: "did:hive:agent:router", payload: routed, privKey });
console.log(chain.getTaintStatus()); // "tainted"

// Verify chain integrity
const result = chain.verifyChain();
console.log(result.valid, result.chainTaintStatus); // true, "tainted"

// Merkle proof for fragment disclosure
const root = chain.getMerkleRoot();
const proof = chain.getMerkleProof(1);
console.log(verifyMerkleProof(proof, root)); // true — node 1 is in this chain
```

---

## API

| Export | Description |
|--------|-------------|
| `CustodyChain` | Mutable chain. `append()`, `getNodes()`, `getTaintStatus()`, `verifyChain()`, `getMerkleRoot()`, `getMerkleProof()` |
| `nodeHash(node)` | SHA-256 of canonical node body (excluding signature) |
| `merkleRoot(leaves)` | Binary Merkle root over leaf hashes |
| `buildMerkleProof(leaves, idx)` | Inclusion proof for leaf at index |
| `verifyMerkleProof(proof, root)` | Stateless proof verification |

---

## NOTICE

Reference implementation — USPTO 64/055,601, HiveAttest Claim C16.  
Inventor: Stephen A. Rotzin. Apache License 2.0.
