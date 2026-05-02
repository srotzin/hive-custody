/**
 * Types for hive-custody — Custody-Chain Tainting (HiveAttest C16).
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

/** Taint status of a custody node or chain. */
export type TaintStatus = "clean" | "tainted" | "unknown";

/** A single node in the custody chain. */
export interface CustodyNode {
  /** Unique node ID (UUID v4). */
  node_id: string;
  /** Transform or processing step identifier. */
  transform_id: string;
  /** DID of the agent that performed this transform. */
  agent_did: string;
  /** ISO-8601 UTC timestamp. */
  timestamp: string;
  /** SHA-256 hex of this node's payload (the data at this point in the chain). */
  payload_hash: string;
  /** SHA-256 hex of the previous node's canonical representation (or "genesis" for the first). */
  prev_hash: string;
  /** Taint status of this node. */
  taint_status: TaintStatus;
  /** Base64url Ed25519 signature over JCS body (excluding this field). */
  signature: string;
  /** Base64url raw 32-byte public key that signed this node. */
  key_id: string;
}

/** Result of appending a node. */
export interface AppendResult {
  node: CustodyNode;
  /** Chain-level taint status after appending (propagated). */
  chainTaintStatus: TaintStatus;
}

/** A Merkle inclusion proof for a single custody node. */
export interface MerkleProof {
  /** The node being proven. */
  nodeId: string;
  /** Leaf hash (SHA-256 of the canonical node). */
  leafHash: string;
  /** Sibling hashes on the path from leaf to root, bottom-up. */
  siblings: Array<{ hash: string; position: "left" | "right" }>;
  /** Merkle root. */
  root: string;
}

/** Result of verifying a full custody chain. */
export interface ChainVerifyResult {
  valid: boolean;
  /** Index of the first invalid node, if any. */
  firstInvalidIndex?: number;
  reason?: string;
  /** Per-node taint status after propagation. */
  taintStatuses: TaintStatus[];
  /** Chain-level taint (tainted if any node is tainted). */
  chainTaintStatus: TaintStatus;
}
