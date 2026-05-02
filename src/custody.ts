/**
 * hive-custody — Custody-Chain Tainting (HiveAttest Claim C16).
 *
 * Each data transform appends a signed custody node with:
 *   prev_hash + transform_id + agent_did + timestamp + payload_hash + taint_status + signature
 *
 * Taint propagation: if any node is TAINTED, all downstream nodes are TAINTED
 * regardless of their own declared status.
 *
 * Merkle tree over the chain enables fragment disclosure without revealing the
 * full chain (O(log n) proof size).
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import type {
  AppendResult,
  ChainVerifyResult,
  CustodyNode,
  MerkleProof,
  TaintStatus,
} from "./types.js";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function b64uEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function b64uDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// JCS canonicalize (minimal, no external dep)
// ---------------------------------------------------------------------------

function canonicalize(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return JSON.stringify(v)!;
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.filter((k) => obj[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
  }
  throw new TypeError(`canonicalize: non-serializable ${typeof v}`);
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

function sha256Hex(data: string | Uint8Array): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return bytesToHex(sha256(bytes));
}

/** Compute the canonical hash of a CustodyNode (excluding its signature field). */
export function nodeHash(node: CustodyNode): string {
  const body: Omit<CustodyNode, "signature"> = {
    node_id: node.node_id,
    transform_id: node.transform_id,
    agent_did: node.agent_did,
    timestamp: node.timestamp,
    payload_hash: node.payload_hash,
    prev_hash: node.prev_hash,
    taint_status: node.taint_status,
    key_id: node.key_id,
  };
  return sha256Hex(canonicalize(body));
}

// ---------------------------------------------------------------------------
// UUID helper
// ---------------------------------------------------------------------------

function randomUUID(): string {
  const c = (globalThis as Record<string, unknown>).crypto as { randomUUID?: () => string } | undefined;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  const b = ed.utils.randomPrivateKey().slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

function signingBody(node: CustodyNode): Uint8Array {
  const body: Omit<CustodyNode, "signature"> = {
    node_id: node.node_id,
    transform_id: node.transform_id,
    agent_did: node.agent_did,
    timestamp: node.timestamp,
    payload_hash: node.payload_hash,
    prev_hash: node.prev_hash,
    taint_status: node.taint_status,
    key_id: node.key_id,
  };
  return new TextEncoder().encode(canonicalize(body));
}

// ---------------------------------------------------------------------------
// Merkle tree (binary, SHA-256, left-pad odd layers with copy of last node)
// ---------------------------------------------------------------------------

function merkleParent(left: string, right: string): string {
  return sha256Hex(left + right);
}

function buildMerkleTree(leaves: string[]): string[][] {
  if (leaves.length === 0) return [[]];
  const layers: string[][] = [leaves.slice()];
  let current = leaves.slice();
  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i]; // duplicate last
      next.push(merkleParent(left, right));
    }
    layers.push(next);
    current = next;
  }
  return layers;
}

export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return sha256Hex("empty");
  const layers = buildMerkleTree(leaves);
  return layers[layers.length - 1][0];
}

export function buildMerkleProof(leaves: string[], index: number): MerkleProof {
  if (index < 0 || index >= leaves.length)
    throw new RangeError(`Index ${index} out of range [0, ${leaves.length})`);
  const layers = buildMerkleTree(leaves);
  const root = layers[layers.length - 1][0];
  const siblings: Array<{ hash: string; position: "left" | "right" }> = [];
  let idx = index;
  for (let l = 0; l < layers.length - 1; l++) {
    const layer = layers[l];
    const isRightChild = idx % 2 === 1;
    const siblingIdx = isRightChild ? idx - 1 : Math.min(idx + 1, layer.length - 1);
    siblings.push({
      hash: layer[siblingIdx],
      position: isRightChild ? "left" : "right",
    });
    idx = Math.floor(idx / 2);
  }
  return { nodeId: "", leafHash: leaves[index], siblings, root };
}

export function verifyMerkleProof(proof: MerkleProof, root: string): boolean {
  let current = proof.leafHash;
  for (const sib of proof.siblings) {
    current = sib.position === "left"
      ? merkleParent(sib.hash, current)
      : merkleParent(current, sib.hash);
  }
  return current === root;
}

// ---------------------------------------------------------------------------
// CustodyChain
// ---------------------------------------------------------------------------

export class CustodyChain {
  private readonly nodes: CustodyNode[] = [];
  private chainTaint: TaintStatus = "clean";

  /** Append a new node to the chain. Signs it with the provided private key. */
  append(opts: {
    transformId: string;
    agentDid: string;
    payload: unknown;
    taintStatus?: TaintStatus;
    privKey: Uint8Array;
    nowMs?: number;
  }): AppendResult {
    const prevHash =
      this.nodes.length === 0 ? "genesis" : nodeHash(this.nodes[this.nodes.length - 1]);

    const timestamp = new Date(opts.nowMs ?? Date.now()).toISOString();
    const payloadHash = sha256Hex(canonicalize(opts.payload));
    const pubKeyB64u = b64uEncode(ed.getPublicKey(opts.privKey));

    // Propagate taint: if chain is already tainted, this node is tainted too
    let declaredTaint: TaintStatus = opts.taintStatus ?? "clean";
    if (this.chainTaint === "tainted") declaredTaint = "tainted";

    const partial: Omit<CustodyNode, "signature"> = {
      node_id: randomUUID(),
      transform_id: opts.transformId,
      agent_did: opts.agentDid,
      timestamp,
      payload_hash: payloadHash,
      prev_hash: prevHash,
      taint_status: declaredTaint,
      key_id: pubKeyB64u,
    };

    const bodyBytes = new TextEncoder().encode(canonicalize(partial));
    const sig = ed.sign(bodyBytes, opts.privKey);
    const node: CustodyNode = { ...partial, signature: b64uEncode(sig) };

    this.nodes.push(node);

    // Update chain taint
    if (declaredTaint === "tainted") this.chainTaint = "tainted";
    if (declaredTaint === "unknown" && this.chainTaint === "clean") this.chainTaint = "unknown";

    return { node, chainTaintStatus: this.chainTaint };
  }

  /** Return a copy of all nodes. */
  getNodes(): CustodyNode[] {
    return this.nodes.slice();
  }

  /** Current chain-level taint status. */
  getTaintStatus(): TaintStatus {
    return this.chainTaint;
  }

  /** Compute the Merkle root over the chain's node hashes. */
  getMerkleRoot(): string {
    return merkleRoot(this.nodes.map(nodeHash));
  }

  /** Build a Merkle inclusion proof for the node at the given index. */
  getMerkleProof(index: number): MerkleProof {
    const leaves = this.nodes.map(nodeHash);
    const proof = buildMerkleProof(leaves, index);
    return { ...proof, nodeId: this.nodes[index].node_id };
  }

  /** Verify the entire chain: hash linkage + signatures + taint propagation. */
  verifyChain(trustedKeys?: Record<string, string>): ChainVerifyResult {
    const taintStatuses: TaintStatus[] = [];
    let propagatedTaint: TaintStatus = "clean";

    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];

      // 1. Hash linkage
      const expectedPrev = i === 0 ? "genesis" : nodeHash(this.nodes[i - 1]);
      if (node.prev_hash !== expectedPrev) {
        return {
          valid: false,
          firstInvalidIndex: i,
          reason: `Node ${i} prev_hash mismatch`,
          taintStatuses,
          chainTaintStatus: propagatedTaint,
        };
      }

      // 2. Signature
      const pubKeyB64u =
        trustedKeys && trustedKeys[node.agent_did] ? trustedKeys[node.agent_did] : node.key_id;
      const bodyBytes = signingBody(node);
      let sigOk = false;
      try {
        const pubBytes = b64uDecode(pubKeyB64u);
        const sigBytes = b64uDecode(node.signature);
        sigOk = ed.verify(sigBytes, bodyBytes, pubBytes);
      } catch {
        sigOk = false;
      }
      if (!sigOk) {
        return {
          valid: false,
          firstInvalidIndex: i,
          reason: `Node ${i} signature invalid`,
          taintStatuses,
          chainTaintStatus: propagatedTaint,
        };
      }

      // 3. Taint propagation
      const effectiveTaint: TaintStatus =
        propagatedTaint === "tainted" ? "tainted" : node.taint_status;
      taintStatuses.push(effectiveTaint);
      if (effectiveTaint === "tainted") propagatedTaint = "tainted";
      if (effectiveTaint === "unknown" && propagatedTaint === "clean") propagatedTaint = "unknown";
    }

    return { valid: true, taintStatuses, chainTaintStatus: propagatedTaint };
  }
}
