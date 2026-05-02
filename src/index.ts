/**
 * @hivecivilization/hive-custody
 *
 * Custody-chain tainting and Merkle proof for agent data lineage.
 * Reference implementation of HiveAttest Claim C16, USPTO 64/055,601.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

export {
  CustodyChain,
  nodeHash,
  merkleRoot,
  buildMerkleProof,
  verifyMerkleProof,
} from "./custody.js";

export type {
  CustodyNode,
  TaintStatus,
  AppendResult,
  MerkleProof,
  ChainVerifyResult,
} from "./types.js";
