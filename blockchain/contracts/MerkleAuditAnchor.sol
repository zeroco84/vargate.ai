// SPDX-License-Identifier: MIT
// MerkleAuditAnchor.sol — Vargate Merkle-based audit anchoring contract.
// Deployed to Ethereum Sepolia testnet for independently-verifiable
// tamper-evident anchoring of audit log Merkle roots (AG-2.2 / AG-2.3).
//
// Fix 4B (AG-2.2): Added prevMerkleRoot to form an on-chain hash chain
// of Merkle roots — providing consistency proof across anchor periods.
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

contract MerkleAuditAnchor is Ownable {

    struct Anchor {
        bytes32  merkleRoot;
        bytes32  prevMerkleRoot;   // Fix 4B: previous anchor's merkle root (or 0x0 for first)
        uint256  recordCount;
        uint256  fromRecord;
        uint256  toRecord;
        uint256  blockNumber;
        uint256  timestamp;
        string   systemId;
    }

    Anchor[] public anchors;

    event AnchorSubmitted(
        uint256 indexed anchorIndex,
        bytes32 merkleRoot,
        bytes32 prevMerkleRoot,
        uint256 recordCount
    );

    constructor() Ownable(msg.sender) {}

    /**
     * @notice Submit a new Merkle root anchor covering [fromRecord, toRecord].
     * @param merkleRoot      SHA-256 Merkle root of the audit log records.
     * @param prevMerkleRoot  Merkle root from the immediately preceding anchor (or 0x0 for first).
     * @param recordCount     Total number of records covered by this root.
     * @param fromRecord      First record id covered.
     * @param toRecord        Last record id covered.
     * @param systemId        Identifier for the gateway instance.
     * @return anchorIndex    The index of the newly stored anchor.
     */
    function submitAnchor(
        bytes32  merkleRoot,
        bytes32  prevMerkleRoot,
        uint256  recordCount,
        uint256  fromRecord,
        uint256  toRecord,
        string   calldata systemId
    ) external onlyOwner returns (uint256 anchorIndex) {
        anchors.push(Anchor({
            merkleRoot:     merkleRoot,
            prevMerkleRoot: prevMerkleRoot,
            recordCount:    recordCount,
            fromRecord:     fromRecord,
            toRecord:       toRecord,
            blockNumber:    block.number,
            timestamp:      block.timestamp,
            systemId:       systemId
        }));
        anchorIndex = anchors.length - 1;
        emit AnchorSubmitted(anchorIndex, merkleRoot, prevMerkleRoot, recordCount);
    }

    /**
     * @notice Get a specific anchor by index.
     */
    function getAnchor(uint256 index) external view returns (Anchor memory) {
        require(index < anchors.length, "Anchor not found");
        return anchors[index];
    }

    /**
     * @notice Get the most recent anchor and its index.
     */
    function getLatestAnchor() external view returns (Anchor memory, uint256 index) {
        require(anchors.length > 0, "No anchors yet");
        index = anchors.length - 1;
        return (anchors[index], index);
    }

    /**
     * @notice Return the total number of anchors submitted.
     */
    function getAnchorCount() external view returns (uint256) {
        return anchors.length;
    }
}
