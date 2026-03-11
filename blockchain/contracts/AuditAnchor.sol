// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AuditAnchor {

    struct Anchor {
        uint256 blockNumber;
        uint256 timestamp;
        bytes32 chainTipHash;
        uint256 recordCount;
        string  systemId;
    }

    Anchor[] public anchors;
    address  public owner;

    event AnchorSubmitted(
        uint256 indexed anchorIndex,
        bytes32 chainTipHash,
        uint256 recordCount,
        uint256 timestamp
    );

    constructor() {
        owner = msg.sender;
    }

    function submitAnchor(
        bytes32 chainTipHash,
        uint256 recordCount,
        string  calldata systemId
    ) external returns (uint256 anchorIndex) {
        anchors.push(Anchor({
            blockNumber:  block.number,
            timestamp:    block.timestamp,
            chainTipHash: chainTipHash,
            recordCount:  recordCount,
            systemId:     systemId
        }));
        anchorIndex = anchors.length - 1;
        emit AnchorSubmitted(anchorIndex, chainTipHash, recordCount, block.timestamp);
    }

    function getAnchor(uint256 index) external view returns (Anchor memory) {
        require(index < anchors.length, "Anchor not found");
        return anchors[index];
    }

    function getLatestAnchor() external view returns (Anchor memory, uint256 index) {
        require(anchors.length > 0, "No anchors yet");
        index = anchors.length - 1;
        return (anchors[index], index);
    }

    function getAnchorCount() external view returns (uint256) {
        return anchors.length;
    }
}
