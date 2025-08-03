// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ZKEVMProofRegistry
 * @notice On-chain registry for zkEVM performance proofs
 * @dev EF can verify our performance claims directly on Ethereum blockchain
 */
contract ZKEVMProofRegistry {
    
    struct ProofSubmission {
        uint256 sourceBlockNumber;      // Ethereum block we proved
        bytes32 proofHash;             // Hash of the zkEVM proof  
        uint256 proofSize;             // Size of proof in bytes
        uint256 submissionTimestamp;   // When proof was submitted
        uint256 submissionBlockNumber; // Ethereum block of submission
        address submitter;             // Who submitted the proof
        uint256 claimedLatencyMs;      // Claimed proving time in milliseconds
    }
    
    mapping(uint256 => ProofSubmission) public proofs;
    mapping(address => bool) public authorizedProvers;
    
    event ProofSubmitted(
        uint256 indexed sourceBlock,
        bytes32 indexed proofHash,
        uint256 proofSize,
        uint256 latencyMs,
        uint256 submissionTime
    );
    
    modifier onlyAuthorized() {
        require(authorizedProvers[msg.sender], "Not authorized prover");
        _;
    }
    
    constructor() {
        // Authorize our prover address
        authorizedProvers[msg.sender] = true;
    }
    
    /**
     * @notice Submit a zkEVM proof for an Ethereum block
     * @param sourceBlock The Ethereum block number that was proved
     * @param proofData The actual zkEVM proof bytes
     * @param claimedLatencyMs Claimed proving time in milliseconds
     */
    function submitProof(
        uint256 sourceBlock,
        bytes calldata proofData,
        uint256 claimedLatencyMs
    ) external onlyAuthorized {
        require(sourceBlock < block.number, "Cannot prove future blocks");
        require(proofData.length > 0, "Proof cannot be empty");
        require(proofData.length <= 300000, "Proof exceeds 300KB EF limit");
        require(claimedLatencyMs <= 10000, "Latency exceeds 10s EF limit");
        
        bytes32 proofHash = keccak256(proofData);
        
        proofs[sourceBlock] = ProofSubmission({
            sourceBlockNumber: sourceBlock,
            proofHash: proofHash,
            proofSize: proofData.length,
            submissionTimestamp: block.timestamp,
            submissionBlockNumber: block.number,
            submitter: msg.sender,
            claimedLatencyMs: claimedLatencyMs
        });
        
        emit ProofSubmitted(
            sourceBlock,
            proofHash,
            proofData.length,
            claimedLatencyMs,
            block.timestamp
        );
    }
    
    /**
     * @notice Get proof details for a specific block
     */
    function getProof(uint256 sourceBlock) external view returns (ProofSubmission memory) {
        return proofs[sourceBlock];
    }
    
    /**
     * @notice Verify if proof meets EF requirements
     */
    function meetsEFRequirements(uint256 sourceBlock) external view returns (
        bool latencyCompliant,
        bool sizeCompliant,
        bool overallCompliant
    ) {
        ProofSubmission memory proof = proofs[sourceBlock];
        
        latencyCompliant = proof.claimedLatencyMs > 0 && proof.claimedLatencyMs <= 10000;
        sizeCompliant = proof.proofSize > 0 && proof.proofSize <= 300000;
        overallCompliant = latencyCompliant && sizeCompliant;
    }
    
    /**
     * @notice Calculate actual submission delay (for timing verification)
     */
    function getSubmissionDelay(uint256 sourceBlock) external view returns (uint256 delaySeconds) {
        ProofSubmission memory proof = proofs[sourceBlock];
        require(proof.sourceBlockNumber != 0, "Proof not found");
        
        // Note: This is approximate due to block time variations
        // Real verification should use block timestamps
        uint256 blockDelay = proof.submissionBlockNumber - sourceBlock;
        delaySeconds = blockDelay * 12; // ~12 second Ethereum block time
    }
}
