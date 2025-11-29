// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FractalProverRegistry
 * @notice Manages permissionless prover registration for the fractal network
 * @dev Implements trustless prover coordination without central authority
 */
contract FractalProverRegistry {
    struct Prover {
        address proverAddress;
        bytes32 nodeId;
        string networkAddress; // P2P address
        uint256 registrationTime;
        uint256 totalProofs;
        uint256 totalRewards;
        uint8 fractalLevel;
        uint16 clusterPosition;
        bool active;
    }
    
    struct ProofSubmission {
        bytes32 taskId;
        address prover;
        bytes proofData;
        uint256 timestamp;
        bool verified;
    }
    
    // Prover registry
    mapping(address => Prover) public provers;
    mapping(bytes32 => address) public nodeIdToAddress;
    address[] public proverList;
    
    // Proof tracking
    mapping(bytes32 => ProofSubmission) public proofs;
    mapping(address => bytes32[]) public proverProofs;
    
    // Reputation tracking
    mapping(address => uint256) public reputation;
    
    // Events
    event ProverRegistered(address indexed prover, bytes32 nodeId, uint8 fractalLevel);
    event ProofSubmitted(bytes32 indexed taskId, address indexed prover);
    event ProofVerified(bytes32 indexed taskId, address indexed prover);
    event ReputationUpdated(address indexed prover, uint256 newReputation);
    
    /**
     * @notice Register as a prover in the fractal network
     * @param nodeId Unique node identifier
     * @param networkAddress P2P network address
     * @param fractalLevel Computed fractal level (0-7)
     * @param clusterPosition Position within fractal cluster
     */
    function registerProver(
        bytes32 nodeId,
        string calldata networkAddress,
        uint8 fractalLevel,
        uint16 clusterPosition
    ) external {
        require(provers[msg.sender].proverAddress == address(0), "Already registered");
        require(fractalLevel <= 7, "Invalid fractal level");
        require(nodeIdToAddress[nodeId] == address(0), "Node ID already used");
        
        Prover memory newProver = Prover({
            proverAddress: msg.sender,
            nodeId: nodeId,
            networkAddress: networkAddress,
            registrationTime: block.timestamp,
            totalProofs: 0,
            totalRewards: 0,
            fractalLevel: fractalLevel,
            clusterPosition: clusterPosition,
            active: true
        });
        
        provers[msg.sender] = newProver;
        nodeIdToAddress[nodeId] = msg.sender;
        proverList.push(msg.sender);
        
        emit ProverRegistered(msg.sender, nodeId, fractalLevel);
    }
    
    /**
     * @notice Submit a proof for verification
     * @param taskId Unique task identifier
     * @param proofData ZK proof bytes
     */
    function submitProof(bytes32 taskId, bytes calldata proofData) external {
        require(provers[msg.sender].active, "Prover not active");
        require(proofs[taskId].prover == address(0), "Proof already submitted");
        
        ProofSubmission memory submission = ProofSubmission({
            taskId: taskId,
            prover: msg.sender,
            proofData: proofData,
            timestamp: block.timestamp,
            verified: false
        });
        
        proofs[taskId] = submission;
        proverProofs[msg.sender].push(taskId);
        provers[msg.sender].totalProofs++;
        
        emit ProofSubmitted(taskId, msg.sender);
    }
    
    /**
     * @notice Verify a submitted proof (called by verifier contract)
     * @param taskId Task identifier
     */
    function verifyProof(bytes32 taskId) external {
        require(proofs[taskId].prover != address(0), "Proof not found");
        require(!proofs[taskId].verified, "Already verified");
        
        // In production: actual verification logic or oracle check
        proofs[taskId].verified = true;
        
        address prover = proofs[taskId].prover;
        reputation[prover] += 10; // Increase reputation
        
        emit ProofVerified(taskId, prover);
        emit ReputationUpdated(prover, reputation[prover]);
    }
    
    /**
     * @notice Get prover information
     */
    function getProver(address proverAddress) external view returns (Prover memory) {
        return provers[proverAddress];
    }
    
    /**
     * @notice Get all proofs by a prover
     */
    function getProverProofs(address proverAddress) external view returns (bytes32[] memory) {
        return proverProofs[proverAddress];
    }
    
    /**
     * @notice Get total number of registered provers
     */
    function getTotalProvers() external view returns (uint256) {
        return proverList.length;
    }
    
    /**
     * @notice Get active provers count
     */
    function getActiveProversCount() external view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < proverList.length; i++) {
            if (provers[proverList[i]].active) {
                count++;
            }
        }
        return count;
    }
}
