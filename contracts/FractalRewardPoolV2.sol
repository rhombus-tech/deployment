// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./FractalToken.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title FractalRewardPoolV2
 * @notice Manages FRAC token rewards for fractal network provers
 * @dev Mints new tokens for each proof, with bonuses for quality and speed
 * 
 * Economics:
 * - Base reward: 10 FRAC per proof
 * - Quality bonus: up to 15 FRAC (based on proof quality 0-100)
 * - Speed bonus: up to 5 FRAC (sub-second proofs get max)
 * - Maximum per proof: 30 FRAC
 */
contract FractalRewardPoolV2 is AccessControl, ReentrancyGuard {
    bytes32 public constant REGISTRY_ROLE = keccak256("REGISTRY_ROLE");
    
    FractalToken public immutable fracToken;
    
    // Reward configuration
    uint256 public baseRewardPerProof = 10 * 10**18; // 10 FRAC
    uint256 public maxQualityBonus = 15 * 10**18; // 15 FRAC
    uint256 public maxSpeedBonus = 5 * 10**18; // 5 FRAC
    
    // Reward tracking
    struct RewardClaim {
        bytes32 taskId;
        address prover;
        uint256 baseReward;
        uint256 qualityBonus;
        uint256 speedBonus;
        uint256 totalReward;
        uint256 timestamp;
        bool paid;
    }
    
    mapping(bytes32 => RewardClaim) public claims;
    mapping(address => uint256) public proverTotalEarned;
    mapping(address => uint256) public proverProofCount;
    
    // Statistics
    uint256 public totalRewardsPaid;
    uint256 public totalProofsRewarded;
    
    // Events
    event RewardClaimed(
        bytes32 indexed taskId,
        address indexed prover,
        uint256 baseReward,
        uint256 qualityBonus,
        uint256 speedBonus,
        uint256 totalReward
    );
    event RewardPaid(address indexed prover, uint256 amount);
    event ConfigurationUpdated(string parameter, uint256 newValue);
    
    constructor(address _fracToken) {
        fracToken = FractalToken(_fracToken);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ROLE, msg.sender);
    }
    
    /**
     * @notice Claim reward for a completed proof
     * @param taskId Task identifier
     * @param proofQuality Quality score (0-100)
     * @param provingTimeMs Proving time in milliseconds
     */
    function claimReward(
        bytes32 taskId,
        uint8 proofQuality,
        uint256 provingTimeMs
    ) external nonReentrant {
        require(claims[taskId].prover == address(0), "Already claimed");
        require(proofQuality <= 100, "Invalid quality score");
        
        // Calculate rewards
        uint256 baseReward = baseRewardPerProof;
        
        // Quality bonus (0-100 score scales to 0-15 FRAC)
        uint256 qualityBonus = (maxQualityBonus * proofQuality) / 100;
        
        // Speed bonus
        uint256 speedBonus = 0;
        if (provingTimeMs < 1000) { // Sub-second
            speedBonus = maxSpeedBonus;
        } else if (provingTimeMs < 5000) { // Sub-5s
            speedBonus = maxSpeedBonus / 2;
        } else if (provingTimeMs < 10000) { // Sub-10s
            speedBonus = maxSpeedBonus / 4;
        }
        
        uint256 totalReward = baseReward + qualityBonus + speedBonus;
        
        // Store claim
        claims[taskId] = RewardClaim({
            taskId: taskId,
            prover: msg.sender,
            baseReward: baseReward,
            qualityBonus: qualityBonus,
            speedBonus: speedBonus,
            totalReward: totalReward,
            timestamp: block.timestamp,
            paid: false
        });
        
        // Mint tokens directly to prover
        fracToken.mintProofReward(msg.sender, totalReward);
        
        // Update statistics
        proverTotalEarned[msg.sender] += totalReward;
        proverProofCount[msg.sender]++;
        totalRewardsPaid += totalReward;
        totalProofsRewarded++;
        
        // Mark as paid
        claims[taskId].paid = true;
        
        emit RewardClaimed(
            taskId,
            msg.sender,
            baseReward,
            qualityBonus,
            speedBonus,
            totalReward
        );
        emit RewardPaid(msg.sender, totalReward);
    }
    
    /**
     * @notice Burn tokens when proof is verified (deflationary)
     * @dev Called by registry after proof verification
     */
    function burnForProofVerification(bytes32 taskId) external onlyRole(REGISTRY_ROLE) {
        RewardClaim memory claim = claims[taskId];
        require(claim.paid, "Claim not paid");
        
        fracToken.burnForProofVerification(taskId, claim.totalReward);
    }
    
    /**
     * @notice Calculate estimated reward for parameters
     */
    function estimateReward(uint8 proofQuality, uint256 provingTimeMs) 
        external 
        view 
        returns (uint256 estimated) 
    {
        require(proofQuality <= 100, "Invalid quality");
        
        uint256 base = baseRewardPerProof;
        uint256 quality = (maxQualityBonus * proofQuality) / 100;
        
        uint256 speed = 0;
        if (provingTimeMs < 1000) {
            speed = maxSpeedBonus;
        } else if (provingTimeMs < 5000) {
            speed = maxSpeedBonus / 2;
        } else if (provingTimeMs < 10000) {
            speed = maxSpeedBonus / 4;
        }
        
        return base + quality + speed;
    }
    
    /**
     * @notice Get prover statistics
     */
    function getProverStats(address prover) external view returns (
        uint256 totalEarned,
        uint256 proofCount,
        uint256 avgRewardPerProof
    ) {
        totalEarned = proverTotalEarned[prover];
        proofCount = proverProofCount[prover];
        avgRewardPerProof = proofCount > 0 ? totalEarned / proofCount : 0;
    }
    
    /**
     * @notice Get global statistics
     */
    function getGlobalStats() external view returns (
        uint256 totalPaid,
        uint256 totalProofs,
        uint256 avgRewardPerProof,
        uint256 currentSupply
    ) {
        totalPaid = totalRewardsPaid;
        totalProofs = totalProofsRewarded;
        avgRewardPerProof = totalProofs > 0 ? totalPaid / totalProofs : 0;
        currentSupply = fracToken.totalSupply();
    }
    
    /**
     * @notice Update reward configuration
     */
    function setBaseReward(uint256 newBaseReward) external onlyRole(DEFAULT_ADMIN_ROLE) {
        baseRewardPerProof = newBaseReward;
        emit ConfigurationUpdated("baseReward", newBaseReward);
    }
    
    function setMaxQualityBonus(uint256 newBonus) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxQualityBonus = newBonus;
        emit ConfigurationUpdated("maxQualityBonus", newBonus);
    }
    
    function setMaxSpeedBonus(uint256 newBonus) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxSpeedBonus = newBonus;
        emit ConfigurationUpdated("maxSpeedBonus", newBonus);
    }
}
