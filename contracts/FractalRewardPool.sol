// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FractalRewardPool
 * @notice Manages rewards for fractal network provers
 * @dev Implements hybrid payment model: transaction fees + protocol inflation
 */
contract FractalRewardPool {
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
    
    // Reward configuration
    uint256 public baseRewardPerProof = 1000; // Base reward in wei
    uint256 public qualityBonusMultiplier = 150; // 1.5x for high quality
    uint256 public speedBonusMax = 500; // Max speed bonus
    uint256 public protocolInflationRate = 5; // 5% annual inflation
    
    // Treasury
    uint256 public treasuryBalance;
    uint256 public totalRewardsPaid;
    uint256 public totalProofsRewarded;
    
    // Reward tracking
    mapping(bytes32 => RewardClaim) public claims;
    mapping(address => uint256) public proverEarnings;
    mapping(address => uint256) public proverClaimCount;
    
    // Access control
    address public admin;
    address public proverRegistry;
    
    // Events
    event RewardClaimed(bytes32 indexed taskId, address indexed prover, uint256 amount);
    event RewardPaid(address indexed prover, uint256 amount);
    event TreasuryFunded(address indexed funder, uint256 amount);
    event ConfigurationUpdated(string parameter, uint256 newValue);
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }
    
    modifier onlyRegistry() {
        require(msg.sender == proverRegistry, "Only registry");
        _;
    }
    
    constructor(address _proverRegistry) {
        admin = msg.sender;
        proverRegistry = _proverRegistry;
    }
    
    /**
     * @notice Fund the treasury
     */
    function fundTreasury() external payable {
        treasuryBalance += msg.value;
        emit TreasuryFunded(msg.sender, msg.value);
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
    ) external {
        require(claims[taskId].prover == address(0), "Already claimed");
        require(proofQuality <= 100, "Invalid quality score");
        
        // Calculate rewards
        uint256 baseReward = baseRewardPerProof;
        
        // Quality bonus (up to 1.5x for perfect quality)
        uint256 qualityBonus = (baseReward * qualityBonusMultiplier * proofQuality) / 10000;
        
        // Speed bonus (faster = more bonus)
        uint256 speedBonus = 0;
        if (provingTimeMs < 1000) { // Sub-second
            speedBonus = speedBonusMax;
        } else if (provingTimeMs < 5000) { // Sub-5s
            speedBonus = speedBonusMax / 2;
        } else if (provingTimeMs < 10000) { // Sub-10s
            speedBonus = speedBonusMax / 4;
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
        
        proverEarnings[msg.sender] += totalReward;
        proverClaimCount[msg.sender]++;
        
        emit RewardClaimed(taskId, msg.sender, totalReward);
    }
    
    /**
     * @notice Pay out accumulated rewards to prover
     */
    function withdrawRewards() external {
        uint256 earnings = proverEarnings[msg.sender];
        require(earnings > 0, "No earnings to withdraw");
        require(treasuryBalance >= earnings, "Insufficient treasury");
        
        proverEarnings[msg.sender] = 0;
        treasuryBalance -= earnings;
        totalRewardsPaid += earnings;
        
        (bool success, ) = msg.sender.call{value: earnings}("");
        require(success, "Transfer failed");
        
        emit RewardPaid(msg.sender, earnings);
    }
    
    /**
     * @notice Get pending rewards for a prover
     */
    function getPendingRewards(address prover) external view returns (uint256) {
        return proverEarnings[prover];
    }
    
    /**
     * @notice Update base reward
     */
    function setBaseReward(uint256 newBaseReward) external onlyAdmin {
        baseRewardPerProof = newBaseReward;
        emit ConfigurationUpdated("baseReward", newBaseReward);
    }
    
    /**
     * @notice Update quality bonus multiplier
     */
    function setQualityBonusMultiplier(uint256 newMultiplier) external onlyAdmin {
        qualityBonusMultiplier = newMultiplier;
        emit ConfigurationUpdated("qualityBonusMultiplier", newMultiplier);
    }
    
    /**
     * @notice Get reward breakdown for a claim
     */
    function getRewardBreakdown(bytes32 taskId) external view returns (
        uint256 baseReward,
        uint256 qualityBonus,
        uint256 speedBonus,
        uint256 totalReward
    ) {
        RewardClaim memory claim = claims[taskId];
        return (
            claim.baseReward,
            claim.qualityBonus,
            claim.speedBonus,
            claim.totalReward
        );
    }
    
    /**
     * @notice Get treasury statistics
     */
    function getTreasuryStats() external view returns (
        uint256 balance,
        uint256 totalPaid,
        uint256 totalProofs
    ) {
        return (treasuryBalance, totalRewardsPaid, totalProofsRewarded);
    }
    
    /**
     * @notice Emergency withdraw (admin only)
     */
    function emergencyWithdraw() external onlyAdmin {
        uint256 balance = address(this).balance;
        (bool success, ) = admin.call{value: balance}("");
        require(success, "Transfer failed");
    }
    
    receive() external payable {
        fundTreasury();
    }
}
