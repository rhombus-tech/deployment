// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title FractalStaking
 * @notice Stake FRAC tokens to participate in the proving network
 * @dev Implements tiered staking with APY rewards and slashing for misbehavior
 */
contract FractalStaking is ReentrancyGuard, AccessControl {
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    
    IERC20 public fracToken;
    
    // Staking tiers
    uint256 public constant BRONZE_TIER = 1_000 * 10**18;      // 1,000 FRAC
    uint256 public constant SILVER_TIER = 10_000 * 10**18;     // 10,000 FRAC
    uint256 public constant GOLD_TIER = 100_000 * 10**18;      // 100,000 FRAC
    uint256 public constant PLATINUM_TIER = 1_000_000 * 10**18; // 1,000,000 FRAC
    
    // APY rates (basis points: 500 = 5%)
    uint256 public constant BRONZE_APY = 500;    // 5%
    uint256 public constant SILVER_APY = 600;    // 6%
    uint256 public constant GOLD_APY = 700;      // 7%
    uint256 public constant PLATINUM_APY = 800;  // 8%
    
    // Earnings multipliers (100 = 1.0x)
    uint256 public constant BRONZE_MULTIPLIER = 100;   // 1.0x
    uint256 public constant SILVER_MULTIPLIER = 150;   // 1.5x
    uint256 public constant GOLD_MULTIPLIER = 200;     // 2.0x
    uint256 public constant PLATINUM_MULTIPLIER = 250; // 2.5x
    
    // Lock periods
    uint256 public constant FLEXIBLE_LOCK = 0;
    uint256 public constant LOCK_30_DAYS = 30 days;
    uint256 public constant LOCK_90_DAYS = 90 days;
    uint256 public constant LOCK_1_YEAR = 365 days;
    
    // Lock bonuses (basis points added to APY)
    uint256 public constant BONUS_30_DAYS = 50;   // +0.5%
    uint256 public constant BONUS_90_DAYS = 100;  // +1%
    uint256 public constant BONUS_1_YEAR = 200;   // +2%
    
    // Unstake penalty for flexible staking
    uint256 public constant FLEXIBLE_PENALTY = 300; // 3%
    
    struct Stake {
        uint256 amount;
        uint256 timestamp;
        uint256 lockPeriod;
        uint256 lastClaimTime;
        uint256 accumulatedRewards;
        bool active;
    }
    
    // Staker data
    mapping(address => Stake) public stakes;
    mapping(address => uint256) public voteWeight;
    
    // Global stats
    uint256 public totalStaked;
    uint256 public totalStakers;
    uint256 public totalRewardsDistributed;
    
    // Events
    event Staked(address indexed staker, uint256 amount, uint256 lockPeriod);
    event Unstaked(address indexed staker, uint256 amount, uint256 penalty);
    event RewardsClaimed(address indexed staker, uint256 amount);
    event Slashed(address indexed staker, uint256 amount, string reason);
    event VoteWeightUpdated(address indexed staker, uint256 newWeight);
    
    constructor(address _fracToken) {
        require(_fracToken != address(0), "Invalid token address");
        fracToken = IERC20(_fracToken);
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SLASHER_ROLE, msg.sender);
    }
    
    /**
     * @notice Stake FRAC tokens
     * @param amount Amount to stake
     * @param lockPeriod Lock period (0, 30 days, 90 days, or 1 year)
     */
    function stake(uint256 amount, uint256 lockPeriod) external nonReentrant {
        require(amount >= BRONZE_TIER, "Minimum stake is 1,000 FRAC");
        require(
            lockPeriod == FLEXIBLE_LOCK ||
            lockPeriod == LOCK_30_DAYS ||
            lockPeriod == LOCK_90_DAYS ||
            lockPeriod == LOCK_1_YEAR,
            "Invalid lock period"
        );
        
        // Transfer tokens from user
        require(
            fracToken.transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );
        
        Stake storage userStake = stakes[msg.sender];
        
        // If already staking, claim existing rewards first
        if (userStake.active) {
            _claimRewards(msg.sender);
        } else {
            totalStakers++;
        }
        
        // Update stake
        userStake.amount += amount;
        userStake.timestamp = block.timestamp;
        userStake.lockPeriod = lockPeriod;
        userStake.lastClaimTime = block.timestamp;
        userStake.active = true;
        
        totalStaked += amount;
        
        // Update vote weight
        _updateVoteWeight(msg.sender);
        
        emit Staked(msg.sender, amount, lockPeriod);
    }
    
    /**
     * @notice Unstake FRAC tokens
     * @param amount Amount to unstake
     */
    function unstake(uint256 amount) external nonReentrant {
        Stake storage userStake = stakes[msg.sender];
        require(userStake.active, "No active stake");
        require(amount <= userStake.amount, "Insufficient stake");
        
        // Check if lock period has passed
        uint256 lockEnd = userStake.timestamp + userStake.lockPeriod;
        bool isLocked = block.timestamp < lockEnd;
        
        // Claim pending rewards
        _claimRewards(msg.sender);
        
        uint256 penalty = 0;
        uint256 amountToReturn = amount;
        
        // Apply penalty if unstaking during flexible period without lock
        if (userStake.lockPeriod == FLEXIBLE_LOCK) {
            penalty = (amount * FLEXIBLE_PENALTY) / 10000;
            amountToReturn = amount - penalty;
        } else if (isLocked) {
            // Cannot unstake during lock period
            revert("Stake is still locked");
        }
        
        // Update stake
        userStake.amount -= amount;
        totalStaked -= amount;
        
        if (userStake.amount == 0) {
            userStake.active = false;
            totalStakers--;
        }
        
        // Update vote weight
        _updateVoteWeight(msg.sender);
        
        // Transfer tokens back (minus penalty)
        require(
            fracToken.transfer(msg.sender, amountToReturn),
            "Transfer failed"
        );
        
        // If there was a penalty, send it to treasury (msg.sender of contract)
        if (penalty > 0) {
            require(
                fracToken.transfer(getRoleMember(DEFAULT_ADMIN_ROLE, 0), penalty),
                "Penalty transfer failed"
            );
        }
        
        emit Unstaked(msg.sender, amount, penalty);
    }
    
    /**
     * @notice Claim accumulated staking rewards
     */
    function claimRewards() external nonReentrant {
        _claimRewards(msg.sender);
    }
    
    /**
     * @notice Internal function to claim rewards
     */
    function _claimRewards(address staker) internal {
        Stake storage userStake = stakes[staker];
        require(userStake.active, "No active stake");
        
        uint256 rewards = calculateRewards(staker);
        
        if (rewards > 0) {
            userStake.lastClaimTime = block.timestamp;
            userStake.accumulatedRewards += rewards;
            totalRewardsDistributed += rewards;
            
            // Mint rewards (in production, this would call FractalToken.mintProofReward)
            require(
                fracToken.transfer(staker, rewards),
                "Reward transfer failed"
            );
            
            emit RewardsClaimed(staker, rewards);
        }
    }
    
    /**
     * @notice Calculate pending rewards for a staker
     */
    function calculateRewards(address staker) public view returns (uint256) {
        Stake storage userStake = stakes[staker];
        if (!userStake.active) return 0;
        
        uint256 timeStaked = block.timestamp - userStake.lastClaimTime;
        uint256 apy = getAPY(staker);
        
        // Calculate annual reward and pro-rate by time
        uint256 annualReward = (userStake.amount * apy) / 10000;
        uint256 reward = (annualReward * timeStaked) / 365 days;
        
        return reward;
    }
    
    /**
     * @notice Get APY for a staker (including tier and lock bonuses)
     */
    function getAPY(address staker) public view returns (uint256) {
        Stake storage userStake = stakes[staker];
        if (!userStake.active) return 0;
        
        uint256 baseAPY;
        
        // Determine tier APY
        if (userStake.amount >= PLATINUM_TIER) {
            baseAPY = PLATINUM_APY;
        } else if (userStake.amount >= GOLD_TIER) {
            baseAPY = GOLD_APY;
        } else if (userStake.amount >= SILVER_TIER) {
            baseAPY = SILVER_APY;
        } else {
            baseAPY = BRONZE_APY;
        }
        
        // Add lock bonus
        if (userStake.lockPeriod == LOCK_1_YEAR) {
            baseAPY += BONUS_1_YEAR;
        } else if (userStake.lockPeriod == LOCK_90_DAYS) {
            baseAPY += BONUS_90_DAYS;
        } else if (userStake.lockPeriod == LOCK_30_DAYS) {
            baseAPY += BONUS_30_DAYS;
        }
        
        return baseAPY;
    }
    
    /**
     * @notice Get earnings multiplier based on stake tier
     */
    function getEarningsMultiplier(address staker) public view returns (uint256) {
        Stake storage userStake = stakes[staker];
        if (!userStake.active) return 100;
        
        if (userStake.amount >= PLATINUM_TIER) {
            return PLATINUM_MULTIPLIER;
        } else if (userStake.amount >= GOLD_TIER) {
            return GOLD_MULTIPLIER;
        } else if (userStake.amount >= SILVER_TIER) {
            return SILVER_MULTIPLIER;
        } else {
            return BRONZE_MULTIPLIER;
        }
    }
    
    /**
     * @notice Get staking tier for an address
     */
    function getTier(address staker) public view returns (string memory) {
        Stake storage userStake = stakes[staker];
        if (!userStake.active) return "None";
        
        if (userStake.amount >= PLATINUM_TIER) {
            return "Platinum";
        } else if (userStake.amount >= GOLD_TIER) {
            return "Gold";
        } else if (userStake.amount >= SILVER_TIER) {
            return "Silver";
        } else {
            return "Bronze";
        }
    }
    
    /**
     * @notice Slash a misbehaving staker
     * @param staker Address to slash
     * @param percentage Percentage to slash (basis points)
     * @param reason Reason for slashing
     */
    function slash(
        address staker,
        uint256 percentage,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) {
        require(percentage <= 5000, "Max slash is 50%");
        
        Stake storage userStake = stakes[staker];
        require(userStake.active, "No active stake");
        
        uint256 slashAmount = (userStake.amount * percentage) / 10000;
        
        userStake.amount -= slashAmount;
        totalStaked -= slashAmount;
        
        if (userStake.amount == 0) {
            userStake.active = false;
            totalStakers--;
        }
        
        // Update vote weight
        _updateVoteWeight(staker);
        
        // Send 50% of slashed amount to treasury, burn 50%
        uint256 toTreasury = slashAmount / 2;
        uint256 toBurn = slashAmount - toTreasury;
        
        require(
            fracToken.transfer(getRoleMember(DEFAULT_ADMIN_ROLE, 0), toTreasury),
            "Treasury transfer failed"
        );
        
        // Burn would require FractalToken.burn() - simplified here
        
        emit Slashed(staker, slashAmount, reason);
    }
    
    /**
     * @notice Update vote weight based on stake amount and multiplier
     */
    function _updateVoteWeight(address staker) internal {
        Stake storage userStake = stakes[staker];
        
        if (!userStake.active) {
            voteWeight[staker] = 0;
        } else {
            // Vote weight = stake amount * tier multiplier
            uint256 multiplier = getEarningsMultiplier(staker);
            voteWeight[staker] = (userStake.amount * multiplier) / 100;
        }
        
        emit VoteWeightUpdated(staker, voteWeight[staker]);
    }
    
    /**
     * @notice Get complete stake info for an address
     */
    function getStakeInfo(address staker) external view returns (
        uint256 amount,
        uint256 lockPeriod,
        uint256 lockEnds,
        uint256 pendingRewards,
        uint256 apy,
        uint256 multiplier,
        uint256 voteWt,
        string memory tier,
        bool active
    ) {
        Stake storage userStake = stakes[staker];
        
        return (
            userStake.amount,
            userStake.lockPeriod,
            userStake.timestamp + userStake.lockPeriod,
            calculateRewards(staker),
            getAPY(staker),
            getEarningsMultiplier(staker),
            voteWeight[staker],
            getTier(staker),
            userStake.active
        );
    }
    
    /**
     * @notice Get global staking statistics
     */
    function getGlobalStats() external view returns (
        uint256 _totalStaked,
        uint256 _totalStakers,
        uint256 _totalRewards,
        uint256 avgStakeSize
    ) {
        uint256 avg = totalStakers > 0 ? totalStaked / totalStakers : 0;
        
        return (
            totalStaked,
            totalStakers,
            totalRewardsDistributed,
            avg
        );
    }
}
