// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title FractalTokenDistribution
 * @notice Fair launch and vesting for FRAC token
 * @dev Handles initial distribution with vesting schedules
 * 
 * Distribution:
 * - 60% Provers (600M) - Minted as rewards over time
 * - 20% Liquidity (200M) - Immediate for DEX pools
 * - 15% Team (150M) - 4 year vest, 1 year cliff
 * - 5% Treasury (50M) - 6 month cliff, 2 year vest
 */
contract FractalTokenDistribution is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    IERC20 public immutable fracToken;
    
    // Distribution amounts
    uint256 public constant TOTAL_SUPPLY = 1_000_000_000 * 10**18;
    uint256 public constant PROVER_ALLOCATION = 600_000_000 * 10**18; // 60%
    uint256 public constant LIQUIDITY_ALLOCATION = 200_000_000 * 10**18; // 20%
    uint256 public constant TEAM_ALLOCATION = 150_000_000 * 10**18; // 15%
    uint256 public constant TREASURY_ALLOCATION = 50_000_000 * 10**18; // 5%
    
    // Vesting schedules
    struct VestingSchedule {
        uint256 totalAmount;
        uint256 releasedAmount;
        uint256 startTime;
        uint256 cliffDuration;
        uint256 vestingDuration;
    }
    
    mapping(address => VestingSchedule) public vestingSchedules;
    
    // Launch configuration
    uint256 public launchTime;
    bool public launched;
    
    // Addresses
    address public liquidityPool;
    address public rewardPool;
    address public treasury;
    
    // Events
    event Launched(uint256 timestamp);
    event VestingScheduleCreated(address indexed beneficiary, uint256 amount, uint256 cliff, uint256 duration);
    event TokensReleased(address indexed beneficiary, uint256 amount);
    event LiquidityAllocated(address indexed pool, uint256 amount);
    
    constructor(address _fracToken) {
        fracToken = IERC20(_fracToken);
    }
    
    /**
     * @notice Launch token distribution
     * @dev Can only be called once
     */
    function launch(
        address _liquidityPool,
        address _rewardPool,
        address _treasury,
        address[] calldata teamMembers,
        uint256[] calldata teamAmounts
    ) external onlyOwner {
        require(!launched, "Already launched");
        require(teamMembers.length == teamAmounts.length, "Length mismatch");
        
        liquidityPool = _liquidityPool;
        rewardPool = _rewardPool;
        treasury = _treasury;
        launchTime = block.timestamp;
        launched = true;
        
        // Distribute liquidity (immediate)
        fracToken.safeTransfer(liquidityPool, LIQUIDITY_ALLOCATION);
        emit LiquidityAllocated(liquidityPool, LIQUIDITY_ALLOCATION);
        
        // Setup team vesting (4 year vest, 1 year cliff)
        uint256 totalTeamAllocation = 0;
        for (uint256 i = 0; i < teamMembers.length; i++) {
            require(teamAmounts[i] > 0, "Invalid amount");
            totalTeamAllocation += teamAmounts[i];
            
            _createVestingSchedule(
                teamMembers[i],
                teamAmounts[i],
                365 days, // 1 year cliff
                4 * 365 days // 4 year vest
            );
        }
        require(totalTeamAllocation <= TEAM_ALLOCATION, "Exceeds team allocation");
        
        // Setup treasury vesting (2 year vest, 6 month cliff)
        _createVestingSchedule(
            treasury,
            TREASURY_ALLOCATION,
            180 days, // 6 month cliff
            2 * 365 days // 2 year vest
        );
        
        emit Launched(launchTime);
    }
    
    /**
     * @notice Create vesting schedule for address
     */
    function _createVestingSchedule(
        address beneficiary,
        uint256 amount,
        uint256 cliffDuration,
        uint256 vestingDuration
    ) internal {
        require(beneficiary != address(0), "Invalid beneficiary");
        require(vestingSchedules[beneficiary].totalAmount == 0, "Schedule exists");
        
        vestingSchedules[beneficiary] = VestingSchedule({
            totalAmount: amount,
            releasedAmount: 0,
            startTime: launchTime,
            cliffDuration: cliffDuration,
            vestingDuration: vestingDuration
        });
        
        emit VestingScheduleCreated(beneficiary, amount, cliffDuration, vestingDuration);
    }
    
    /**
     * @notice Calculate vested amount for address
     */
    function vestedAmount(address beneficiary) public view returns (uint256) {
        VestingSchedule memory schedule = vestingSchedules[beneficiary];
        
        if (schedule.totalAmount == 0 || block.timestamp < schedule.startTime + schedule.cliffDuration) {
            return 0;
        }
        
        if (block.timestamp >= schedule.startTime + schedule.vestingDuration) {
            return schedule.totalAmount;
        }
        
        uint256 timeVested = block.timestamp - schedule.startTime;
        return (schedule.totalAmount * timeVested) / schedule.vestingDuration;
    }
    
    /**
     * @notice Calculate releasable amount for address
     */
    function releasableAmount(address beneficiary) public view returns (uint256) {
        uint256 vested = vestedAmount(beneficiary);
        return vested - vestingSchedules[beneficiary].releasedAmount;
    }
    
    /**
     * @notice Release vested tokens
     */
    function release() external nonReentrant {
        uint256 amount = releasableAmount(msg.sender);
        require(amount > 0, "No tokens to release");
        
        vestingSchedules[msg.sender].releasedAmount += amount;
        fracToken.safeTransfer(msg.sender, amount);
        
        emit TokensReleased(msg.sender, amount);
    }
    
    /**
     * @notice Get vesting info for address
     */
    function getVestingInfo(address beneficiary) external view returns (
        uint256 total,
        uint256 released,
        uint256 vested,
        uint256 releasable,
        uint256 nextVestDate
    ) {
        VestingSchedule memory schedule = vestingSchedules[beneficiary];
        total = schedule.totalAmount;
        released = schedule.releasedAmount;
        vested = vestedAmount(beneficiary);
        releasable = releasableAmount(beneficiary);
        
        if (block.timestamp < schedule.startTime + schedule.cliffDuration) {
            nextVestDate = schedule.startTime + schedule.cliffDuration;
        } else if (block.timestamp < schedule.startTime + schedule.vestingDuration) {
            nextVestDate = block.timestamp + 1 days; // Daily vesting
        } else {
            nextVestDate = 0; // Fully vested
        }
    }
    
    /**
     * @notice Emergency withdraw (only before launch)
     */
    function emergencyWithdraw() external onlyOwner {
        require(!launched, "Already launched");
        uint256 balance = fracToken.balanceOf(address(this));
        fracToken.safeTransfer(owner(), balance);
    }
}
