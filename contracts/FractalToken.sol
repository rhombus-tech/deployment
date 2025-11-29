// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title FractalToken (FRAC)
 * @notice Decentralized proving network token - Earn by generating ZK proofs
 * @dev Deflationary token with controlled minting for network rewards
 * 
 * Tokenomics:
 * - Max Supply: 1 billion FRAC
 * - Distribution: 60% provers, 20% liquidity, 15% team (4yr vest), 5% treasury
 * - Inflation: 5% annually, decreasing by 0.5% per year
 * - Deflation: 0.1% burned per proof verification
 */
contract FractalToken is ERC20, ERC20Burnable, AccessControl, Pausable {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    
    // Tokenomics
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10**18; // 1 billion
    uint256 public constant INITIAL_SUPPLY = 100_000_000 * 10**18; // 100M (10% at launch)
    
    // Inflation control
    uint256 public annualInflationRate = 500; // 5.00% (basis points)
    uint256 public lastInflationAdjustment;
    uint256 public constant INFLATION_DECREASE = 50; // 0.50% per year
    uint256 public constant MIN_INFLATION = 100; // 1.00% minimum
    
    // Minting tracking
    uint256 public totalMinted;
    uint256 public proofRewardsMinted;
    
    // Proof verification burn
    uint256 public constant BURN_PER_PROOF = 10; // 0.001% basis points
    uint256 public totalBurnedForProofs;
    
    // Events
    event InflationRateAdjusted(uint256 oldRate, uint256 newRate);
    event ProofRewardMinted(address indexed prover, uint256 amount);
    event ProofVerificationBurn(bytes32 indexed taskId, uint256 amount);
    
    constructor() ERC20("Fractal Token", "FRAC") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        
        // Initial supply to deployer for distribution
        _mint(msg.sender, INITIAL_SUPPLY);
        totalMinted = INITIAL_SUPPLY;
        lastInflationAdjustment = block.timestamp;
    }
    
    /**
     * @notice Mint tokens as proof rewards
     * @dev Only callable by reward pool contract
     */
    function mintProofReward(address prover, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(totalMinted + amount <= MAX_SUPPLY, "Max supply exceeded");
        
        _mint(prover, amount);
        totalMinted += amount;
        proofRewardsMinted += amount;
        
        emit ProofRewardMinted(prover, amount);
    }
    
    /**
     * @notice Burn tokens when proof is verified (deflationary mechanism)
     * @dev Burns from total supply, reducing circulation
     */
    function burnForProofVerification(bytes32 taskId, uint256 rewardAmount) external onlyRole(MINTER_ROLE) {
        // Calculate burn amount (0.1% of reward)
        uint256 burnAmount = (rewardAmount * BURN_PER_PROOF) / 10000;
        
        if (burnAmount > 0 && balanceOf(address(this)) >= burnAmount) {
            _burn(address(this), burnAmount);
            totalBurnedForProofs += burnAmount;
            
            emit ProofVerificationBurn(taskId, burnAmount);
        }
    }
    
    /**
     * @notice Adjust annual inflation rate (decreases over time)
     * @dev Can be called once per year
     */
    function adjustInflationRate() external {
        require(block.timestamp >= lastInflationAdjustment + 365 days, "Too early");
        
        uint256 oldRate = annualInflationRate;
        
        if (annualInflationRate > MIN_INFLATION) {
            annualInflationRate -= INFLATION_DECREASE;
            if (annualInflationRate < MIN_INFLATION) {
                annualInflationRate = MIN_INFLATION;
            }
        }
        
        lastInflationAdjustment = block.timestamp;
        
        emit InflationRateAdjusted(oldRate, annualInflationRate);
    }
    
    /**
     * @notice Calculate maximum mintable tokens this year
     */
    function getAnnualMintCap() public view returns (uint256) {
        uint256 currentSupply = totalSupply();
        return (currentSupply * annualInflationRate) / 10000;
    }
    
    /**
     * @notice Pause token transfers (emergency only)
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }
    
    /**
     * @notice Unpause token transfers
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
    
    /**
     * @notice Get token statistics
     */
    function getStats() external view returns (
        uint256 currentSupply,
        uint256 maxSupply,
        uint256 circulatingSupply,
        uint256 totalBurned,
        uint256 inflationRate,
        uint256 proofRewards
    ) {
        currentSupply = totalSupply();
        maxSupply = MAX_SUPPLY;
        circulatingSupply = currentSupply - balanceOf(address(this));
        totalBurned = totalBurnedForProofs;
        inflationRate = annualInflationRate;
        proofRewards = proofRewardsMinted;
    }
    
    // Override required by Solidity
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override whenNotPaused {
        super._beforeTokenTransfer(from, to, amount);
    }
}
