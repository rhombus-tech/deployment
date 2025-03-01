// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title PrecisionVulnerable
 * @dev A contract demonstrating various precision vulnerabilities
 */
contract PrecisionVulnerable {
    uint256 public constant DECIMALS = 18;
    uint256 public constant PRECISION = 10**DECIMALS;
    
    // Division before multiplication vulnerability
    function divisionBeforeMultiplication(uint256 amount, uint256 ratio, uint256 total) public pure returns (uint256) {
        // Vulnerable: Division before multiplication
        return (amount / total) * ratio;
        
        // Safe approach would be:
        // return (amount * ratio) / total;
    }
    
    // Improper scaling vulnerability
    function improperScaling(uint256 amount) public pure returns (uint256) {
        // Vulnerable: Improper scaling when converting between different decimal precisions
        uint256 tokenDecimals = 18;
        uint256 otherTokenDecimals = 6;
        
        // Incorrect scaling (losing precision)
        return amount / (10**(tokenDecimals - otherTokenDecimals));
        
        // Safe approach would be:
        // return amount * (10**(otherTokenDecimals)) / (10**(tokenDecimals));
    }
    
    // Truncation issues
    function truncationIssue(uint256 amount, uint256 fee) public pure returns (uint256) {
        // Vulnerable: Integer division truncation
        uint256 feeAmount = amount * fee / 10000;
        return amount - feeAmount;
        
        // This can lead to rounding errors, especially with small amounts
    }
    
    // Inconsistent decimal handling
    function inconsistentDecimalHandling(uint256 amountA, uint256 amountB) public pure returns (uint256) {
        // Vulnerable: Inconsistent decimal handling between tokens
        // Assume amountA has 18 decimals and amountB has 6 decimals
        
        // Incorrect: Treating both as if they have the same precision
        return amountA + amountB;
        
        // Safe approach would be:
        // return amountA + (amountB * 10**12);
    }
    
    // Exponentiation precision problems
    function exponentiationIssues(uint256 base, uint256 exponent) public pure returns (uint256) {
        // Vulnerable: Precision loss in exponentiation
        uint256 result = 1;
        
        // Naive power implementation can lead to precision issues
        for (uint256 i = 0; i < exponent; i++) {
            result = result * base / PRECISION;
        }
        
        return result;
        
        // A better approach would use logarithms or specialized libraries
    }
    
    // Multiple precision vulnerabilities in one function
    function multipleVulnerabilities(uint256 amount, uint256 ratio, uint256 fee) public pure returns (uint256) {
        // Division before multiplication
        uint256 share = (amount / 100) * ratio;
        
        // Truncation issue
        uint256 feeAmount = share * fee / 10000;
        
        // Improper scaling
        return (share - feeAmount) / 10**9;
    }
}
