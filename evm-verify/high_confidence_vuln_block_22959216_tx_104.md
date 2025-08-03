# HIGH-CONFIDENCE Vulnerability Report - Block 22959216 Transaction 104

## Contract Information
- **Analysis Mode**: High-Confidence Only
- **Protocol**: High-Confidence Analysis
- **Contract Address**: 0x32a91ff604ab2adcd832e91d68b2f3f25358fdad
- **Block Number**: 22959216
- **Transaction Index**: 104
- **Scan Date**: 2025-07-21 12:20:52 UTC

## High-Confidence Vulnerabilities Detected

*These vulnerabilities have been filtered for high confidence and are likely real security issues.*

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 75%):
• External call at PC 1905 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  2 state changes detected after external call at PCs: [1973, 2006]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 2308 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [2375]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 2537 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [2636]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 3658 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [3668]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 5520 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [5548]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 6444 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [6537]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 90%):
• External call at PC 6637 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  2 state changes detected after external call at PCs: [6697, 6825]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 90%):
• External call at PC 6647 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  2 state changes detected after external call at PCs: [6697, 6825]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 8629 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [8685]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 65%):
• External call at PC 8915 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  1 state changes detected after external call at PCs: [8969]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 9200 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [9284]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 9705 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [9801]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 65%):
• External call at PC 9718 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  1 state changes detected after external call at PCs: [9801]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### SelfDestruct (Severity: Medium)
- **Description**: Potential self-destruct vulnerability in proxy contract
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Review and implement appropriate security measures

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### IntegerUnderflow (Severity: Medium)
- **Description**: Potential integer underflow detected
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Use SafeMath or check for underflow conditions

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 437. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 1047. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 1905. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 1933. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 2288. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 2996. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 3658. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 4234. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 4237. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 4329. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 4336. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 4422. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 4591. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 6244. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 7349. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 7785. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 7886. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 8270. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 8292. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 8439. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 8757. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 9040. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 9705. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### UncheckedCall (Severity: Low)
- **Description**: Unchecked external call at position 9718. The return value of the call is not checked.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Always check return values of external calls

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 75%):
• External call at PC 1905 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  2 state changes detected after external call at PCs: [1973, 2006]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 2308 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [2375]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 2537 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [2636]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 3658 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [3668]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 5520 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [5548]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 6444 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [6537]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 90%):
• External call at PC 6637 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  2 state changes detected after external call at PCs: [6697, 6825]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 90%):
• External call at PC 6647 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  2 state changes detected after external call at PCs: [6697, 6825]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 8629 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [8685]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 65%):
• External call at PC 8915 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  1 state changes detected after external call at PCs: [8969]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 9200 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [9284]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 80%):
• External call at PC 9705 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  Call provides sufficient gas for complex callback
• ⚠️  1 state changes detected after external call at PCs: [9801]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### Reentrancy (Severity: High)
- **Description**: High-confidence reentrancy vulnerability detected (risk score: 65%):
• External call at PC 9718 with HIGH risk profile
• ⚠️  Call transfers ETH value - enables callback with incentive
• ⚠️  1 state changes detected after external call at PCs: [9801]

This represents a real reentrancy vulnerability, not a false positive.
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Implement ReentrancyGuard or check-effects-interactions pattern

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

### AccessControl (Severity: High)
- **Description**: Missing access control for sensitive operation
- **Location**: Unknown
- **Confidence**: High (>75%)
- **Recommendation**: Add proper access control modifiers (onlyOwner, etc.)

---
*Generated by Startup-Friendly zkEVM Vulnerability Scanner*
*Designed to reduce false positives and support innovation*
