/// Remediation Code Generator
/// Automatically generates fixed Solidity code that resolves detected vulnerabilities
use crate::bytecode::SecuritySeverity;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RemediationCodeGenerator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RemediationPatch {
    pub vulnerability_type: String,
    pub original_code: String,
    pub fixed_code: String,
    pub explanation: String,
    pub gas_impact: i64,
    pub difficulty: RemediationDifficulty,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RemediationDifficulty {
    Easy,      // Simple pattern fix
    Medium,    // Requires refactoring
    Hard,      // Major architectural change
    Critical,  // Requires complete redesign
}

impl RemediationCodeGenerator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn generate_remediations(&self, vulnerabilities: &[(String, usize)]) -> Vec<RemediationPatch> {
        let mut patches = Vec::new();

        for (vuln_type, location) in vulnerabilities {
            if let Some(patch) = self.generate_patch(vuln_type, *location) {
                patches.push(patch);
            }
        }

        patches
    }

    fn generate_patch(&self, vuln_type: &str, location: usize) -> Option<RemediationPatch> {
        match vuln_type {
            "Reentrancy" => self.generate_reentrancy_fix(location),
            "Integer Overflow" => self.generate_overflow_fix(location),
            "Access Control Missing" => self.generate_access_control_fix(location),
            "Uninitialized Proxy" => self.generate_proxy_initialization_fix(location),
            "Unchecked External Call" => self.generate_external_call_fix(location),
            _ => self.generate_generic_fix(vuln_type, location),
        }
    }

    fn generate_reentrancy_fix(&self, location: usize) -> Option<RemediationPatch> {
        let original = r#"
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}
"#.to_string();

        let fixed = r#"
// Add reentrancy guard at contract level
bool private locked;
modifier nonReentrant() {
    require(!locked, "ReentrancyGuard: reentrant call");
    locked = true;
    _;
    locked = false;
}

// Fixed function with guard and checks-effects-interactions
function withdraw(uint amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    // EFFECTS: Update state BEFORE external call
    balances[msg.sender] -= amount;
    
    // INTERACTIONS: External call last
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
"#.to_string();

        Some(RemediationPatch {
            vulnerability_type: "Reentrancy".to_string(),
            original_code: original,
            fixed_code: fixed,
            explanation: "Applied checks-effects-interactions pattern and added nonReentrant modifier".to_string(),
            gas_impact: 5000, // Extra SSTORE for lock
            difficulty: RemediationDifficulty::Easy,
        })
    }

    fn generate_overflow_fix(&self, location: usize) -> Option<RemediationPatch> {
        let original = r#"
function transfer(address to, uint amount) external {
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
"#.to_string();

        let fixed = r#"
// Import SafeMath or use Solidity 0.8.0+
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
using SafeMath for uint256;

function transfer(address to, uint amount) external {
    // SafeMath automatically reverts on overflow/underflow
    balances[msg.sender] = balances[msg.sender].sub(amount);
    balances[to] = balances[to].add(amount);
}

// OR upgrade to Solidity 0.8.0+ for built-in overflow checks:
// pragma solidity ^0.8.0; // Automatic overflow protection
"#.to_string();

        Some(RemediationPatch {
            vulnerability_type: "Integer Overflow".to_string(),
            original_code: original,
            fixed_code: fixed,
            explanation: "Use SafeMath library or upgrade to Solidity 0.8.0+ for automatic overflow protection".to_string(),
            gas_impact: 200, // Minimal gas increase
            difficulty: RemediationDifficulty::Easy,
        })
    }

    fn generate_access_control_fix(&self, location: usize) -> Option<RemediationPatch> {
        let original = r#"
function setOwner(address newOwner) external {
    owner = newOwner;
}
"#.to_string();

        let fixed = r#"
// Add access control at contract level
address public owner;
modifier onlyOwner() {
    require(msg.sender == owner, "Caller is not owner");
    _;
}

// Fixed function with access control
function setOwner(address newOwner) external onlyOwner {
    require(newOwner != address(0), "Invalid new owner");
    address oldOwner = owner;
    owner = newOwner;
    emit OwnershipTransferred(oldOwner, newOwner);
}

// Add event for transparency
event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
"#.to_string();

        Some(RemediationPatch {
            vulnerability_type: "Access Control Missing".to_string(),
            original_code: original,
            fixed_code: fixed,
            explanation: "Added onlyOwner modifier and ownership transfer event".to_string(),
            gas_impact: 3000, // SLOAD for owner check
            difficulty: RemediationDifficulty::Easy,
        })
    }

    fn generate_proxy_initialization_fix(&self, location: usize) -> Option<RemediationPatch> {
        let original = r#"
contract Implementation {
    address public owner;
    
    constructor(address _owner) {
        owner = _owner;
    }
}
"#.to_string();

        let fixed = r#"
// Import Initializable from OpenZeppelin
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract Implementation is Initializable {
    address public owner;
    
    // Remove constructor - use initializer instead
    // constructor() {} // DON'T USE
    
    // Add initializer function
    function initialize(address _owner) external initializer {
        require(_owner != address(0), "Invalid owner");
        owner = _owner;
    }
    
    // Prevent implementation from being initialized
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
}
"#.to_string();

        Some(RemediationPatch {
            vulnerability_type: "Uninitialized Proxy".to_string(),
            original_code: original,
            fixed_code: fixed,
            explanation: "Converted constructor to initializer function with Initializable pattern".to_string(),
            gas_impact: 8000, // Initializer overhead
            difficulty: RemediationDifficulty::Medium,
        })
    }

    fn generate_external_call_fix(&self, location: usize) -> Option<RemediationPatch> {
        let original = r#"
function execute(address target, bytes memory data) external {
    target.call(data);
}
"#.to_string();

        let fixed = r#"
function execute(address target, bytes memory data) external {
    // Check return value
    (bool success, bytes memory returnData) = target.call(data);
    
    // Always verify external call succeeded
    require(success, "External call failed");
    
    // Optional: Check return data is not empty if expecting return value
    if (returnData.length > 0) {
        // Decode and validate return data as needed
    }
}
"#.to_string();

        Some(RemediationPatch {
            vulnerability_type: "Unchecked External Call".to_string(),
            original_code: original,
            fixed_code: fixed,
            explanation: "Added return value check for external call".to_string(),
            gas_impact: 100,
            difficulty: RemediationDifficulty::Easy,
        })
    }

    fn generate_generic_fix(&self, vuln_type: &str, location: usize) -> Option<RemediationPatch> {
        Some(RemediationPatch {
            vulnerability_type: vuln_type.to_string(),
            original_code: format!("// Vulnerability detected at location {}", location),
            fixed_code: format!("// Manual review required for {}", vuln_type),
            explanation: format!("This vulnerability requires manual review and custom fix"),
            gas_impact: 0,
            difficulty: RemediationDifficulty::Hard,
        })
    }

    pub fn generate_full_contract_patch(&self, vulnerabilities: &[(String, usize)]) -> String {
        let patches = self.generate_remediations(vulnerabilities);
        
        let mut full_patch = String::from("// SECURITY PATCH - AUTO-GENERATED\n");
        full_patch.push_str("// Review all changes before deployment\n\n");
        
        full_patch.push_str("pragma solidity ^0.8.0; // Use latest for built-in protections\n\n");
        full_patch.push_str("// Recommended imports:\n");
        full_patch.push_str("import \"@openzeppelin/contracts/security/ReentrancyGuard.sol\";\n");
        full_patch.push_str("import \"@openzeppelin/contracts/access/Ownable.sol\";\n");
        full_patch.push_str("import \"@openzeppelin/contracts/security/Pausable.sol\";\n\n");
        
        for patch in &patches {
            full_patch.push_str(&format!("// FIX: {}\n", patch.vulnerability_type));
            full_patch.push_str(&format!("// {}\n", patch.explanation));
            full_patch.push_str(&format!("// Gas Impact: {} gas\n\n", patch.gas_impact));
            full_patch.push_str(&patch.fixed_code);
            full_patch.push_str("\n\n");
        }
        
        full_patch
    }

    pub fn estimate_total_gas_impact(&self, vulnerabilities: &[(String, usize)]) -> i64 {
        self.generate_remediations(vulnerabilities)
            .iter()
            .map(|p| p.gas_impact)
            .sum()
    }
}
