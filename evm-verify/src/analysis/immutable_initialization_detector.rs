/// Immutable Variable Initialization Vulnerability Detector
/// 
/// Detects when immutable variables can be initialized with attacker-controlled
/// values during contract deployment, leading to permanent backdoors.
/// 
/// Critical patterns:
/// - Immutables set from constructor parameters
/// - No validation of immutable values
/// - Critical addresses/values set as immutable
/// - Proxy patterns with immutable implementation
/// 
/// Why dangerous:
/// - Immutables CANNOT be changed after deployment
/// - Set once in constructor = permanent
/// - If attacker controls constructor args = permanent backdoor
/// - Common in proxy patterns and factory deployments
/// 
/// Example vulnerability:
/// ```solidity
/// contract Vault {
///     address public immutable oracle;  // Set once, forever
///     address public immutable admin;
///     
///     constructor(address _oracle, address _admin) {
///         oracle = _oracle;   // ❌ No validation!
///         admin = _admin;     // ❌ Attacker can set this!
///     }
///     
///     function withdraw() external {
///         require(msg.sender == admin);  // Backdoor!
///         // ...
///     }
/// }
/// ```
/// 
/// Real exploit:
/// - Factory deploys with attacker's oracle address
/// - Oracle address immutable = permanent backdoor
/// - All price feeds controlled by attacker

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableInitializationVulnerability {
    pub vulnerability_type: ImmutableIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImmutableIssueType {
    UnvalidatedImmutableAddress,    // Address immutable without zero check
    UnvalidatedImmutableValue,      // Value immutable without bounds check
    CriticalImmutableNoValidation,  // Critical immutable (admin/oracle) no validation
    ImmutableFromUntrustedSource,   // Immutable set from external input
    FactoryPatternImmutableRisk,    // Factory creates with immutable backdoor
}

pub struct ImmutableInitializationDetector {
    bytecode: Vec<u8>,
}

impl ImmutableInitializationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ImmutableInitializationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Immutables are stored in code, not storage
        // Constructor stores them via CODECOPY or direct code embedding
        
        vulnerabilities.extend(self.detect_unvalidated_immutable_addresses());
        vulnerabilities.extend(self.detect_unvalidated_immutable_values());
        vulnerabilities.extend(self.detect_critical_immutables_without_validation());

        vulnerabilities
    }

    // ============ UNVALIDATED IMMUTABLE ADDRESSES ============
    
    fn detect_unvalidated_immutable_addresses(&self) -> Vec<ImmutableInitializationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Constructor takes address parameter and embeds it in code
        // without validation (no zero address check)
        
        // In constructor code, look for:
        // CALLDATALOAD (get constructor arg) → directly embedded without checks
        
        if let Some(constructor_code) = self.extract_constructor() {
            let calldataload_positions = self.find_calldataload_positions(&constructor_code);
            
            for &pos in &calldataload_positions {
                // Check if this is an address (20 bytes) parameter
                if self.is_address_parameter(pos, &constructor_code) {
                    // Check if there's NO zero address validation
                    if !self.has_zero_address_validation_after(pos, &constructor_code) {
                        vulnerabilities.push(ImmutableInitializationVulnerability {
                            vulnerability_type: ImmutableIssueType::UnvalidatedImmutableAddress,
                            severity: SecuritySeverity::High,
                            confidence: 0.75,
                            description: "Immutable address set from constructor without validation".to_string(),
                            exploit_scenario: format!(
                                "UNVALIDATED IMMUTABLE ADDRESS at position {}:\n\
                                \n\
                                Vulnerable Pattern:\n\
                                ```solidity\n\
                                contract PriceOracle {{\n\
                                    address public immutable dataSource;\n\
                                    address public immutable admin;\n\
                                    \n\
                                    // ❌ No validation!\n\
                                    constructor(address _dataSource, address _admin) {{\n\
                                        dataSource = _dataSource;  // Could be address(0)!\n\
                                        admin = _admin;            // Could be attacker!\n\
                                    }}\n\
                                    \n\
                                    function getPrice() external view returns (uint256) {{\n\
                                        return IDataSource(dataSource).latestPrice();\n\
                                        // If dataSource = address(0) → permanent DoS\n\
                                        // If dataSource = attacker → price manipulation\n\
                                    }}\n\
                                    \n\
                                    function emergencyWithdraw() external {{\n\
                                        require(msg.sender == admin);\n\
                                        // If admin = attacker → backdoor!\n\
                                        // admin is IMMUTABLE = can't fix!\n\
                                    }}\n\
                                }}\n\
                                ```\n\
                                \n\
                                Real Exploit Scenarios:\n\
                                \n\
                                Scenario 1: Factory Deployment\n\
                                ```solidity\n\
                                contract VaultFactory {{\n\
                                    function createVault(address _oracle) external returns (address) {{\n\
                                        // ❌ No validation here\n\
                                        return address(new Vault(_oracle));\n\
                                    }}\n\
                                }}\n\
                                \n\
                                // Attack:\n\
                                // 1. Attacker calls createVault(attackerOracle)\n\
                                // 2. Vault deployed with attacker's oracle\n\
                                // 3. Oracle is IMMUTABLE\n\
                                // 4. Attacker controls all prices forever\n\
                                // 5. Users deposit, attacker manipulates prices\n\
                                // 6. Attacker liquidates everyone, steals funds\n\
                                ```\n\
                                \n\
                                Scenario 2: CREATE2 Deployment\n\
                                ```solidity\n\
                                // Attacker frontrun legitimate deployment\n\
                                bytes32 salt = keccak256(\"vault_v1\");\n\
                                address predictedAddress = computeCreate2Address(...);\n\
                                \n\
                                // Attacker deploys first with malicious params\n\
                                create2(bytecode, salt, attackerOracle, attackerAdmin);\n\
                                \n\
                                // Victim's deployment fails (address taken)\n\
                                // Attacker's version has backdoor via immutables\n\
                                ```\n\
                                \n\
                                Impact:\n\
                                - Permanent backdoor (immutables can't be changed)\n\
                                - No recovery mechanism\n\
                                - Must redeploy entire contract\n\
                                - Users' funds at risk if already deposited\n\
                                \n\
                                Fix:\n\
                                ```solidity\n\
                                constructor(address _dataSource, address _admin) {{\n\
                                    require(_dataSource != address(0), 'Zero data source');\n\
                                    require(_admin != address(0), 'Zero admin');\n\
                                    \n\
                                    // Optional: Whitelist validation\n\
                                    require(approvedDataSources[_dataSource], 'Unapproved source');\n\
                                    \n\
                                    // Optional: Sanity check\n\
                                    require(_dataSource.code.length > 0, 'Not a contract');\n\
                                    \n\
                                    dataSource = _dataSource;\n\
                                    admin = _admin;\n\
                                }}\n\
                                ```\n\
                                \n\
                                Best Practice:\n\
                                - ALWAYS validate immutable addresses\n\
                                - Check != address(0)\n\
                                - Verify contract code exists\n\
                                - Consider whitelist for critical addresses\n\
                                - Use timelock for immutable deployments",
                                pos
                            ),
                            location: pos,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    // ============ UNVALIDATED IMMUTABLE VALUES ============
    
    fn detect_unvalidated_immutable_values(&self) -> Vec<ImmutableInitializationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(constructor_code) = self.extract_constructor() {
            let calldataload_positions = self.find_calldataload_positions(&constructor_code);
            
            for &pos in &calldataload_positions {
                // Check if this is a numeric parameter (uint256)
                if self.is_numeric_parameter(pos, &constructor_code) {
                    // Check if there's NO bounds validation
                    if !self.has_bounds_validation_after(pos, &constructor_code) {
                        vulnerabilities.push(ImmutableInitializationVulnerability {
                            vulnerability_type: ImmutableIssueType::UnvalidatedImmutableValue,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.70,
                            description: "Immutable value set from constructor without bounds check".to_string(),
                            exploit_scenario: format!(
                                "UNVALIDATED IMMUTABLE VALUE at position {}:\n\
                                \n\
                                Pattern:\n\
                                ```solidity\n\
                                contract DeFiProtocol {{\n\
                                    uint256 public immutable feeRate;        // Basis points\n\
                                    uint256 public immutable minDeposit;     // Wei\n\
                                    uint256 public immutable maxLeverage;    // Multiplier\n\
                                    \n\
                                    // ❌ No bounds validation!\n\
                                    constructor(\n\
                                        uint256 _feeRate,\n\
                                        uint256 _minDeposit,\n\
                                        uint256 _maxLeverage\n\
                                    ) {{\n\
                                        feeRate = _feeRate;        // Could be 100% (10000 bps)!\n\
                                        minDeposit = _minDeposit;  // Could be type(uint256).max!\n\
                                        maxLeverage = _maxLeverage; // Could be 1000x!\n\
                                    }}\n\
                                    \n\
                                    function deposit() external payable {{\n\
                                        require(msg.value >= minDeposit);\n\
                                        uint256 fee = msg.value * feeRate / 10000;\n\
                                        // If feeRate = 10000 → 100% fee → steal all funds\n\
                                    }}\n\
                                }}\n\
                                ```\n\
                                \n\
                                Exploit:\n\
                                1. Deploy with feeRate = 10000 (100%)\n\
                                2. Users deposit funds\n\
                                3. Protocol takes 100% as fee\n\
                                4. feeRate is IMMUTABLE = permanent 100% fee\n\
                                5. All user funds stolen\n\
                                \n\
                                Fix:\n\
                                ```solidity\n\
                                constructor(uint256 _feeRate, ...) {{\n\
                                    require(_feeRate <= 1000, 'Fee too high'); // Max 10%\n\
                                    require(_minDeposit >= 0.01 ether, 'Min too low');\n\
                                    require(_minDeposit <= 100 ether, 'Min too high');\n\
                                    require(_maxLeverage <= 10, 'Leverage too high');\n\
                                    \n\
                                    feeRate = _feeRate;\n\
                                    // ...\n\
                                }}\n\
                                ```",
                                pos
                            ),
                            location: pos,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    // ============ CRITICAL IMMUTABLES ============
    
    fn detect_critical_immutables_without_validation(&self) -> Vec<ImmutableInitializationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for patterns suggesting critical immutables like oracle, admin, implementation
        // These are especially dangerous without validation
        
        if let Some(constructor_code) = self.extract_constructor() {
            // Look for multiple unvalidated parameters
            let unvalidated_params = self.count_unvalidated_parameters(&constructor_code);
            
            if unvalidated_params >= 2 {
                vulnerabilities.push(ImmutableInitializationVulnerability {
                    vulnerability_type: ImmutableIssueType::CriticalImmutableNoValidation,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.80,
                    description: format!(
                        "{} constructor parameters set as immutables without validation",
                        unvalidated_params
                    ),
                    exploit_scenario: format!(
                        "MULTIPLE CRITICAL IMMUTABLES UNVALIDATED:\n\
                        \n\
                        Detected {} constructor parameters that become immutable without validation.\n\
                        \n\
                        Extreme Risk Pattern:\n\
                        ```solidity\n\
                        contract CriticalSystem {{\n\
                            address public immutable owner;\n\
                            address public immutable oracle;\n\
                            address public immutable implementation;\n\
                            address public immutable treasury;\n\
                            \n\
                            // ❌ NO VALIDATION AT ALL\n\
                            constructor(\n\
                                address _owner,\n\
                                address _oracle,\n\
                                address _implementation,\n\
                                address _treasury\n\
                            ) {{\n\
                                owner = _owner;\n\
                                oracle = _oracle;\n\
                                implementation = _implementation;\n\
                                treasury = _treasury;\n\
                                // All IMMUTABLE, all UNVALIDATED!\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        This is CRITICAL because:\n\
                        1. Multiple attack vectors in one deployment\n\
                        2. ANY parameter can be malicious\n\
                        3. ALL are permanent (immutable)\n\
                        4. NO recovery mechanism\n\
                        \n\
                        Attack Vectors:\n\
                        - owner = attacker → backdoor access\n\
                        - oracle = attacker → price manipulation\n\
                        - implementation = malicious → arbitrary code execution\n\
                        - treasury = attacker → all fees stolen\n\
                        \n\
                        Real Incident Pattern:\n\
                        - Seen in multiple 2023-2024 exploits\n\
                        - Factory contracts deploying with no validation\n\
                        - CREATE2 frontrunning with malicious params\n\
                        - Users depositing before noticing backdoor\n\
                        \n\
                        Mandatory Fix:\n\
                        ```solidity\n\
                        constructor(...) {{\n\
                            // Validate ALL parameters\n\
                            require(_owner != address(0), 'Zero owner');\n\
                            require(_oracle != address(0), 'Zero oracle');\n\
                            require(_implementation != address(0), 'Zero impl');\n\
                            require(_treasury != address(0), 'Zero treasury');\n\
                            \n\
                            // Verify contracts exist\n\
                            require(_oracle.code.length > 0, 'Oracle not contract');\n\
                            require(_implementation.code.length > 0, 'Impl not contract');\n\
                            \n\
                            // Optional: Whitelist check\n\
                            require(approvedOracles[_oracle], 'Oracle not approved');\n\
                            \n\
                            owner = _owner;\n\
                            oracle = _oracle;\n\
                            implementation = _implementation;\n\
                            treasury = _treasury;\n\
                        }}\n\
                        ```\n\
                        \n\
                        Defense in Depth:\n\
                        1. Constructor validation (required)\n\
                        2. Factory validation (if deployed via factory)\n\
                        3. Timelock on deployments (recommended)\n\
                        4. Multi-sig for critical deployments\n\
                        5. Community review before users deposit",
                        unvalidated_params
                    ),
                    location: 0,
                });
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn extract_constructor(&self) -> Option<Vec<u8>> {
        // Constructor is the code before CODECOPY + RETURN
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x39 { // CODECOPY
                // Look for RETURN nearby
                for j in i+1..i+10 {
                    if j < self.bytecode.len() && self.bytecode[j] == 0xF3 { // RETURN
                        return Some(self.bytecode[0..=j].to_vec());
                    }
                }
            }
        }
        None
    }

    fn find_calldataload_positions(&self, code: &[u8]) -> Vec<usize> {
        code.iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x35) // CALLDATALOAD
            .map(|(i, _)| i)
            .collect()
    }

    fn is_address_parameter(&self, pos: usize, code: &[u8]) -> bool {
        // Heuristic: Address parameters often followed by AND with address mask
        // or used with EXTCODESIZE check
        for i in pos..pos.saturating_add(15).min(code.len()) {
            // Check for address mask: AND with 0xffffffffffffffffffffffffffffffffffffffff
            if code[i] == 0x16 { // AND
                return true;
            }
            // Check for EXTCODESIZE (contract check)
            if code[i] == 0x3B { // EXTCODESIZE
                return true;
            }
        }
        false
    }

    fn is_numeric_parameter(&self, _pos: usize, _code: &[u8]) -> bool {
        // If not address, likely numeric
        // More sophisticated analysis could check usage patterns
        true
    }

    fn has_zero_address_validation_after(&self, pos: usize, code: &[u8]) -> bool {
        // Look for: PUSH 0, EQ, ISZERO, JUMPI/REVERT pattern
        for i in pos..pos.saturating_add(20).min(code.len()) {
            if i + 4 < code.len() {
                if code[i] == 0x60 &&      // PUSH1
                   code[i+1] == 0x00 &&    // 0
                   code[i+2] == 0x14 &&    // EQ
                   code[i+3] == 0x15 {     // ISZERO
                    return true;
                }
            }
        }
        false
    }

    fn has_bounds_validation_after(&self, pos: usize, code: &[u8]) -> bool {
        // Look for: LT, GT, or EQ comparison followed by conditional
        for i in pos..pos.saturating_add(15).min(code.len()) {
            if code[i] == 0x10 || code[i] == 0x11 || code[i] == 0x14 { // LT, GT, EQ
                // Check for JUMPI or REVERT nearby
                if i + 3 < code.len() {
                    if code[i+1] == 0x57 || code[i+2] == 0xFD { // JUMPI or REVERT
                        return true;
                    }
                }
            }
        }
        false
    }

    fn count_unvalidated_parameters(&self, code: &[u8]) -> usize {
        let calldataload_count = code.iter().filter(|&&b| b == 0x35).count();
        let validation_count = self.count_validation_checks(code);
        
        // If more parameters than validations, some are unvalidated
        calldataload_count.saturating_sub(validation_count)
    }

    fn count_validation_checks(&self, code: &[u8]) -> usize {
        let mut count = 0;
        
        for i in 0..code.len().saturating_sub(5) {
            // Count REVERT or JUMPI after comparisons as validations
            if (code[i] == 0x10 || code[i] == 0x11 || code[i] == 0x14) && // Comparison
               i + 3 < code.len() &&
               (code[i+2] == 0x57 || code[i+3] == 0xFD) { // JUMPI or REVERT
                count += 1;
            }
        }
        
        count
    }
}
