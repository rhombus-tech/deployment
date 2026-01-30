/// Constructor vs Runtime Behavior Divergence Detector
/// 
/// Detects when constructor code performs checks or operations that are NOT
/// present in runtime code, leading to unexpected behavior after deployment.
/// 
/// Critical patterns:
/// - Constructor validates parameters, runtime doesn't
/// - Constructor checks msg.sender, runtime doesn't
/// - Constructor sets critical state, runtime can override
/// - Constructor has access control, runtime doesn't
/// 
/// Real exploits:
/// - Constructor checks deployer == owner, runtime allows anyone
/// - Constructor validates addresses, runtime accepts zero address
/// - Constructor initializes with safe values, runtime allows unsafe changes

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructorRuntimeDivergenceVulnerability {
    pub vulnerability_type: ConstructorDivergenceType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub constructor_location: usize,
    pub runtime_location: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstructorDivergenceType {
    MissingRuntimeValidation,      // Constructor validates, runtime doesn't
    ConstructorOnlyAccessControl,  // Constructor has access control, runtime doesn't
    InitializationNotProtected,    // Constructor sets values, runtime allows changes
    AddressValidationSkipped,      // Constructor checks addresses, runtime doesn't
    ParameterCheckMissing,         // Constructor validates params, runtime doesn't
}

pub struct ConstructorRuntimeDivergenceDetector {
    bytecode: Vec<u8>,
}

impl ConstructorRuntimeDivergenceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ConstructorRuntimeDivergenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Split bytecode into constructor and runtime portions
        if let Some((constructor_code, runtime_code)) = self.split_constructor_runtime() {
            vulnerabilities.extend(self.detect_validation_divergence(&constructor_code, &runtime_code));
            vulnerabilities.extend(self.detect_access_control_divergence(&constructor_code, &runtime_code));
            vulnerabilities.extend(self.detect_initialization_divergence(&constructor_code, &runtime_code));
        }

        vulnerabilities
    }

    // ============ SPLIT CONSTRUCTOR FROM RUNTIME ============
    
    fn split_constructor_runtime(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        // Constructor ends with CODECOPY + RETURN of runtime code
        // Pattern: CODECOPY runtime_offset, code_offset, code_length; RETURN runtime_offset, code_length
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x39 { // CODECOPY
                // Look ahead for RETURN
                for j in i+1..i+15 {
                    if j < self.bytecode.len() && self.bytecode[j] == 0xF3 { // RETURN
                        // Split at RETURN
                        let constructor = self.bytecode[0..=j].to_vec();
                        let runtime = if j + 1 < self.bytecode.len() {
                            self.bytecode[j+1..].to_vec()
                        } else {
                            Vec::new()
                        };
                        return Some((constructor, runtime));
                    }
                }
            }
        }
        
        None
    }

    // ============ VALIDATION DIVERGENCE ============
    
    fn detect_validation_divergence(
        &self,
        constructor: &[u8],
        runtime: &[u8]
    ) -> Vec<ConstructorRuntimeDivergenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Constructor has REVERT after checks, runtime doesn't
        let constructor_checks = self.count_validation_patterns(constructor);
        let runtime_checks = self.count_validation_patterns(runtime);

        if constructor_checks > runtime_checks + 2 {
            vulnerabilities.push(ConstructorRuntimeDivergenceVulnerability {
                vulnerability_type: ConstructorDivergenceType::MissingRuntimeValidation,
                severity: SecuritySeverity::High,
                confidence: 0.75,
                description: format!(
                    "Constructor has {} validation checks, runtime only has {}",
                    constructor_checks, runtime_checks
                ),
                exploit_scenario: format!(
                    "CONSTRUCTOR vs RUNTIME DIVERGENCE:\n\
                    \n\
                    Constructor code:\n\
                    - {} parameter validations\n\
                    - {} require() statements\n\
                    \n\
                    Runtime code:\n\
                    - {} parameter validations\n\
                    - {} require() statements\n\
                    \n\
                    Real Exploit Pattern:\n\
                    ```solidity\n\
                    constructor(address _token) {{\n\
                        require(_token != address(0), 'Zero address'); // ✓ Checked\n\
                        require(_token.code.length > 0, 'Not contract'); // ✓ Checked\n\
                        token = _token;\n\
                    }}\n\
                    \n\
                    function updateToken(address _newToken) external {{\n\
                        token = _newToken;  // ❌ NO CHECKS!\n\
                    }}\n\
                    ```\n\
                    \n\
                    Exploit:\n\
                    1. Deploy with valid token address\n\
                    2. Later call updateToken(address(0))\n\
                    3. Token set to zero address\n\
                    4. All token interactions break\n\
                    \n\
                    Fix: Reuse same validation logic in both",
                    constructor_checks,
                    constructor_checks,
                    runtime_checks,
                    runtime_checks
                ),
                constructor_location: 0,
                runtime_location: None,
            });
        }

        vulnerabilities
    }

    fn count_validation_patterns(&self, code: &[u8]) -> usize {
        let mut count = 0;
        
        for i in 0..code.len().saturating_sub(5) {
            // Pattern: Check + JUMPI + REVERT (validation)
            if (code[i] == 0x10 || code[i] == 0x11 || code[i] == 0x14) && // LT, GT, EQ
               i + 3 < code.len() &&
               code[i+1] == 0x15 && // ISZERO
               code[i+2] == 0x57 && // JUMPI
               i + 5 < code.len() &&
               code[i+5] == 0xFD { // REVERT nearby
                count += 1;
            }
        }
        
        count
    }

    // ============ ACCESS CONTROL DIVERGENCE ============
    
    fn detect_access_control_divergence(
        &self,
        constructor: &[u8],
        runtime: &[u8]
    ) -> Vec<ConstructorRuntimeDivergenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if constructor has msg.sender checks that runtime doesn't
        let constructor_sender_checks = self.count_msg_sender_checks(constructor);
        let runtime_sender_checks = self.count_msg_sender_checks(runtime);

        if constructor_sender_checks > 0 && runtime_sender_checks == 0 {
            vulnerabilities.push(ConstructorRuntimeDivergenceVulnerability {
                vulnerability_type: ConstructorDivergenceType::ConstructorOnlyAccessControl,
                severity: SecuritySeverity::Critical,
                confidence: 0.80,
                description: "Constructor has msg.sender access control, runtime has none".to_string(),
                exploit_scenario: "CRITICAL: CONSTRUCTOR-ONLY ACCESS CONTROL:\n\
                    \n\
                    Constructor:\n\
                    ```solidity\n\
                    constructor(address _vault) {{\n\
                        require(msg.sender == trustedDeployer, 'Unauthorized');\n\
                        vault = _vault;\n\
                    }}\n\
                    ```\n\
                    \n\
                    Runtime:\n\
                    ```solidity\n\
                    function setVault(address _newVault) external {{\n\
                        vault = _newVault;  // ❌ NO msg.sender CHECK!\n\
                    }}\n\
                    ```\n\
                    \n\
                    Exploit:\n\
                    1. Contract deployed by trusted deployer ✓\n\
                    2. Attacker calls setVault(attackerVault)\n\
                    3. No access control in runtime\n\
                    4. Vault updated to attacker's address\n\
                    5. All funds routed to attacker\n\
                    \n\
                    This is CRITICAL because:\n\
                    - Developer assumed constructor check was enough\n\
                    - Runtime functions have no protection\n\
                    - Common in minimal proxy patterns\n\
                    \n\
                    Fix: Add access control modifier to runtime functions".to_string(),
                constructor_location: 0,
                runtime_location: None,
            });
        }

        vulnerabilities
    }

    fn count_msg_sender_checks(&self, code: &[u8]) -> usize {
        let mut count = 0;
        
        for i in 0..code.len().saturating_sub(3) {
            if code[i] == 0x33 { // CALLER (msg.sender)
                // Check if followed by comparison
                if i + 2 < code.len() && code[i+2] == 0x14 { // EQ
                    count += 1;
                }
            }
        }
        
        count
    }

    // ============ INITIALIZATION DIVERGENCE ============
    
    fn detect_initialization_divergence(
        &self,
        constructor: &[u8],
        runtime: &[u8]
    ) -> Vec<ConstructorRuntimeDivergenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if constructor initializes storage but runtime allows re-initialization
        let constructor_sstores = self.count_sstore_operations(constructor);
        let runtime_sstores = self.count_sstore_operations(runtime);

        if constructor_sstores > 3 && runtime_sstores > 2 {
            // Check if runtime has initialization guards
            if !self.has_initialization_guard(runtime) {
                vulnerabilities.push(ConstructorRuntimeDivergenceVulnerability {
                    vulnerability_type: ConstructorDivergenceType::InitializationNotProtected,
                    severity: SecuritySeverity::High,
                    confidence: 0.70,
                    description: "Constructor initializes state, runtime allows re-initialization without guards".to_string(),
                    exploit_scenario: "INITIALIZATION RE-ENTRANCY:\n\
                        \n\
                        Constructor:\n\
                        ```solidity\n\
                        constructor(address _owner, uint256 _value) {{\n\
                            owner = _owner;\n\
                            initialized = true;\n\
                            criticalValue = _value;\n\
                        }}\n\
                        ```\n\
                        \n\
                        Runtime:\n\
                        ```solidity\n\
                        function initialize(address _owner, uint256 _value) external {{\n\
                            // ❌ Missing: require(!initialized, 'Already initialized');\n\
                            owner = _owner;\n\
                            initialized = true;\n\
                            criticalValue = _value;\n\
                        }}\n\
                        ```\n\
                        \n\
                        Exploit (Proxy Pattern):\n\
                        1. Deploy implementation via constructor ✓\n\
                        2. Deploy proxy pointing to implementation\n\
                        3. Proxy calls initialize() on implementation\n\
                        4. Attacker front-runs and calls initialize() first\n\
                        5. Attacker sets themselves as owner\n\
                        6. Takes control of proxy\n\
                        \n\
                        Real incident: Multiple proxy implementations in 2023\n\
                        \n\
                        Fix: Add initializer modifier:\n\
                        ```solidity\n\
                        bool private initialized;\n\
                        modifier initializer() {{\n\
                            require(!initialized, 'Already initialized');\n\
                            initialized = true;\n\
                            _;\n\
                        }}\n\
                        ```".to_string(),
                    constructor_location: 0,
                    runtime_location: None,
                });
            }
        }

        // Check for address validation divergence
        if self.has_zero_address_check(constructor) && !self.has_zero_address_check(runtime) {
            vulnerabilities.push(ConstructorRuntimeDivergenceVulnerability {
                vulnerability_type: ConstructorDivergenceType::AddressValidationSkipped,
                severity: SecuritySeverity::Medium,
                confidence: 0.75,
                description: "Constructor validates addresses != 0, runtime doesn't".to_string(),
                exploit_scenario: "ZERO ADDRESS BYPASS:\n\
                    \n\
                    Constructor checks:\n\
                    ```solidity\n\
                    require(_token != address(0));\n\
                    require(_oracle != address(0));\n\
                    ```\n\
                    \n\
                    Runtime functions don't check:\n\
                    ```solidity\n\
                    function updateOracle(address _oracle) external onlyOwner {{\n\
                        oracle = _oracle;  // ❌ No zero check\n\
                    }}\n\
                    ```\n\
                    \n\
                    Impact:\n\
                    - Owner accidentally sets oracle = address(0)\n\
                    - All oracle calls revert\n\
                    - Protocol breaks\n\
                    \n\
                    Fix: Reuse validation helper functions".to_string(),
                constructor_location: 0,
                runtime_location: Some(0),
            });
        }

        vulnerabilities
    }

    fn count_sstore_operations(&self, code: &[u8]) -> usize {
        code.iter().filter(|&&b| b == 0x55).count() // SSTORE
    }

    fn has_initialization_guard(&self, code: &[u8]) -> bool {
        // Look for: SLOAD + ISZERO + JUMPI pattern (initialized check)
        for i in 0..code.len().saturating_sub(4) {
            if code[i] == 0x54 &&      // SLOAD
               code[i+1] == 0x15 &&    // ISZERO
               code[i+2] == 0x57 {     // JUMPI
                return true;
            }
        }
        false
    }

    fn has_zero_address_check(&self, code: &[u8]) -> bool {
        // Pattern: PUSH 0, EQ, ISZERO (check != 0)
        for i in 0..code.len().saturating_sub(4) {
            if code[i] == 0x60 &&      // PUSH1
               code[i+1] == 0x00 &&    // 0
               code[i+2] == 0x14 &&    // EQ
               code[i+3] == 0x15 {     // ISZERO
                return true;
            }
        }
        false
    }
}
