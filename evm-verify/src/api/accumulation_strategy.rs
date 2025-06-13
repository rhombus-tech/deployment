// Import the ZODAAccumulationAdapter from the external pcd crate
use anyhow::Result;
use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintSynthesizer;
use log::{debug, info};
use pcd::zoda_accumulation::ZODAAccumulationAdapter;
use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

/// Available verification strategies
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerificationStrategy {
    /// Traditional Groth16-based approach
    Groth16,
    /// Accidental Computer (ZODA) approach
    ZODA,
}

impl Default for VerificationStrategy {
    fn default() -> Self {
        VerificationStrategy::Groth16
    }
}

/// Groth16-based strategy using the existing implementation
#[derive(Clone)]
pub struct Groth16Strategy {
    // Current bytecode being analyzed
    bytecode: Option<Vec<u8>>,
    // Vulnerability flags
    vulnerabilities: std::collections::HashMap<String, bool>,
}

impl Groth16Strategy {
    /// Create a new Groth16-based strategy
    pub fn new() -> Self {
        Self {
            bytecode: None,
            vulnerabilities: std::collections::HashMap::new(),
        }
    }

    /// Initialize the strategy with bytecode
    pub fn initialize(&mut self, bytecode: Vec<u8>) -> Result<()> {
        self.bytecode = Some(bytecode);
        self.vulnerabilities.clear();
        Ok(())
    }

    /// Accumulate a circuit's constraints and check for vulnerabilities
    pub fn accumulate_circuit<C: ConstraintSynthesizer<Fr>>(&mut self, circuit: C) -> Result<()> {
        // This is a simplified version - in a real implementation,
        // you would generate and verify proofs using your existing Groth16 approach

        // For now, we'll just set a vulnerability flag based on the circuit type name
        let type_name = std::any::type_name::<C>();
        let vuln_type = if type_name.contains("Reentrancy") {
            "reentrancy"
        } else if type_name.contains("SignatureReplay") {
            "signature_replay"
        } else {
            "unknown"
        };

        // In a real implementation, you would analyze the circuit for vulnerabilities
        // For now, we'll just set a dummy value
        self.vulnerabilities.insert(vuln_type.to_string(), false);

        Ok(())
    }

    /// Verify that no vulnerabilities are present
    pub fn verify(&mut self) -> Result<bool> {
        // In a real implementation, you would verify all accumulated proofs
        // For now, we'll just check if any vulnerabilities were found
        Ok(!self.vulnerabilities.values().any(|&v| v))
    }

    /// Check if a specific vulnerability is present
    pub fn has_vulnerability(&self, vuln_type: &str) -> Result<bool> {
        Ok(self
            .vulnerabilities
            .get(vuln_type)
            .copied()
            .unwrap_or(false))
    }
}

/// ZODA-based strategy using the Accidental Computer approach
#[derive(Clone)]
pub struct ZODAStrategy {
    /// The adapter for tensor ZODA accumulation
    adapter: ZODAAccumulationAdapter<Fr>,
    
    /// Field size for randomness generation
    field_size: u64,
    
    /// Distance parameter for Reed-Solomon code
    distance_parameter: usize,
    
    /// Time spent on setup (initialization)
    setup_time: Option<std::time::Duration>,
    
    /// Time spent on verification
    verification_time: Option<std::time::Duration>,
    
    /// Number of circuits accumulated
    accumulated_circuits: usize,
    
    /// Cache for vulnerability query results
    vulnerability_cache: std::collections::HashMap<String, bool>,
}

impl ZODAStrategy {
    /// Create a new ZODA-based strategy with default parameters
    /// - Uses Field size 128 (compatible with BN254 curve)
    /// - Uses standard (non-test) mode
    /// - Sets distance parameter to 10 (balanced security vs. efficiency)
    pub fn new() -> Self {
        Self::with_options(128, false)
    }
    
    /// Create a new ZODA-based strategy specifically for testing
    /// - Uses Field size 16 (smaller dimensions for test bytecode)
    /// - Uses test mode with lower security parameters
    /// - Sets distance parameter to 4 (optimized for testing)
    pub fn new_test_mode() -> Self {
        Self::with_options(16, true)
    }

    /// Create a new ZODA-based strategy with custom options
    /// 
    /// # Arguments
    /// * `field_size` - Field size for randomness generation
    /// * `test_mode` - If true, uses test mode with lower security parameters for faster processing
    pub fn with_options(field_size: u64, test_mode: bool) -> Self {
        let distance_parameter = if test_mode { 4 } else { 10 };
        
        Self {
            adapter: ZODAAccumulationAdapter::new(field_size, test_mode),
            field_size,
            distance_parameter,
            setup_time: None,
            verification_time: None,
            accumulated_circuits: 0,
            vulnerability_cache: std::collections::HashMap::new(),
        }
    }

    /// Initialize the strategy with bytecode
    /// 
    /// This sets up the tensor ZODA system with the specified bytecode,
    /// creating the vulnerability matrix and code matrices for tensor encoding.
    /// 
    /// # Arguments
    /// * `bytecode` - The EVM bytecode to analyze
    pub fn initialize(&mut self, bytecode: Vec<u8>) -> Result<()> {
        debug!("Initializing ZODA strategy with {} bytes of bytecode", bytecode.len());
        let start_time = Instant::now();
        
        // Reset the vulnerability cache
        self.vulnerability_cache.clear();
        self.accumulated_circuits = 0;
        
        // Initialize the tensor ZODA system through the adapter
        match self.adapter.initialize(bytecode, self.field_size, self.distance_parameter) {
            Ok(_) => {
                self.setup_time = Some(start_time.elapsed());
                debug!("ZODA initialization completed in {:?}", self.setup_time.unwrap());
                Ok(())
            },
            Err(e) => {
                let error_msg = format!("Failed to initialize ZODA adapter: {:?}", e);
                debug!("{}", error_msg);
                Err(anyhow::anyhow!(error_msg))
            },
        }
    }

    /// Accumulate a circuit's constraints and check for vulnerabilities
    /// 
    /// This function:
    /// 1. Analyzes the circuit's constraints for vulnerability patterns
    /// 2. Updates the vulnerability matrix with findings
    /// 3. Maps the circuit's constraints to tensor encoding
    /// 
    /// # Arguments
    /// * `circuit` - Circuit implementing ConstraintSynthesizer
    pub fn accumulate_circuit<C: ConstraintSynthesizer<Fr>>(&mut self, circuit: C) -> Result<()> {
        let circuit_name = std::any::type_name::<C>();
        debug!("Accumulating circuit: {}", circuit_name);
        
        self.accumulated_circuits += 1;
        
        // Process the circuit through the ZODA adapter
        match self.adapter.accumulate(circuit) {
            Ok(_) => {
                // Clear the vulnerability cache as it's now outdated
                self.vulnerability_cache.clear();
                
                debug!("Successfully accumulated circuit #{}", self.accumulated_circuits);
                Ok(())
            },
            Err(e) => {
                let error_msg = format!("Failed to accumulate circuit: {:?}", e);
                debug!("{}", error_msg);
                Err(anyhow::anyhow!(error_msg))
            },
        }
    }

    /// Verify that no vulnerabilities are present
    /// 
    /// This performs a complete verification using the tensor ZODA protocol:
    /// 1. Finalizes the accumulator (encoding the vulnerability matrix)
    /// 2. Uses tensor ZODA verification with sampling
    /// 3. Checks that no vulnerabilities are detected
    pub fn verify(&mut self) -> Result<bool> {
        debug!("Verifying accumulated circuits (count: {})", self.accumulated_circuits);
        
        if self.accumulated_circuits == 0 {
            return Ok(true); // No circuits to verify means no vulnerabilities
        }
        
        let start_time = Instant::now();
        
        // Finalize the accumulator before verification if needed
        if !self.adapter.finalized {
            debug!("Finalizing ZODA accumulator before verification");
            match self.adapter.finalize() {
                Ok(_) => {
                    debug!("Successfully finalized ZODA accumulation");
                },
                Err(e) => {
                    let error_msg = format!("Failed to finalize ZODA accumulation: {:?}", e);
                    debug!("{}", error_msg);
                    return Err(anyhow::anyhow!(error_msg));
                }
            }
        }
        
        // Verify the result using tensor ZODA protocol
        match self.adapter.verify() {
            Ok(result) => {
                self.verification_time = Some(start_time.elapsed());
                info!("ZODA verification completed in {:?}: {}", 
                      self.verification_time.unwrap(), 
                      if result { "No vulnerabilities detected" } else { "Vulnerabilities found" });
                Ok(result)
            },
            Err(e) => {
                let error_msg = format!("Failed to verify ZODA accumulation: {:?}", e);
                debug!("{}", error_msg);
                Err(anyhow::anyhow!(error_msg))
            }
        }
    }

    /// Check if a specific vulnerability is present
    /// 
    /// This provides a more efficient implementation that caches results
    /// for faster repeated checks of the same vulnerability type.
    /// 
    /// # Arguments
    /// * `vuln_type` - The vulnerability type to check (e.g., "reentrancy")
    pub fn has_vulnerability(&self, vuln_type: &str) -> Result<bool> {
        // Check if we have the result cached
        if let Some(&result) = self.vulnerability_cache.get(vuln_type) {
            return Ok(result);
        }
        
        // Otherwise ask the adapter
        match self.adapter.has_vulnerability(vuln_type) {
            Ok(result) => {
                // Cache the result for future queries
                let mut cache = self.vulnerability_cache.clone();
                cache.insert(vuln_type.to_string(), result);
                
                if result {
                    info!("Vulnerability detected: {}", vuln_type);
                } else {
                    debug!("No '{}' vulnerability detected", vuln_type);
                }
                
                Ok(result)
            },
            Err(e) => {
                let error_msg = format!("Failed to check vulnerability {}: {:?}", vuln_type, e);
                debug!("{}", error_msg);
                Err(anyhow::anyhow!(error_msg))
            },
        }
    }
    
    /// Get performance metrics for the ZODA verification process
    pub fn get_metrics(&self) -> (Option<std::time::Duration>, Option<std::time::Duration>, usize) {
        (self.setup_time, self.verification_time, self.accumulated_circuits)
    }
}

/// Enum representing the different accumulation strategies available
#[derive(Clone)]
pub enum AccumulationStrategy {
    /// Groth16-based strategy
    Groth16(Groth16Strategy),
    /// ZODA-based strategy
    ZODA(ZODAStrategy),
}

impl AccumulationStrategy {
    /// Initialize the strategy with bytecode
    pub fn initialize(&mut self, bytecode: Vec<u8>) -> Result<()> {
        match self {
            Self::Groth16(strategy) => strategy.initialize(bytecode),
            Self::ZODA(strategy) => strategy.initialize(bytecode),
        }
    }

    /// Accumulate a circuit's constraints and check for vulnerabilities
    pub fn accumulate_circuit<C: ConstraintSynthesizer<Fr>>(&mut self, circuit: C) -> Result<()> {
        match self {
            Self::Groth16(strategy) => strategy.accumulate_circuit(circuit),
            Self::ZODA(strategy) => strategy.accumulate_circuit(circuit),
        }
    }

    /// Verify that no vulnerabilities are present
    pub fn verify(&mut self) -> Result<bool> {
        match self {
            Self::Groth16(strategy) => strategy.verify(),
            Self::ZODA(strategy) => strategy.verify(),
        }
    }

    /// Check if a specific vulnerability is present
    pub fn has_vulnerability(&self, vuln_type: &str) -> Result<bool> {
        match self {
            Self::Groth16(strategy) => strategy.has_vulnerability(vuln_type),
            Self::ZODA(strategy) => strategy.has_vulnerability(vuln_type),
        }
    }
}

impl fmt::Debug for AccumulationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Groth16(_) => {
                write!(f, "Groth16Strategy")
            },
            Self::ZODA(strategy) => {
                let (setup_time, verification_time, accumulated_circuits) = strategy.get_metrics();
                write!(f, "ZODAStrategy {{ setup_time: {:?}, verification_time: {:?}, accumulated_circuits: {} }}", 
                       setup_time, verification_time, accumulated_circuits)
            },
        }
    }
}

impl AccumulationStrategy {
    /// Create a new AccumulationStrategy with the specified verification strategy
    pub fn new(strategy: VerificationStrategy) -> Self {
        match strategy {
            VerificationStrategy::Groth16 => Self::Groth16(Groth16Strategy::new()),
            VerificationStrategy::ZODA => Self::ZODA(ZODAStrategy::new()),
        }
    }

    /// Create a new ZODA AccumulationStrategy in test mode with smaller dimensions
    /// 
    /// This is useful for testing with simple bytecode that might have very few constraints
    pub fn new_zoda_test_mode() -> Self {
        Self::ZODA(ZODAStrategy::new_test_mode())
    }

    /// Get performance metrics for the strategy
    /// 
    /// Returns (setup_time, verification_time, accumulated_circuits)
    /// 
    /// Note that for Groth16, these metrics are not tracked and will return None/0.
    /// For ZODA, these metrics are tracked and will provide useful information.
    pub fn get_metrics(&self) -> (Option<std::time::Duration>, Option<std::time::Duration>, usize) {
        match self {
            Self::Groth16(_) => (None, None, 0),
            Self::ZODA(strategy) => strategy.get_metrics(),
        }
    }
}
