use anyhow::Result;

/// Memory safety property verification
pub mod memory;
/// EVM bytecode analysis
pub mod bytecode;
/// Pipeline for analyzing EVM bytecode
pub mod pipeline;
/// Mathematical failure detection for algorithmic stablecoin
pub mod mathematical_failure_detector;
/// Ultimate autonomous stablecoin operation engine
pub mod autonomous_stablecoin_engine;
/// Autonomous operational components
pub mod autonomous_components;
/// Mathematical stability verification for algorithmic stablecoin
pub mod stability;
/// Game theory and economic verification for algorithmic stablecoin
pub mod game_theory;
/// Economic bounds and anti-death spiral protection
pub mod economic_bounds;
/// Oracle-independent DEX price verification
pub mod dex_price_verifier;
/// Cross-chain bridge risk analysis
pub mod cross_chain_risk;
/// Systemic market risk and stress testing
pub mod systemic_risk;
/// Emergency recovery mechanism verification
pub mod recovery_mechanism;
/// Death spiral prevention and confidence analysis
pub mod death_spiral_prevention;
/// Peg stability and recovery mechanisms
pub mod peg_stability;
/// Reserve adequacy and diversification analysis
pub mod reserve_adequacy;
/// Ultimate oracle-free mathematical stability system
pub mod ultimate_stability_system;
/// High-Frequency Trading Execution Engine with advanced mathematical models
pub mod hft_execution_engine;

pub use memory::MemoryAnalyzer;
pub use bytecode::BytecodeAnalyzer;
pub use pipeline::AnalysisPipeline;

// Stablecoin verification analyzers
pub use stability::StabilityAnalyzer;
pub use game_theory::GameTheoryAnalyzer;
pub use economic_bounds::EconomicBoundsAnalyzer;
pub use dex_price_verifier::DEXPriceVerifier;
pub use cross_chain_risk::CrossChainRiskAnalyzer;
pub use systemic_risk::SystemicRiskAnalyzer;
pub use recovery_mechanism::RecoveryMechanismAnalyzer;
pub use death_spiral_prevention::DeathSpiralPreventionAnalyzer;
pub use peg_stability::PegStabilityAnalyzer;
pub use reserve_adequacy::ReserveAdequacyAnalyzer;
pub use ultimate_stability_system::UltimateStabilitySystem;
pub use mathematical_failure_detector::MathematicalFailureDetector;
pub use autonomous_stablecoin_engine::AutonomousStablecoinEngine;
pub use hft_execution_engine::HFTExecutionEngine;

#[cfg(test)]
mod tests;

/// Common trait for all EVM properties that can be verified
pub trait Property {
    type Proof;
    
    /// Verify a property for a given EVM bytecode
    fn verify(&self, bytecode: &[u8]) -> Result<Self::Proof>;
}
