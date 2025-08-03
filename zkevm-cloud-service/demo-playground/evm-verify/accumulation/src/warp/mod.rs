//! WARP - Linear-Time Accumulation Scheme Implementation
//! 
//! Based on "Linear-Time Accumulation Schemes" (Bünz, Chiesa, Fenzi, Wang; 2025)
//! 
//! This module implements the WARP accumulation scheme, which provides:
//! - Linear-time proving complexity
//! - Logarithmic-time verification
//! - Support for arbitrary linear codes
//! - Plausible post-quantum security via hash-based commitments
//! - Unbounded accumulation depth

pub mod field;
pub mod polynomial;
pub mod commitment;
pub mod verification;
pub mod integration;

#[cfg(test)]
pub mod tests;
