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
pub mod linear_code;
pub mod multilinear;
pub mod accumulation;
pub mod verification;
pub mod integration;

pub use field::*;
pub use polynomial::*;
pub use linear_code::*;
pub use multilinear::*;
pub use accumulation::*;
pub use verification::*;
pub use integration::*;
