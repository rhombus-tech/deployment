// WARP implementation for linear-time accumulation scheme
// This module implements the WARP paper's accumulation scheme
// with BLS12-381 field and KZG polynomial commitments

pub mod field;
pub mod polynomial;
pub mod commitment;
pub mod accumulation;
pub mod verification;
pub mod integration;

#[cfg(test)]
mod tests;
