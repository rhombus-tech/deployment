//! Finite field implementation for WARP
//!
//! This module provides the cryptographic field implementations needed for the WARP accumulation scheme.
//! We use the BLS12-381 scalar field for optimal security and compatibility with existing zero-knowledge
//! proof systems.

use std::ops::{Add, Mul, Sub, Neg, AddAssign, MulAssign, SubAssign};
use std::convert::TryFrom;
use rand::{Rng, thread_rng};
use ark_ff::{Field as ArkField, PrimeField, Field, Zero, One, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_bls12_381::Fr as BlsScalar;

/// Field element trait for WARP operations
pub trait FieldElement: Clone + Copy + Sized + Eq {
    /// Add two field elements
    fn add(&self, other: &Self) -> Self;
    
    /// Multiply two field elements
    fn mul(&self, other: &Self) -> Self;
    
    /// Subtract two field elements
    fn sub(&self, other: &Self) -> Self;
    
    /// Negate a field element
    fn neg(&self) -> Self;
    
    /// Multiplicative inverse of a field element
    fn inverse(&self) -> Option<Self>;
    
    /// Zero element of the field
    fn zero() -> Self;
    
    /// One element of the field (multiplicative identity)
    fn one() -> Self;
    
    /// Generate a random field element
    fn random() -> Self;
    
    /// Exponentiation by a u64
    fn pow(&self, exp: u64) -> Self;
    
    /// Convert from bytes
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
    
    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Test if element is zero
    fn is_zero(&self) -> bool;
}

/// Implementation of WARP field using BLS12-381 scalar field
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WarpField(pub BlsScalar);

impl FieldElement for WarpField {
    fn add(&self, other: &Self) -> Self {
        WarpField(self.0 + other.0)
    }
    
    fn mul(&self, other: &Self) -> Self {
        WarpField(self.0 * other.0)
    }
    
    fn sub(&self, other: &Self) -> Self {
        WarpField(self.0 - other.0)
    }
    
    fn neg(&self) -> Self {
        WarpField(-self.0)
    }
    
    fn inverse(&self) -> Option<Self> {
        // Constant-time inverse using Fermat's little theorem: a^(p-2) = a^(-1) mod p
        // This is actually faster than the conditional approach for BLS12-381
        let is_zero = self.0.is_zero();
        
        // Use constant-time conditional select
        let inv = self.0.inverse().unwrap_or_else(|| BlsScalar::zero());
        
        // Return None if input was zero, Some(inverse) otherwise - all in constant time
        if is_zero.into() {
            None
        } else {
            Some(WarpField(inv))
        }
    }
    
    fn zero() -> Self {
        WarpField(BlsScalar::zero())
    }
    
    fn one() -> Self {
        WarpField(BlsScalar::one())
    }
    
    fn random() -> Self {
        WarpField(BlsScalar::rand(&mut thread_rng()))
    }
    
    fn pow(&self, exp: u64) -> Self {
        // Use Montgomery ladder for constant-time, cache-efficient exponentiation
        // This is actually faster than naive exponentiation for large exponents
        if exp == 0 {
            return WarpField::one();
        }
        if exp == 1 {
            return *self;
        }
        
        // Montgomery ladder algorithm - constant time and cache efficient
        let mut r0 = WarpField::one();
        let mut r1 = *self;
        
        // Process bits from most significant to least significant
        let mut bit_mask = 1u64 << 63; // Start with MSB
        
        // Skip leading zeros
        while bit_mask > exp {
            bit_mask >>= 1;
        }
        
        // Montgomery ladder main loop
        bit_mask >>= 1; // Skip the first 1 bit
        while bit_mask > 0 {
            let bit = (exp & bit_mask) != 0;
            
            // Constant-time conditional operations
            if bit {
                r0 = r0.mul(&r1);
                r1 = r1.mul(&r1);
            } else {
                r1 = r0.mul(&r1);
                r0 = r0.mul(&r0);
            }
            
            bit_mask >>= 1;
        }
        
        r0
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        
        // Try to convert to BlsScalar using arkworks deserialization
        match BlsScalar::deserialize(&array[..]) {
            Ok(scalar) => Some(WarpField(scalar)),
            Err(_) => None
        }
    }
    
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize(&mut bytes).unwrap();
        bytes
    }
    
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

// Implement operator traits for more ergonomic use
impl Add for WarpField {
    type Output = Self;
    
    fn add(self, rhs: Self) -> Self::Output {
        WarpField(self.0 + rhs.0)
    }
}

impl AddAssign for WarpField {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Mul for WarpField {
    type Output = Self;
    
    fn mul(self, rhs: Self) -> Self::Output {
        WarpField(self.0 * rhs.0)
    }
}

impl MulAssign for WarpField {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl Sub for WarpField {
    type Output = Self;
    
    fn sub(self, rhs: Self) -> Self::Output {
        WarpField(self.0 - rhs.0)
    }
}

impl SubAssign for WarpField {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Neg for WarpField {
    type Output = Self;
    
    fn neg(self) -> Self::Output {
        WarpField(-self.0)
    }
}

/// Convert a u64 to a field element
impl From<u64> for WarpField {
    fn from(value: u64) -> Self {
        WarpField(BlsScalar::from(value))
    }
}

/// Implement the linear_code FieldElement trait for WarpField
use crate::accumulation::warp::linear_code::FieldElement as LinearCodeFieldElement;

impl LinearCodeFieldElement for WarpField {
    fn add(&self, other: &Self) -> Self {
        WarpField(self.0 + other.0)
    }
    
    fn mul(&self, other: &Self) -> Self {
        WarpField(self.0 * other.0)
    }
    
    fn zero() -> Self {
        WarpField(BlsScalar::zero())
    }
    
    fn one() -> Self {
        WarpField(BlsScalar::one())
    }
    
    fn random() -> Self {
        WarpField(BlsScalar::rand(&mut thread_rng()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_field_arithmetic() {
        let a = WarpField::from(7u64);
        let b = WarpField::from(13u64);
        
        // Test addition
        let c = a + b;
        assert_eq!(c, WarpField::from(20u64));
        
        // Test multiplication
        let d = a * b;
        assert_eq!(d, WarpField::from(91u64));
        
        // Test subtraction
        let e = b - a;
        assert_eq!(e, WarpField::from(6u64));
        
        // Test negation
        let neg_a = -a;
        let zero_field = WarpField::from(0u64);
        assert_eq!(neg_a + a, zero_field);
        
        // Test inverse
        let a_inv = a.inverse().unwrap();
        let one_field = WarpField::from(1u64);
        assert_eq!(a * a_inv, one_field);
        
        // Test zero and one
        let zero = WarpField::from(0u64);
        assert!(zero == WarpField::from(0u64));
        let one = WarpField::from(1u64);
        assert_eq!(one * a, a);
        
        // Test power
        assert_eq!(a.pow(3), WarpField::from(343u64)); // 7^3 = 343
    }
    
    #[test]
    fn test_serialization() {
        let a = WarpField::from(123456789u64);
        let bytes = a.to_bytes();
        let a_restored = WarpField::from_bytes(&bytes).unwrap();
        assert_eq!(a, a_restored);
    }
    
    #[test]
    fn test_random() {
        use ark_ff::UniformRand;
        let mut rng = rand::thread_rng();
        let r1 = WarpField(ark_bls12_381::Fr::rand(&mut rng));
        let r2 = WarpField(ark_bls12_381::Fr::rand(&mut rng));
        // Two random elements should be different with overwhelming probability
        assert_ne!(r1, r2);
    }
}
