//! Finite field implementation for WARP
//!
//! This module provides the cryptographic field implementations needed for the WARP accumulation scheme.
//! We use the BLS12-381 scalar field for optimal security and compatibility with existing zero-knowledge
//! proof systems.

use std::ops::{Add, Mul, Sub, Neg, AddAssign, MulAssign, SubAssign};
use std::convert::TryFrom;
use rand::{Rng, thread_rng};
use ark_ff::{Field as ArkField, PrimeField};
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
        if self.is_zero() {
            None
        } else {
            // Safe to unwrap since we checked for zero
            Some(WarpField(self.0.inverse().unwrap()))
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
        // Convert u64 to scalar's required exp format
        let exp_fe = BlsScalar::from(exp);
        WarpField(self.0.pow(&exp_fe.into_repr()))
    }
    
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        
        // Try to convert to BlsScalar
        match BlsScalar::from_bytes(&array) {
            Ok(scalar) => Some(WarpField(scalar)),
            Err(_) => None
        }
    }
    
    fn to_bytes(&self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }
    
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

// Implement operator traits for more ergonomic use
impl Add for WarpField {
    type Output = Self;
    
    fn add(self, rhs: Self) -> Self::Output {
        self.add(&rhs)
    }
}

impl AddAssign for WarpField {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(&rhs);
    }
}

impl Mul for WarpField {
    type Output = Self;
    
    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(&rhs)
    }
}

impl MulAssign for WarpField {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(&rhs);
    }
}

impl Sub for WarpField {
    type Output = Self;
    
    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(&rhs)
    }
}

impl SubAssign for WarpField {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(&rhs);
    }
}

impl Neg for WarpField {
    type Output = Self;
    
    fn neg(self) -> Self::Output {
        self.neg()
    }
}

/// Convert a u64 to a field element
impl From<u64> for WarpField {
    fn from(value: u64) -> Self {
        WarpField(BlsScalar::from(value))
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
        let c = a.add(&b);
        assert_eq!(c, WarpField::from(20u64));
        
        // Test multiplication
        let d = a.mul(&b);
        assert_eq!(d, WarpField::from(91u64));
        
        // Test subtraction
        let e = b.sub(&a);
        assert_eq!(e, WarpField::from(6u64));
        
        // Test negation
        let neg_a = a.neg();
        assert_eq!(neg_a.add(&a), WarpField::zero());
        
        // Test inverse
        let a_inv = a.inverse().unwrap();
        assert_eq!(a.mul(&a_inv), WarpField::one());
        
        // Test zero and one
        assert!(WarpField::zero().is_zero());
        assert_eq!(WarpField::one().mul(&a), a);
        
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
        let r1 = WarpField::random();
        let r2 = WarpField::random();
        // Two random elements should be different with overwhelming probability
        assert_ne!(r1, r2);
    }
}
