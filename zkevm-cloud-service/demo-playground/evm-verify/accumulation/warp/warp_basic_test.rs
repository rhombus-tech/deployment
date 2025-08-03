use ark_bls12_381::Fr as BlsScalar;
use ark_ff::{Field, One, Zero};
use std::ops::{Add, Mul, Sub, Div};

// A simplified version of WarpField for direct testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestWarpField(BlsScalar);

impl TestWarpField {
    pub fn new(value: BlsScalar) -> Self {
        Self(value)
    }
    
    pub fn from(value: u64) -> Self {
        Self(BlsScalar::from(value))
    }
    
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Self)
    }
}

impl Zero for TestWarpField {
    fn zero() -> Self {
        Self(BlsScalar::zero())
    }
    
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl One for TestWarpField {
    fn one() -> Self {
        Self(BlsScalar::one())
    }
}

impl Add for TestWarpField {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl Sub for TestWarpField {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl Mul for TestWarpField {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl Div for TestWarpField {
    type Output = Self;
    
    fn div(self, other: Self) -> Self {
        Self(self.0 * other.0.inverse().unwrap())
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_arithmetic() {
        let a = TestWarpField::from(5);
        let b = TestWarpField::from(3);
        
        // Addition
        assert_eq!(a + b, TestWarpField::from(8));
        
        // Subtraction
        assert_eq!(a - b, TestWarpField::from(2));
        
        // Multiplication
        assert_eq!(a * b, TestWarpField::from(15));
        
        // Identities
        assert_eq!(a + TestWarpField::zero(), a);
        assert_eq!(a * TestWarpField::one(), a);
        
        // Inverse and division
        let b_inv = b.inverse().unwrap();
        assert_eq!(b * b_inv, TestWarpField::one());
    }
    
    #[test]
    fn test_field_properties() {
        // Commutativity
        let a = TestWarpField::from(7);
        let b = TestWarpField::from(11);
        
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);
        
        // Associativity
        let c = TestWarpField::from(13);
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!((a * b) * c, a * (b * c));
        
        // Distributivity
        assert_eq!(a * (b + c), a * b + a * c);
    }
}

fn main() {
    println!("Running basic WARP field tests...");
    tests::test_basic_arithmetic();
    tests::test_field_properties();
    println!("All tests passed!");
}
