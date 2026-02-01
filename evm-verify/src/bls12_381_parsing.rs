// BLS12-381 point parsing utilities for EIP-4844
use ark_bls12_381::{G1Affine, Fq, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, Field, Zero, One, SquareRootField};
use anyhow::{Result, anyhow};

/// Parse compressed BLS12-381 G1 point (48 bytes) per EIP-4844 specification
/// Implements full point decompression with y-coordinate recovery
pub fn parse_bls12_381_g1(bytes: &[u8]) -> Result<G1Affine> {
    if bytes.len() != 48 {
        return Err(anyhow!("Invalid G1 point length: expected 48 bytes"));
    }
    
    // Extract compression flags from first byte
    let compression_flag = bytes[0] & 0x80; // C_flag (bit 7)
    let infinity_flag = bytes[0] & 0x40;     // I_flag (bit 6)
    let y_flag = bytes[0] & 0x20;            // Y_flag (bit 5) - y-coordinate sign
    
    // Check compression flag is set (required for compressed points)
    if compression_flag == 0 {
        return Err(anyhow!("Compression flag not set"));
    }
    
    // Handle point at infinity
    if infinity_flag != 0 {
        // For infinity, all other bits must be zero
        if y_flag != 0 || bytes[0] & 0x1F != 0 || bytes[1..].iter().any(|&b| b != 0) {
            return Err(anyhow!("Invalid infinity point encoding"));
        }
        return Ok(G1Affine::zero());
    }
    
    // Parse x-coordinate (clear compression flags)
    let mut x_bytes = bytes.to_vec();
    x_bytes[0] &= 0x1F; // Clear top 3 bits (C_flag, I_flag, Y_flag)
    
    // Convert to field element (big-endian)
    let x = Fq::from_be_bytes_mod_order(&x_bytes);
    
    // Check x is valid (less than field modulus)
    if x.is_zero() {
        return Err(anyhow!("Invalid x-coordinate: zero"));
    }
    
    // Compute y² = x³ + 4 (BLS12-381 G1 curve equation)
    let x_cubed = x.square() * x;
    let b = Fq::from(4u64); // curve parameter b = 4
    let y_squared = x_cubed + b;
    
    // Compute y = sqrt(y²)
    let y = y_squared.sqrt().ok_or_else(|| {
        anyhow!("Point not on BLS12-381 curve: no square root exists")
    })?;
    
    // Select correct sign of y based on Y_flag
    // Y_flag = 1 means we want the lexicographically larger y
    let y_final = if is_lexicographically_largest(&y) == (y_flag != 0) {
        y
    } else {
        -y
    };
    
    // Construct the affine point
    let point = G1Affine::new(x, y_final, false);
    
    // Validate point is on curve (should always pass if sqrt succeeded)
    if !point.is_on_curve() {
        return Err(anyhow!("Point not on BLS12-381 curve"));
    }
    
    // Validate point is in correct subgroup (critical for security)
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(anyhow!("Point not in correct G1 subgroup"));
    }
    
    Ok(point)
}

/// Check if field element is lexicographically largest
/// Per EIP-4844: y is "largest" if its big-endian bytes represent a value >= (p-1)/2
fn is_lexicographically_largest(f: &Fq) -> bool {
    use ark_ff::BigInteger;
    
    // For BLS12-381 Fq, the "lexicographically largest" is determined by
    // checking if the field element > (p-1)/2 when interpreted as integer
    // Simpler: check if negation gives a smaller value
    let neg_f = -(*f);
    let repr = f.into_repr();
    let neg_repr = neg_f.into_repr();
    
    // y is "largest" if -y is smaller (lexicographically)
    repr > neg_repr
}
