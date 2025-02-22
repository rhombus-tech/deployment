use ark_ff::{Field, PrimeField, Zero};
use ethers::types::{Address, H256, U256, H160};

/// Convert bytes to field element
pub fn bytes_to_field<F: Field + Zero>(bytes: &[u8]) -> F {
    let mut value = F::zero();
    for &byte in bytes {
        value = value * F::from(256u64) + F::from(byte as u64);
    }
    value
}

/// Convert address to field element
pub fn address_to_field<F: Field + Zero>(address: Address) -> F {
    bytes_to_field(address.as_bytes())
}

/// Convert storage slot to field element
pub fn slot_to_field<F: Field + Zero>(slot: H256) -> F {
    bytes_to_field(slot.as_bytes())
}

/// Convert U256 value to field element
pub fn value_to_field<F: Field + Zero>(value: U256) -> F {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    bytes_to_field(&bytes)
}

/// Convert U256 to field element
pub fn value_to_field_new<F: Field + Zero>(value: U256) -> F {
    let mut result = F::zero();
    let mut base = F::one();
    
    for i in 0..4 {
        let limb = value.0[i];
        for j in 0..64 {
            if (limb >> j) & 1 == 1 {
                result += base;
            }
            base = base + base;
        }
    }
    
    result
}

/// Convert H160 address to field element
pub fn address_to_field_new<F: Field + Zero>(address: H160) -> F {
    let mut result = F::zero();
    let mut base = F::one();
    
    let bytes = address.as_bytes();
    for byte in bytes {
        for j in 0..8 {
            if (byte >> j) & 1 == 1 {
                result += base;
            }
            base = base + base;
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn test_bytes_to_field() {
        let bytes = [1, 2, 3, 4];
        let field = bytes_to_field::<Fr>(&bytes);
        assert!(field != Fr::zero());
    }

    #[test]
    fn test_address_to_field() {
        let address = Address::zero();
        let field = address_to_field::<Fr>(address);
        assert_eq!(field, Fr::zero());
    }

    #[test]
    fn test_slot_to_field() {
        let slot = H256::zero();
        let field = slot_to_field::<Fr>(slot);
        assert_eq!(field, Fr::zero());
    }

    #[test]
    fn test_value_to_field() {
        let value = U256::from(1234);
        let field = value_to_field::<Fr>(value);
        assert!(field != Fr::zero());
    }

    #[test]
    fn test_value_to_field_new() {
        let value = U256::from(42);
        let field = value_to_field_new::<Fr>(value);
        assert!(!field.is_zero());
    }

    #[test]
    fn test_address_to_field_new() {
        let address = H160::random();
        let field = address_to_field_new::<Fr>(address);
        assert!(!field.is_zero());
    }
}
