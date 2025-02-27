use ark_ff::{Field, Zero, PrimeField};
use ethers::types::{H160, H256, U256};

/// Convert bytes to field element
pub fn bytes_to_field<F: Field>(bytes: &[u8]) -> F {
    let mut value = F::zero();
    let mut multiplier = F::one();
    for &byte in bytes {
        value += F::from(byte as u64) * multiplier;
        multiplier *= F::from(256u64);
    }
    value
}

/// Convert address to field element
pub fn address_to_field<F: Field>(address: H160) -> F {
    bytes_to_field(&address.as_bytes())
}

/// Convert storage slot to field element
pub fn slot_to_field<F: Field>(slot: H256) -> F {
    bytes_to_field(&slot.as_bytes())
}

/// Convert value to field element
pub fn value_to_field<F: Field>(value: U256) -> F {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    bytes_to_field(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn test_bytes_to_field() {
        let bytes = vec![1, 2, 3, 4];
        let field = bytes_to_field::<Fr>(&bytes);
        assert!(!field.is_zero());
    }

    #[test]
    fn test_address_to_field() {
        let address = H160::zero();
        let field = address_to_field::<Fr>(address);
        assert!(field.is_zero());
    }

    #[test]
    fn test_slot_to_field() {
        let slot = H256::zero();
        let field = slot_to_field::<Fr>(slot);
        assert!(field.is_zero());
    }

    #[test]
    fn test_value_to_field() {
        let value = U256::zero();
        let field = value_to_field::<Fr>(value);
        assert!(field.is_zero());
    }
}
