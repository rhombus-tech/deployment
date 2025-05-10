#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        let token = TestAlkane::default();
        
        // Mock the initialization
        let token_units = 1000000;
        let value_per_mint = 1000;
        let cap = 1000;
        let name = u128::from_le_bytes(*b"TestToken\0\0\0\0\0\0\0\0");
        let symbol = u128::from_le_bytes(*b"TTK\0\0\0\0\0\0\0\0\0\0\0\0\0");
        
        // Set values directly to simulate initialization
        token.set_value_per_mint(value_per_mint);
        token.set_cap(cap);
        token.set_name_and_symbol(name, symbol);
        token.set_total_supply(token_units);
        token.set_initialized();
        
        // Verify the values were set correctly
        assert_eq!(token.value_per_mint(), value_per_mint);
        assert_eq!(token.cap(), cap);
        assert_eq!(token.name(), "TestToken");
        assert_eq!(token.symbol(), "TTK");
        assert_eq!(token.total_supply(), token_units);
        assert_eq!(token.minted(), 0);
        assert!(token.is_initialized());
    }
    
    #[test]
    fn test_mint() {
        let token = TestAlkane::default();
        
        // Initialize the token
        let token_units = 1000000;
        let value_per_mint = 1000;
        let cap = 10;
        token.set_value_per_mint(value_per_mint);
        token.set_cap(cap);
        token.set_total_supply(token_units);
        token.set_initialized();
        
        // Perform minting operations
        for i in 0..cap {
            token.increase_total_supply(value_per_mint).unwrap();
            token.increment_mint().unwrap();
            assert_eq!(token.minted(), i + 1);
            assert_eq!(token.total_supply(), token_units + value_per_mint * (i + 1));
        }
        
        // Verify mint cap is enforced
        assert_eq!(token.minted(), cap);
    }
    
    #[test]
    fn test_trim() {
        let value = u128::from_le_bytes(*b"Test\0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(trim(value), "Test");
    }
}
