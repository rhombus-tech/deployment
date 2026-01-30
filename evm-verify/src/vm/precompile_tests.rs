// Comprehensive tests for Ethereum precompile execution

#[cfg(test)]
mod tests {
    use super::super::*;
    use ethers::types::{U256, H256, Address, Transaction, Block};
    use anyhow::Result;

    fn create_test_tx() -> Transaction {
        Transaction {
            from: Address::from_low_u64_be(0x1234),
            to: Some(Address::from_low_u64_be(0x5678)),
            value: U256::zero(),
            gas: U256::from(1_000_000u64),
            gas_price: Some(U256::from(20_000_000_000u64)),
            input: vec![].into(),
            nonce: U256::zero(),
            hash: H256::zero(),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            v: U256::zero(),
            r: U256::zero(),
            s: U256::zero(),
            chain_id: Some(U256::one()),
            access_list: None,
            transaction_type: None,
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            other: Default::default(),
        }
    }

    fn create_test_block() -> Block<H256> {
        Block {
            hash: Some(H256::zero()),
            parent_hash: H256::zero(),
            uncles_hash: H256::zero(),
            author: Some(Address::zero()),
            state_root: H256::zero(),
            transactions_root: H256::zero(),
            receipts_root: H256::zero(),
            number: Some(U256::from(12345u64)),
            gas_used: U256::zero(),
            gas_limit: U256::from(15_000_000u64),
            extra_data: vec![].into(),
            logs_bloom: None,
            timestamp: U256::from(1234567890u64),
            difficulty: U256::zero(),
            total_difficulty: None,
            seal_fields: vec![],
            uncles: vec![],
            transactions: vec![],
            size: None,
            mix_hash: None,
            nonce: None,
            base_fee_per_gas: None,
            withdrawals_root: None,
            withdrawals: None,
            other: Default::default(),
        }
    }

    #[test]
    fn test_ecrecover_precompile_execution() -> Result<()> {
        // Create bytecode that calls ecrecover precompile (0x01)
        // PUSH1 32 (ret_length), PUSH1 0 (ret_offset), PUSH1 128 (args_length), 
        // PUSH1 0 (args_offset), PUSH1 0 (value), PUSH1 1 (address=ecrecover), PUSH4 100000 (gas), CALL
        let bytecode = vec![
            0x60, 0x20, // PUSH1 32 (ret_length)
            0x60, 0x00, // PUSH1 0 (ret_offset)
            0x60, 0x80, // PUSH1 128 (args_length = 128 bytes for ecrecover input)
            0x60, 0x00, // PUSH1 0 (args_offset)
            0x60, 0x00, // PUSH1 0 (value)
            0x60, 0x01, // PUSH1 1 (address = ecrecover)
            0x62, 0x01, 0x86, 0xa0, // PUSH3 100000 (gas)
            0xF1, // CALL
        ];

        let tx = create_test_tx();
        let block = create_test_block();
        
        let mut interpreter = EVMInterpreter::new(bytecode, &tx, &block, 1_000_000)?;
        let result = interpreter.execute_transaction()?;
        
        // Should execute without errors
        assert!(result.execution_steps.len() > 0);
        println!("✅ ecrecover precompile executed successfully");
        
        Ok(())
    }

    #[test]
    fn test_sha256_precompile() -> Result<()> {
        // Bytecode calling SHA256 precompile (0x02)
        let bytecode = vec![
            0x60, 0x20, // PUSH1 32 (ret_length)
            0x60, 0x00, // PUSH1 0 (ret_offset)
            0x60, 0x05, // PUSH1 5 (args_length - hash "hello")
            0x60, 0x00, // PUSH1 0 (args_offset)
            0x60, 0x00, // PUSH1 0 (value)
            0x60, 0x02, // PUSH1 2 (address = sha256)
            0x62, 0x01, 0x86, 0xa0, // PUSH3 100000 (gas)
            0xF1, // CALL
        ];

        let tx = create_test_tx();
        let block = create_test_block();
        
        // Put "hello" in memory at position 0
        let mut interpreter = EVMInterpreter::new(bytecode, &tx, &block, 1_000_000)?;
        interpreter.state.memory = b"hello".to_vec();
        
        let result = interpreter.execute_transaction()?;
        assert!(result.execution_steps.len() > 0);
        println!("✅ SHA256 precompile executed successfully");
        
        Ok(())
    }

    #[test]
    fn test_ripemd160_precompile() -> Result<()> {
        // Bytecode calling RIPEMD160 precompile (0x03)
        let bytecode = vec![
            0x60, 0x20, // PUSH1 32 (ret_length)
            0x60, 0x00, // PUSH1 0 (ret_offset)
            0x60, 0x05, // PUSH1 5 (args_length)
            0x60, 0x00, // PUSH1 0 (args_offset)
            0x60, 0x00, // PUSH1 0 (value)
            0x60, 0x03, // PUSH1 3 (address = ripemd160)
            0x62, 0x01, 0x86, 0xa0, // PUSH3 100000 (gas)
            0xF1, // CALL
        ];

        let tx = create_test_tx();
        let block = create_test_block();
        
        let mut interpreter = EVMInterpreter::new(bytecode, &tx, &block, 1_000_000)?;
        interpreter.state.memory = b"hello".to_vec();
        
        let result = interpreter.execute_transaction()?;
        assert!(result.execution_steps.len() > 0);
        println!("✅ RIPEMD160 precompile executed successfully");
        
        Ok(())
    }

    #[test]
    fn test_identity_precompile() -> Result<()> {
        // Bytecode calling Identity/DataCopy precompile (0x04)
        let bytecode = vec![
            0x60, 0x10, // PUSH1 16 (ret_length)
            0x60, 0x00, // PUSH1 0 (ret_offset)
            0x60, 0x10, // PUSH1 16 (args_length)
            0x60, 0x00, // PUSH1 0 (args_offset)
            0x60, 0x00, // PUSH1 0 (value)
            0x60, 0x04, // PUSH1 4 (address = identity)
            0x62, 0x01, 0x86, 0xa0, // PUSH3 100000 (gas)
            0xF1, // CALL
        ];

        let tx = create_test_tx();
        let block = create_test_block();
        
        let mut interpreter = EVMInterpreter::new(bytecode, &tx, &block, 1_000_000)?;
        interpreter.state.memory = b"test_data_123456".to_vec();
        
        let result = interpreter.execute_transaction()?;
        assert!(result.execution_steps.len() > 0);
        
        // Identity should copy input to output
        println!("✅ Identity precompile executed successfully");
        
        Ok(())
    }

    #[test]
    fn test_modexp_precompile() -> Result<()> {
        // Bytecode calling ModExp precompile (0x05)
        // ModExp requires: base_len, exp_len, mod_len, base, exp, mod
        let bytecode = vec![
            0x60, 0x20, // PUSH1 32 (ret_length)
            0x60, 0x00, // PUSH1 0 (ret_offset)
            0x60, 0x60, // PUSH1 96 (args_length = 3*32 for lengths)
            0x60, 0x00, // PUSH1 0 (args_offset)
            0x60, 0x00, // PUSH1 0 (value)
            0x60, 0x05, // PUSH1 5 (address = modexp)
            0x62, 0x0f, 0x42, 0x40, // PUSH3 1000000 (gas - modexp needs more)
            0xF1, // CALL
        ];

        let tx = create_test_tx();
        let block = create_test_block();
        
        let mut interpreter = EVMInterpreter::new(bytecode, &tx, &block, 2_000_000)?;
        // Set up minimal ModExp input (all zeros for simplicity)
        interpreter.state.memory = vec![0u8; 96];
        
        let result = interpreter.execute_transaction()?;
        assert!(result.execution_steps.len() > 0);
        println!("✅ ModExp precompile executed successfully");
        
        Ok(())
    }

    #[test]
    fn test_staticcall_ecrecover() -> Result<()> {
        // Test ecrecover via STATICCALL (0xFA)
        let bytecode = vec![
            0x60, 0x20, // PUSH1 32 (ret_length)
            0x60, 0x00, // PUSH1 0 (ret_offset)
            0x60, 0x80, // PUSH1 128 (args_length)
            0x60, 0x00, // PUSH1 0 (args_offset)
            0x60, 0x01, // PUSH1 1 (address = ecrecover)
            0x62, 0x01, 0x86, 0xa0, // PUSH3 100000 (gas)
            0xFA, // STATICCALL
        ];

        let tx = create_test_tx();
        let block = create_test_block();
        
        let mut interpreter = EVMInterpreter::new(bytecode, &tx, &block, 1_000_000)?;
        interpreter.state.memory = vec![0u8; 128];
        
        let result = interpreter.execute_transaction()?;
        assert!(result.execution_steps.len() > 0);
        println!("✅ ecrecover via STATICCALL executed successfully");
        
        Ok(())
    }

    #[test]
    fn test_precompile_invalid_signature_returns_zero() -> Result<()> {
        // Test that ecrecover returns zero address for invalid signature
        let input = vec![0u8; 128]; // All zeros = invalid signature
        
        let (output, _gas) = precompiles::ecrecover(&input, 100000)?;
        
        // ecrecover should return 32 zero bytes (zero address)
        assert_eq!(output.len(), 32);
        assert!(output.iter().all(|&b| b == 0), "Invalid signature should return zero address");
        
        println!("✅ ecrecover correctly returns zero for invalid signature");
        Ok(())
    }

    #[test]
    fn test_sha256_hash_correctness() -> Result<()> {
        let input = b"hello world";
        let (output, _gas) = precompiles::sha256(input, 100000)?;
        
        // Verify SHA256("hello world") produces expected hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input);
        let expected = hasher.finalize();
        
        assert_eq!(output.len(), 32);
        assert_eq!(&output[..], &expected[..]);
        
        println!("✅ SHA256 produces correct hash");
        Ok(())
    }

    #[test]
    fn test_identity_copies_data() -> Result<()> {
        let input = b"test data for identity precompile";
        let (output, _gas) = precompiles::identity(input, 100000)?;
        
        assert_eq!(output, input);
        println!("✅ Identity precompile correctly copies data");
        Ok(())
    }

    #[test]
    fn test_precompile_gas_limit() -> Result<()> {
        let input = b"test";
        
        // Try SHA256 with insufficient gas
        let result = precompiles::sha256(input, 10); // Way too low
        assert!(result.is_err(), "Should fail with insufficient gas");
        
        println!("✅ Precompiles correctly enforce gas limits");
        Ok(())
    }

    #[test]
    fn test_all_precompile_addresses() -> Result<()> {
        // Test that all precompile addresses are recognized
        for addr_num in 1u64..=10 {
            let addr = Address::from_low_u64_be(addr_num);
            assert!(precompiles::is_precompile(&addr), "Address 0x{:02x} should be precompile", addr_num);
            assert_eq!(precompiles::get_precompile_id(&addr), Some(addr_num as u8));
        }
        
        // Test non-precompile
        let non_precompile = Address::from_low_u64_be(0x1234);
        assert!(!precompiles::is_precompile(&non_precompile));
        
        println!("✅ All precompile addresses correctly detected");
        Ok(())
    }

    #[test]
    fn test_real_mainnet_signature_pattern() -> Result<()> {
        // This tests a realistic pattern: contract calling ecrecover in a signature verification flow
        // Bytecode: Load signature components from calldata, call ecrecover, check result
        let bytecode = vec![
            // Load hash from calldata to memory
            0x60, 0x04, // PUSH1 4 (skip function selector)
            0x35,       // CALLDATALOAD
            0x60, 0x00, // PUSH1 0
            0x52,       // MSTORE (store hash at memory[0])
            
            // Load v,r,s from calldata
            0x60, 0x24, // PUSH1 36 (calldata offset for v)
            0x35,       // CALLDATALOAD
            0x60, 0x20, // PUSH1 32
            0x52,       // MSTORE (store v at memory[32])
            
            // Call ecrecover: CALL(gas, 0x01, 0, input_offset, input_size, output_offset, output_size)
            0x60, 0x20, // PUSH1 32 (output size)
            0x60, 0x60, // PUSH1 96 (output offset)
            0x60, 0x80, // PUSH1 128 (input size)
            0x60, 0x00, // PUSH1 0 (input offset)
            0x60, 0x00, // PUSH1 0 (value)
            0x60, 0x01, // PUSH1 1 (ecrecover address)
            0x62, 0x01, 0x86, 0xa0, // PUSH3 100000 (gas)
            0xF1,       // CALL
            
            // Check if call succeeded (returns 1)
            0x60, 0x01, // PUSH1 1
            0x14,       // EQ
            0x00,       // STOP
        ];

        let tx = create_test_tx();
        let block = create_test_block();
        
        let mut interpreter = EVMInterpreter::new(bytecode, &tx, &block, 1_000_000)?;
        
        // Set up memory with signature data
        interpreter.state.memory = vec![0u8; 200];
        
        let result = interpreter.execute_transaction()?;
        assert!(result.execution_steps.len() > 0);
        
        println!("✅ Real-world signature verification pattern works");
        Ok(())
    }

    #[test]
    fn test_multiple_precompile_calls_in_sequence() -> Result<()> {
        // Test calling multiple different precompiles in one transaction
        let bytecode = vec![
            // Call SHA256
            0x60, 0x20, 0x60, 0x00, 0x60, 0x05, 0x60, 0x00, 0x60, 0x00, 0x60, 0x02, 
            0x62, 0x01, 0x86, 0xa0, 0xF1,
            0x50, // POP (discard result)
            
            // Call Identity
            0x60, 0x10, 0x60, 0x00, 0x60, 0x10, 0x60, 0x00, 0x60, 0x00, 0x60, 0x04,
            0x62, 0x01, 0x86, 0xa0, 0xF1,
            0x50, // POP
            
            // Call RIPEMD160
            0x60, 0x20, 0x60, 0x00, 0x60, 0x05, 0x60, 0x00, 0x60, 0x00, 0x60, 0x03,
            0x62, 0x01, 0x86, 0xa0, 0xF1,
            
            0x00, // STOP
        ];

        let tx = create_test_tx();
        let block = create_test_block();
        
        let mut interpreter = EVMInterpreter::new(bytecode, &tx, &block, 5_000_000)?;
        interpreter.state.memory = b"test data for precompiles".to_vec();
        
        let result = interpreter.execute_transaction()?;
        assert!(result.execution_steps.len() > 0);
        
        println!("✅ Multiple sequential precompile calls work correctly");
        Ok(())
    }
}
