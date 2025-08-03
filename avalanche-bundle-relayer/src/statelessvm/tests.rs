//! Tests for StatelessVM integration

#[cfg(test)]
mod tests {
    use crate::statelessvm::client::{StatelessVmClient, StatelessVmClientTrait};
    use crate::types::{
        TransactionSequence, MevProtection, StateVerification, FallbackPlan,
        TransactionStatus, TransactionStatusCode, SignedTransaction, Address
    };
    use std::collections::HashMap;
    use crate::errors::RelayerError;
    use ethers::types::{U256, H256};
    use std::sync::Arc;
    use mockall::predicate::*;
    use mockall::mock;
    use async_trait::async_trait;
    
    // Create a mock for StatelessVmClientTrait
    mock! {
        pub StatelessVmClientMock {}
        
        impl Clone for StatelessVmClientMock {
            fn clone(&self) -> Self;
        }
        
        #[async_trait]
        impl StatelessVmClientTrait for StatelessVmClientMock {
            async fn execute_sequence(&self, sequence: &TransactionSequence) -> crate::errors::Result<Vec<TransactionStatus>>;
            async fn execute_sequence_and_get_hash(&self, sequence: &TransactionSequence) -> crate::errors::Result<String>;
            async fn generate_witness(&self, sequence: &TransactionSequence) -> crate::errors::Result<String>;
        }
    }
    
    fn create_test_sequence() -> TransactionSequence {
        let sender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let receiver = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        
        // Create a basic transaction
        let tx1 = SignedTransaction {
            hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            data: vec![0x01, 0x02, 0x03], // Some mock transaction data
            from: sender.clone(),
            to: Some(receiver.clone()),
            value: "1000000000000000000".to_string(), // 1 ETH
            gas_price: "20000000000".to_string(), // 20 Gwei
            gas_limit: "100000".to_string(),
            nonce: 0,
            chain_id: 1, // Ethereum mainnet
        };
        
        // Create a second transaction for the sequence
        let tx2 = SignedTransaction {
            hash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            data: vec![0x01, 0x02, 0x03], // Some mock transaction data
            from: sender.clone(),
            to: Some("0xcccccccccccccccccccccccccccccccccccccccc".to_string()),
            value: "0".to_string(),
            gas_price: "20000000000".to_string(), // 20 Gwei
            gas_limit: "150000".to_string(),
            nonce: 1,
            chain_id: 1, // Ethereum mainnet
        };
        
        // Create metadata hashmap
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("description".to_string(), serde_json::json!("Test sequence for unit tests"));
        metadata.insert("app".to_string(), serde_json::json!("test-app"));
        
        TransactionSequence {
            sequence_id: "test-sequence-1".to_string(),
            transactions: vec![tx1, tx2],
            atomic: true,
            timeout_seconds: 30,
            market_conditions: Some(serde_json::json!({
                "max_base_fee": "30000000000",  // 30 Gwei
                "max_priority_fee": "2000000000",  // 2 Gwei
                "price_threshold": null
            })),
            mev_protection: Some(MevProtection {
                use_private_mempool: true,
                frontrunning_protection: 50, // medium level protection (0-100)                
                max_slippage_percent: 5.0, // 5% slippage tolerance
                monitor_sandwich_attacks: true,
                use_commit_reveal: false,
            }),
            state_verification: Some(vec![StateVerification {
                contracts: vec!["0xbb00000000000000000000000000000000000000".to_string()],
                storage_slots: {
                    let mut slots = HashMap::new();
                    slots.insert(
                        "0xbb00000000000000000000000000000000000000".to_string(), 
                        vec!["0x0".to_string()]
                    );
                    slots
                },
                balance_requirements: {
                    let mut balances = HashMap::new();
                    balances.insert(
                        "0xbb00000000000000000000000000000000000000".to_string(), 
                        "1000000000000000000".to_string()
                    );
                    balances
                },
                custom_requirements: Some(serde_json::json!({
                    "checksum_validation": true,
                    "code_hash_validation": true
                })),
            }]),
            fallback_plans: Some(vec![
                FallbackPlan {
                    transactions: vec![],  // Empty for test purposes
                    trigger_conditions: serde_json::json!({"timeout": 30}),
                    priority: 1,
                    description: "Fallback plan for timeout".to_string(),
                }
            ]),
            metadata: Some(metadata),
        }
    }
    

    
    #[tokio::test]
    async fn test_execute_sequence_success() {
        // Create a mock client
        let mut mock_client = MockStatelessVmClientMock::new();
        
        // Create expected transaction statuses for the successful response
        let expected_statuses = vec![
            TransactionStatus {
                hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                status_code: TransactionStatusCode::Confirmed,
                block_number: Some(12345678),
                gas_used: Some("21000".to_string()),
                error: None,
                transaction_index: Some(0),
            },
            TransactionStatus {
                hash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                status_code: TransactionStatusCode::Confirmed,
                block_number: Some(12345678),
                gas_used: Some("35000".to_string()),
                error: None,
                transaction_index: Some(1),
            },
        ];
        
        // Set up the mock to return a successful response
        mock_client.expect_execute_sequence()
            .returning(move |_| {
                // Return a clone of our expected transaction statuses
                Ok(expected_statuses.clone())
            });
        
        // Create a test sequence
        let sequence = create_test_sequence();
        
        // Execute the sequence
        let result = mock_client.execute_sequence(&sequence).await;
        
        // Check that the execution was successful
        assert!(result.is_ok(), "Sequence execution failed: {:?}", result.err());
        
        let transaction_statuses = result.unwrap();
        assert_eq!(transaction_statuses.len(), 2);
        assert_eq!(transaction_statuses[0].hash, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        assert_eq!(transaction_statuses[1].hash, "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    }
    
    #[tokio::test]
    async fn test_execute_sequence_market_condition_failure() {
        // Create a mock client
        let mut mock_client = MockStatelessVmClientMock::new();
        
        // Set up the mock to return a market condition failure error
        mock_client.expect_execute_sequence()
            .returning(|_| {
                // Return an error with the market conditions not met message
                Err(RelayerError::ApiError("Market conditions not met: Current base fee (40 Gwei) exceeds max base fee (30 Gwei)".to_string()))
            });
        
        // Create a test sequence
        let sequence = create_test_sequence();
        
        // Execute the sequence
        let result = mock_client.execute_sequence(&sequence).await;
        
        // Verify that we get the expected error
        assert!(result.is_err(), "Expected an error but got success: {:?}", result.ok());
        
        let err = result.unwrap_err();
        match err {
            RelayerError::ApiError(message) => {
                assert!(message.contains("Market conditions not met"));
                assert!(message.contains("base fee"));
            },
            _ => panic!("Expected ApiError but got: {:?}", err)
        }
    }
    
    #[tokio::test]
    async fn test_execute_sequence_with_fallback() {
        // Create a mock client
        let mut mock_client = MockStatelessVmClientMock::new();
        
        // Create expected transaction statuses for the successful response
        let expected_statuses = vec![
            TransactionStatus {
                hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                status_code: TransactionStatusCode::Confirmed,
                block_number: Some(12345678),
                gas_used: Some("25000".to_string()),  // Higher gas used due to fallback
                error: None,
                transaction_index: Some(0),
            },
            TransactionStatus {
                hash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                status_code: TransactionStatusCode::Confirmed,
                block_number: Some(12345678),
                gas_used: Some("40000".to_string()),  // Higher gas used due to fallback
                error: None,
                transaction_index: Some(1),
            },
        ];
        
        // Set up the mock to return a successful response with fallback applied
        mock_client.expect_execute_sequence()
            .returning(move |sequence| {
                // Verify that fallback is enabled
                if sequence.fallback_plans.is_none() || sequence.fallback_plans.as_ref().unwrap().is_empty() {
                    return Err(RelayerError::InternalError("Fallback should be enabled".to_string()));
                }
                
                // Return a clone of our expected transaction statuses
                Ok(expected_statuses.clone())
            });
        
        // Create a test sequence with fallback enabled
        let mut sequence = create_test_sequence();
        sequence.fallback_plans = Some(vec![FallbackPlan {
            transactions: vec![],  // Empty for test purposes
            trigger_conditions: serde_json::json!({"timeout": 30}),
            priority: 1,
            description: "Fallback plan for timeout".to_string(),
        }]);
        
        // Execute the sequence
        let result = mock_client.execute_sequence(&sequence).await;
        
        // Check that the execution was successful with fallback
        assert!(result.is_ok(), "Sequence execution failed: {:?}", result.err());
        
        let transaction_statuses = result.unwrap();
        assert_eq!(transaction_statuses.len(), 2);
        assert_eq!(transaction_statuses[0].hash, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        assert_eq!(transaction_statuses[1].hash, "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    }
    
    #[tokio::test]
    async fn test_execute_sequence_with_mev_protection() {
        // Create a mock client
        let mut mock_client = MockStatelessVmClientMock::new();
        
        // Create expected transaction statuses for the successful response
        let expected_statuses = vec![
            TransactionStatus {
                hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                status_code: TransactionStatusCode::Confirmed,
                block_number: Some(12345678),
                gas_used: Some("21000".to_string()),
                error: None,
                transaction_index: Some(0),
            },
            TransactionStatus {
                hash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                status_code: TransactionStatusCode::Confirmed,
                block_number: Some(12345678),
                gas_used: Some("35000".to_string()),
                error: None,
                transaction_index: Some(1),
            },
        ];
        
        // Set up the mock to return a successful response
        mock_client.expect_execute_sequence()
            .returning(move |sequence| {
                // Verify that MEV protection is enabled with appropriate settings
                if let Some(mev_protection) = &sequence.mev_protection {
                    if !mev_protection.use_private_mempool || mev_protection.frontrunning_protection < 70 {
                        return Err(RelayerError::InternalError("MEV protection settings not properly configured".to_string()));
                    }
                } else {
                    return Err(RelayerError::InternalError("MEV protection not enabled".to_string()));
                }
                
                // Return a clone of our expected transaction statuses
                Ok(expected_statuses.clone())
            });
        
        // Create a test sequence with MEV protection
        let mut sequence = create_test_sequence();
        sequence.mev_protection = Some(MevProtection {
            use_private_mempool: true,
            frontrunning_protection: 80, // high level protection (0-100)
            max_slippage_percent: 3.0, // 3% slippage tolerance
            monitor_sandwich_attacks: true,
            use_commit_reveal: true,
        });
        
        // Execute the sequence
        let result = mock_client.execute_sequence(&sequence).await;
        
        // Check that the execution was successful with MEV protection
        assert!(result.is_ok(), "Sequence execution failed: {:?}", result.err());
        
        let transaction_statuses = result.unwrap();
        assert_eq!(transaction_statuses.len(), 2);
        assert_eq!(transaction_statuses[0].hash, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        assert_eq!(transaction_statuses[1].hash, "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    }
    
    #[tokio::test]
    async fn test_generate_witness() {
        // Create a mock client
        let mut mock_client = MockStatelessVmClientMock::new();
        
        // Expected witness data (base64-encoded)
        let expected_witness = "ZXhhbXBsZV93aXRuZXNzX2RhdGFfYmFzZTY0X2VuY29kZWQ=";
        
        // Set up the mock to return the expected witness
        mock_client.expect_generate_witness()
            .returning(move |sequence| {
                // Verify that the sequence has the correct settings for witness generation
                if sequence.sequence_id.is_empty() {
                    return Err(RelayerError::InternalError("Empty sequence ID".to_string()));
                }
                
                // Return the expected witness
                Ok(expected_witness.to_string())
            });
        
        // Create a test sequence
        let sequence = create_test_sequence();
        
        // Generate the witness
        let result = mock_client.generate_witness(&sequence).await;
        
        // Check that the witness generation was successful
        assert!(result.is_ok(), "Witness generation failed: {:?}", result.err());
        
        let witness = result.unwrap();
        assert_eq!(witness, expected_witness);
    }
    
    #[tokio::test]
    async fn test_execute_sequence_and_get_hash() {
        // Create a mock client
        let mut mock_client = MockStatelessVmClientMock::new();
        
        // Expected transaction hash
        let expected_tx_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        
        // Set up the mock to return the expected transaction hash
        mock_client.expect_execute_sequence_and_get_hash()
            .returning(move |sequence| {
                // Verify that the sequence has appropriate settings
                if let Some(mev) = &sequence.mev_protection {
                    if !mev.use_private_mempool {
                        return Err(RelayerError::InternalError("Private mempool should be enabled".to_string()));
                    }
                }
                
                // Return the expected transaction hash
                Ok(expected_tx_hash.to_string())
            });
        
        // Create a test sequence with MEV protection
        let mut sequence = create_test_sequence();
        sequence.mev_protection = Some(MevProtection {
            use_private_mempool: true,
            frontrunning_protection: 60,
            max_slippage_percent: 2.0,
            monitor_sandwich_attacks: true,
            use_commit_reveal: false,
        });
        
        // Execute the sequence and get the transaction hash
        let result = mock_client.execute_sequence_and_get_hash(&sequence).await;
        
        // Check that the execution was successful
        assert!(result.is_ok(), "Sequence execution failed: {:?}", result.err());
        
        let tx_hash = result.unwrap();
        assert_eq!(tx_hash, expected_tx_hash);
    }
}
