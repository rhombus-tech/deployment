use ethers::types::{H256, U256};
use rlp::RlpStream;
use hex::FromHex;
use anyhow::Result;

/// Storage proof for a specific storage slot
#[derive(Debug, Clone)]
pub struct StorageProof {
    /// Storage value
    pub value: U256,
    /// Merkle proof nodes
    pub proof: Vec<Vec<u8>>,
}

impl StorageProof {
    /// Verify the storage proof against a storage root
    pub fn verify(&self, storage_root: H256, slot: H256) -> Result<bool> {
        let value_bytes = if self.value == U256::zero() {
            vec![]
        } else {
            let mut bytes = [0u8; 32];
            self.value.to_big_endian(&mut bytes);
            bytes.to_vec()
        };
        
        super::trie::verify_proof(
            storage_root,
            slot.as_bytes(),
            &self.proof,
            &value_bytes,
        )
    }
}

/// Account proof containing account data and merkle proof
#[derive(Debug, Clone)]
pub struct AccountProof {
    /// Account nonce
    pub nonce: U256,
    /// Account balance
    pub balance: U256,
    /// Storage root
    pub storage_root: H256,
    /// Code hash
    pub code_hash: H256,
    /// Merkle proof nodes
    pub proof: Vec<Vec<u8>>,
}

impl AccountProof {
    /// Verify the account proof against a state root
    pub fn verify(&self, state_root: H256, address: H256) -> Result<bool> {
        let mut stream = RlpStream::new_list(4);
        stream.append(&self.nonce);
        stream.append(&self.balance);
        stream.append(&self.storage_root);
        stream.append(&self.code_hash);
        
        super::trie::verify_proof(
            state_root,
            address.as_bytes(),
            &self.proof,
            &stream.out(),
        )
    }
}

/// Block verification data
#[derive(Debug, Clone)]
pub struct BlockVerification {
    /// Block number
    pub number: U256,
    /// Block hash
    pub hash: H256,
    /// State root
    pub state_root: H256,
    /// Transactions root
    pub transactions_root: H256,
    /// Receipts root
    pub receipts_root: H256,
}

impl BlockVerification {
    /// Create block verification from hex strings
    pub fn from_hex(
        number: &str,
        hash: &str,
        state_root: &str,
        transactions_root: &str,
        receipts_root: &str,
    ) -> Result<Self> {
        Ok(Self {
            number: U256::from_str_radix(number.trim_start_matches("0x"), 16)?,
            hash: H256::from_slice(&Vec::from_hex(hash.trim_start_matches("0x"))?),
            state_root: H256::from_slice(&Vec::from_hex(state_root.trim_start_matches("0x"))?),
            transactions_root: H256::from_slice(&Vec::from_hex(transactions_root.trim_start_matches("0x"))?),
            receipts_root: H256::from_slice(&Vec::from_hex(receipts_root.trim_start_matches("0x"))?),
        })
    }
}
