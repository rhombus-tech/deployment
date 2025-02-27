use ethers::types::{H256, U256, H160};
use hex_literal::hex;
use crate::ethereum::proof::{StorageProof, AccountProof, BlockVerification};
use crate::ethereum::trie::Node;
use rlp;

#[test]
fn test_storage_proof() {
    // Create a leaf node with the slot and value
    let slot = H256::from(hex!("0000000000000000000000000000000000000000000000000000000000000001"));
    let value = U256::from(100u64);
    let mut value_bytes = [0u8; 32];
    value.to_big_endian(&mut value_bytes);

    let leaf = Node::Leaf {
        key_end: crate::ethereum::trie::bytes_to_nibbles(slot.as_bytes()),
        value: value_bytes.to_vec(),
    };
    
    let storage_root = leaf.hash();
    
    let proof = StorageProof {
        value,
        proof: vec![leaf.encode()],
    };
    
    assert!(proof.verify(storage_root, slot).unwrap());
}

#[test]
fn test_account_proof() {
    let address = H160::random();
    // Pad address to 32 bytes
    let mut padded_address = [0u8; 32];
    padded_address[12..].copy_from_slice(address.as_bytes());
    let address_h256 = H256::from_slice(&padded_address);
    
    let nonce = U256::zero();
    let balance = U256::from(1000);
    let storage_root = H256::zero();
    let code_hash = H256::zero();
    
    // Create leaf node with account data
    let mut stream = rlp::RlpStream::new_list(4);
    stream.append(&nonce);
    stream.append(&balance);
    stream.append(&storage_root);
    stream.append(&code_hash);
    let value = stream.out().to_vec();
    
    let leaf = Node::Leaf {
        key_end: crate::ethereum::trie::bytes_to_nibbles(&padded_address),
        value: value.clone(),
    };
    
    let state_root = leaf.hash();
    let proof = vec![leaf.encode()];
    
    let account_proof = AccountProof {
        nonce,
        balance,
        storage_root,
        code_hash,
        proof,
    };
    
    assert!(account_proof.verify(state_root, address_h256).unwrap());
}

#[test]
fn test_block_verification() {
    let block = BlockVerification::from_hex(
        "0x1",
        "0x1234567890123456789012345678901234567890123456789012345678901234",
        "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    ).unwrap();
    
    assert_eq!(block.number, U256::one());
    assert_eq!(
        block.hash,
        H256::from(hex!("1234567890123456789012345678901234567890123456789012345678901234"))
    );
    assert_eq!(
        block.state_root,
        H256::from(hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"))
    );
}
