use ethers::types::H256;
use hex_literal::hex;
use crate::ethereum::trie::{Node, verify_proof, bytes_to_nibbles};

#[test]
fn test_leaf_node_encoding() {
    let leaf = Node::Leaf {
        key_end: vec![0x12, 0x34],
        value: vec![0x56, 0x78],
    };
    
    let hash = leaf.hash();
    assert_ne!(hash, H256::zero());
    
    let encoded = leaf.encode();
    let decoded = Node::decode(&encoded).unwrap();
    match decoded {
        Node::Leaf { key_end, value } => {
            assert_eq!(key_end, vec![0x12, 0x34]);
            assert_eq!(value, vec![0x56, 0x78]);
        },
        _ => panic!("Wrong node type"),
    }
}

#[test]
fn test_extension_node_encoding() {
    let extension = Node::Extension {
        shared_prefix: vec![0x12],
        child: H256::from_low_u64_be(1),
    };
    
    let hash = extension.hash();
    assert_ne!(hash, H256::zero());
    
    let encoded = extension.encode();
    let decoded = Node::decode(&encoded).unwrap();
    match decoded {
        Node::Extension { shared_prefix, child } => {
            assert_eq!(shared_prefix, vec![0x12]);
            assert_eq!(child, H256::from_low_u64_be(1));
        },
        _ => panic!("Wrong node type"),
    }
}

#[test]
fn test_branch_node_encoding() {
    let mut children = [None; 16];
    children[0] = Some(H256::from_low_u64_be(1));
    children[15] = Some(H256::from_low_u64_be(2));
    
    let branch = Node::Branch {
        children,
        value: Some(vec![0x12, 0x34]),
    };
    
    let hash = branch.hash();
    assert_ne!(hash, H256::zero());
    
    let encoded = branch.encode();
    let decoded = Node::decode(&encoded).unwrap();
    match decoded {
        Node::Branch { children, value } => {
            assert_eq!(children[0], Some(H256::from_low_u64_be(1)));
            assert_eq!(children[15], Some(H256::from_low_u64_be(2)));
            assert_eq!(value, Some(vec![0x12, 0x34]));
        },
        _ => panic!("Wrong node type"),
    }
}

#[test]
fn test_empty_node_encoding() {
    let empty = Node::Empty;
    let hash = empty.hash();
    assert_ne!(hash, H256::zero());
    
    let encoded = empty.encode();
    let decoded = Node::decode(&encoded).unwrap();
    assert!(matches!(decoded, Node::Empty));
}

#[test]
fn test_simple_proof() {
    let key = hex!("1234");
    let value = hex!("5678");
    
    let leaf = Node::Leaf {
        key_end: bytes_to_nibbles(&key).to_vec(),
        value: value.to_vec(),
    };
    
    let root = leaf.hash();
    let proof = vec![leaf.encode()];
    
    let result = verify_proof(root, &key, &proof, &value).unwrap();
    assert!(result);
}

#[test]
fn test_complex_proof() {
    let key = hex!("1234");
    let value = hex!("5678");
    
    // Create a leaf node with the key end (last nibble)
    let leaf = Node::Leaf {
        key_end: vec![0x4],  // Last nibble of the key
        value: value.to_vec(),
    };
    
    // Create an extension node with the shared prefix (first nibble)
    let extension = Node::Extension {
        shared_prefix: vec![0x1, 0x2, 0x3],  // First three nibbles of the key
        child: leaf.hash(),
    };
    
    let root = extension.hash();
    let proof = vec![
        extension.encode(),
        leaf.encode(),
    ];
    
    let result = verify_proof(root, &key, &proof, &value).unwrap();
    assert!(result);
}
