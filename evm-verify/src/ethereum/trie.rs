use ethers::types::H256;
use rlp::RlpStream;
use tiny_keccak::{Hasher, Keccak};
use anyhow::{Result, anyhow};

/// Node types in Merkle Patricia Trie
#[derive(Debug, Clone)]
pub enum Node {
    /// Empty node (NULL)
    Empty,
    /// Leaf node containing key end and value
    Leaf {
        key_end: Vec<u8>,
        value: Vec<u8>,
    },
    /// Extension node with shared prefix and child hash
    Extension {
        shared_prefix: Vec<u8>,
        child: H256,
    },
    /// Branch node with up to 16 children and optional value
    Branch {
        children: [Option<H256>; 16],
        value: Option<Vec<u8>>,
    },
}

impl Node {
    /// Decode node from RLP bytes
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Ok(Node::Empty);
        }

        let rlp = rlp::Rlp::new(bytes);
        if !rlp.is_list() {
            // If bytes is exactly 32 bytes, it's a hash reference
            if bytes.len() == 32 {
                return Ok(Node::Extension {
                    shared_prefix: vec![],
                    child: H256::from_slice(bytes),
                });
            }
            return Err(anyhow!("Not an RLP list"));
        }

        let list_len = rlp.item_count()?;
        match list_len {
            0 => Ok(Node::Empty),
            2 => {
                let prefix_bytes: Vec<u8> = rlp.at(0)?.as_val()?;
                if prefix_bytes.is_empty() {
                    return Err(anyhow!("Empty prefix"));
                }
                let prefix = prefix_bytes[0];
                let high_nibble = prefix >> 4;
                
                match high_nibble {
                    1 => { // Extension node
                        let shared_prefix = prefix_bytes[1..].to_vec();
                        let child_bytes: Vec<u8> = rlp.at(1)?.as_val()?;
                        let child = if child_bytes.len() == 32 {
                            H256::from_slice(&child_bytes)
                        } else {
                            H256::from_slice(&Self::keccak256(&child_bytes))
                        };
                        Ok(Node::Extension { shared_prefix, child })
                    },
                    2 => { // Leaf node
                        let key_end = prefix_bytes[1..].to_vec();
                        let value: Vec<u8> = rlp.at(1)?.as_val()?;
                        Ok(Node::Leaf { key_end, value })
                    },
                    _ => Err(anyhow!("Invalid prefix")),
                }
            },
            17 => {
                let mut children = [None; 16];
                for i in 0..16 {
                    let child: Vec<u8> = rlp.at(i)?.as_val()?;
                    if !child.is_empty() {
                        children[i] = Some(if child.len() == 32 {
                            H256::from_slice(&child)
                        } else {
                            H256::from_slice(&Self::keccak256(&child))
                        });
                    }
                }
                let value: Vec<u8> = rlp.at(16)?.as_val()?;
                Ok(Node::Branch {
                    children,
                    value: if value.is_empty() { None } else { Some(value) },
                })
            },
            _ => Err(anyhow!("Invalid list length")),
        }
    }

    /// Encode node to RLP bytes
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Node::Empty => {
                let mut stream = RlpStream::new_list(0);
                stream.out().to_vec()
            },
            Node::Leaf { key_end, value } => {
                let mut prefix = vec![0x20];
                prefix.extend(key_end);
                let mut stream = RlpStream::new_list(2);
                stream.append(&prefix);
                stream.append(value);
                stream.out().to_vec()
            },
            Node::Extension { shared_prefix, child } => {
                let mut prefix = vec![0x10];
                prefix.extend(shared_prefix);
                let mut stream = RlpStream::new_list(2);
                stream.append(&prefix);
                stream.append(&child.as_bytes().to_vec());
                stream.out().to_vec()
            },
            Node::Branch { children, value } => {
                let mut stream = RlpStream::new_list(17);
                for child in children.iter() {
                    match child {
                        Some(hash) => stream.append(&hash.as_bytes().to_vec()),
                        None => stream.append_empty_data(),
                    };
                }
                match value {
                    Some(v) => stream.append(v),
                    None => stream.append_empty_data(),
                };
                stream.out().to_vec()
            },
        }
    }

    /// Calculate keccak256 hash
    fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut hash);
        hash
    }

    /// Calculate node hash
    pub fn hash(&self) -> H256 {
        let encoded = self.encode();
        H256::from_slice(&Self::keccak256(&encoded))
    }

    /// Verify a Merkle proof path against a root hash
    pub fn verify_proof(
        root_hash: H256,
        key: &[u8],
        proof: &[Vec<u8>],
        expected_value: &[u8]
    ) -> Result<bool> {
        let mut current_hash = root_hash;
        let key_nibbles = bytes_to_nibbles(key);
        let mut key_pos = 0;
        
        for proof_node in proof {
            let node = Node::decode(proof_node)?;
            let node_hash = H256::from_slice(&Self::keccak256(proof_node));
            
            if node_hash != current_hash {
                return Ok(false);
            }
            
            match node {
                Node::Empty => {
                    return Ok(expected_value.is_empty());
                },
                Node::Leaf { key_end, value } => {
                    if key_nibbles[key_pos..] != key_end {
                        return Ok(false);
                    }
                    return Ok(value == expected_value);
                },
                Node::Extension { shared_prefix, child } => {
                    if !key_nibbles[key_pos..].starts_with(&shared_prefix) {
                        return Ok(false);
                    }
                    key_pos += shared_prefix.len();
                    current_hash = child;
                },
                Node::Branch { children, value } => {
                    if key_pos == key_nibbles.len() {
                        if let Some(v) = value {
                            return Ok(v == expected_value);
                        }
                        return Ok(expected_value.is_empty());
                    }
                    
                    let nibble = key_nibbles[key_pos] as usize;
                    if let Some(child) = children[nibble] {
                        key_pos += 1;
                        current_hash = child;
                    } else {
                        return Ok(expected_value.is_empty());
                    }
                },
            }
        }
        
        Ok(false)
    }
}

/// Convert bytes to nibbles
pub fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    nibbles
}

/// Verify a Merkle proof path against a root hash
pub fn verify_proof(
    root_hash: H256,
    key: &[u8],
    proof: &[Vec<u8>],
    expected_value: &[u8]
) -> Result<bool> {
    Node::verify_proof(root_hash, key, proof, expected_value)
}
