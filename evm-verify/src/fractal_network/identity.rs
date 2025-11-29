// Simple Identity Module - Multi-Node Support
// Ed25519 keypairs for node identity

use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use std::path::Path;
use std::fs;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub public_key: Vec<u8>,
    pub node_id: String,
}

pub struct SimpleKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SimpleKeypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        Self {
            signing_key,
            verifying_key,
        }
    }
    
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
    
    pub fn node_id(&self) -> String {
        let hash = Sha256::digest(self.verifying_key.as_bytes());
        format!("node_{}", u64::from_be_bytes(hash[0..8].try_into().unwrap()))
    }
    
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
    
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let bytes = self.signing_key.to_bytes();
        fs::write(path, bytes)?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }
        
        Ok(())
    }
    
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = fs::read(path)?;
        let signing_key = SigningKey::from_bytes(
            &bytes.try_into().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid key file")
            })?
        );
        let verifying_key = signing_key.verifying_key();
        
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
}

pub struct IdentityManager {
    keypair: SimpleKeypair,
    identity: NodeIdentity,
}

impl IdentityManager {
    pub fn new() -> Self {
        let keypair = SimpleKeypair::generate();
        let identity = NodeIdentity {
            public_key: keypair.public_key_bytes(),
            node_id: keypair.node_id(),
        };
        
        Self { keypair, identity }
    }
    
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let keypair = SimpleKeypair::load(path)?;
        let identity = NodeIdentity {
            public_key: keypair.public_key_bytes(),
            node_id: keypair.node_id(),
        };
        
        Ok(Self { keypair, identity })
    }
    
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        self.keypair.save(path)
    }
    
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }
    
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }
}
