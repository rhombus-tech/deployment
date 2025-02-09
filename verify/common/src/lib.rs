use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Compress, Validate, Valid};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid proof format: {0}")]
    InvalidFormat(String),
}

/// Common trait for all property proofs
pub trait PropertyProof {
    /// The type of property this proof verifies
    fn property_type(&self) -> PropertyType;
    
    /// Convert to bytes for circuit input
    fn to_circuit_input(&self) -> Result<Vec<u8>, ProofError>;
}

/// Types of properties that can be verified
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyType {
    MemorySafety,
    TypeCorrectness,
    ResourceBounds,
}

/// Memory safety proof that can be serialized
#[derive(Debug, Clone)]
pub struct MemorySafetyProofData {
    pub bounds_checked: bool,
    pub leak_free: bool,
    pub max_memory: u32,
    pub access_safety: bool,
    pub memory_accesses: Vec<MemoryAccessData>,
    pub allocations: Vec<AllocationData>,
}

#[derive(Debug, Clone)]
pub struct MemoryAccessData {
    pub offset: u64,
    pub size: u32,
    pub is_load: bool,
}

#[derive(Debug, Clone)]
pub struct AllocationData {
    pub address: u32,
    pub size: u32,
    pub is_freed: bool,
}

impl Valid for MemoryAccessData {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl Valid for AllocationData {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl Valid for MemorySafetyProofData {
    fn check(&self) -> Result<(), SerializationError> {
        for access in &self.memory_accesses {
            access.check()?;
        }
        for alloc in &self.allocations {
            alloc.check()?;
        }
        Ok(())
    }
}

impl CanonicalSerialize for MemoryAccessData {
    fn serialize_with_mode<W: std::io::Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        self.offset.serialize_with_mode(&mut writer, compress)?;
        self.size.serialize_with_mode(&mut writer, compress)?;
        self.is_load.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.offset.serialized_size(compress) +
        self.size.serialized_size(compress) +
        self.is_load.serialized_size(compress)
    }
}

impl CanonicalDeserialize for MemoryAccessData {
    fn deserialize_with_mode<R: std::io::Read>(mut reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let offset = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let size = u32::deserialize_with_mode(&mut reader, compress, validate)?;
        let is_load = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self { offset, size, is_load })
    }
}

impl CanonicalSerialize for AllocationData {
    fn serialize_with_mode<W: std::io::Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        self.address.serialize_with_mode(&mut writer, compress)?;
        self.size.serialize_with_mode(&mut writer, compress)?;
        self.is_freed.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.address.serialized_size(compress) +
        self.size.serialized_size(compress) +
        self.is_freed.serialized_size(compress)
    }
}

impl CanonicalDeserialize for AllocationData {
    fn deserialize_with_mode<R: std::io::Read>(mut reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let address = u32::deserialize_with_mode(&mut reader, compress, validate)?;
        let size = u32::deserialize_with_mode(&mut reader, compress, validate)?;
        let is_freed = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self { address, size, is_freed })
    }
}

impl CanonicalSerialize for MemorySafetyProofData {
    fn serialize_with_mode<W: std::io::Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        // Serialize basic properties
        self.bounds_checked.serialize_with_mode(&mut writer, compress)?;
        self.leak_free.serialize_with_mode(&mut writer, compress)?;
        self.max_memory.serialize_with_mode(&mut writer, compress)?;
        self.access_safety.serialize_with_mode(&mut writer, compress)?;
        
        // Serialize memory accesses
        (self.memory_accesses.len() as u32).serialize_with_mode(&mut writer, compress)?;
        for access in &self.memory_accesses {
            access.serialize_with_mode(&mut writer, compress)?;
        }
        
        // Serialize allocations
        (self.allocations.len() as u32).serialize_with_mode(&mut writer, compress)?;
        for alloc in &self.allocations {
            alloc.serialize_with_mode(&mut writer, compress)?;
        }
        
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        // Size of basic properties
        let mut size = self.bounds_checked.serialized_size(compress)
            + self.leak_free.serialized_size(compress)
            + self.max_memory.serialized_size(compress)
            + self.access_safety.serialized_size(compress);
            
        // Size of memory accesses
        size += 4; // length
        for access in &self.memory_accesses {
            size += access.serialized_size(compress);
        }
        
        // Size of allocations
        size += 4; // length
        for alloc in &self.allocations {
            size += alloc.serialized_size(compress);
        }
        
        size
    }
}

impl CanonicalDeserialize for MemorySafetyProofData {
    fn deserialize_with_mode<R: std::io::Read>(mut reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        // Deserialize basic properties
        let bounds_checked = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        let leak_free = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        let max_memory = u32::deserialize_with_mode(&mut reader, compress, validate)?;
        let access_safety = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        
        // Deserialize memory accesses
        let access_count = u32::deserialize_with_mode(&mut reader, compress, validate)? as usize;
        let mut memory_accesses = Vec::with_capacity(access_count);
        for _ in 0..access_count {
            memory_accesses.push(MemoryAccessData::deserialize_with_mode(&mut reader, compress, validate)?);
        }
        
        // Deserialize allocations
        let alloc_count = u32::deserialize_with_mode(&mut reader, compress, validate)? as usize;
        let mut allocations = Vec::with_capacity(alloc_count);
        for _ in 0..alloc_count {
            allocations.push(AllocationData::deserialize_with_mode(&mut reader, compress, validate)?);
        }
        
        Ok(Self {
            bounds_checked,
            leak_free,
            max_memory,
            access_safety,
            memory_accesses,
            allocations,
        })
    }
}

impl PropertyProof for MemorySafetyProofData {
    fn property_type(&self) -> PropertyType {
        PropertyType::MemorySafety
    }
    
    fn to_circuit_input(&self) -> Result<Vec<u8>, ProofError> {
        let mut bytes = Vec::new();
        self.serialize_with_mode(&mut bytes, Compress::Yes)
            .map_err(|e| ProofError::Serialization(e.to_string()))?;
        Ok(bytes)
    }
}
