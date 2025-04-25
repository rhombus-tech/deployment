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

/// Types of parameter validation that can be performed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationTypeInfo {
    /// Basic length check against a maximum value
    LengthCheck,
    /// Range check for a value (min-max)
    RangeCheck,
    /// Type checking
    TypeCheck,
    /// Bounds checking for memory access
    BoundsCheck,
    /// Protocol-specific validation
    ProtocolSpecific(String),
    /// Nested or composite validation
    Composite,
    /// Parameter rejection for invalid input
    Rejection,
    /// Generic or unknown validation type
    Other,
}

/// Implement Valid trait required for CanonicalDeserialize
impl ark_serialize::Valid for ValidationTypeInfo {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        // All values of this enum are valid
        Ok(())
    }
}

impl Default for ValidationTypeInfo {
    fn default() -> Self {
        ValidationTypeInfo::Other
    }
}

/// Information about parameter validation in a contract
#[derive(Debug, Clone)]
pub struct ParameterValidationInfo {
    /// Maximum allowed length for a parameter (if detected)
    pub max_allowed_length: Option<u64>,
    /// Whether the contract validates parameter lengths
    pub validates_length: bool,
    /// Parameter index that is validated
    pub parameter_index: Option<u32>,
    /// Description of the validation strategy
    pub validation_strategy: String,
    /// Validation type classification
    pub validation_type: ValidationTypeInfo,
    /// Extra metadata for validation (protocol-specific information)
    pub metadata: Option<String>,
}

impl Default for ParameterValidationInfo {
    fn default() -> Self {
        Self {
            max_allowed_length: None,
            validates_length: false,
            parameter_index: None,
            validation_strategy: String::new(),
            validation_type: ValidationTypeInfo::default(),
            metadata: None,
        }
    }
}

/// Implement Valid trait required for CanonicalDeserialize
impl ark_serialize::Valid for ParameterValidationInfo {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        // All parameter validation info structs are valid
        Ok(())
    }
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
    /// Whether the contract has parameter validation
    pub has_parameter_validation: bool,
    /// Information about parameter validation strategies
    pub parameter_validation_results: Vec<ParameterValidationInfo>,
}

/// Implement Default for MemorySafetyProofData to make it easier to create
impl Default for MemorySafetyProofData {
    fn default() -> Self {
        Self {
            bounds_checked: false,
            leak_free: false,
            max_memory: 0,
            access_safety: false,
            memory_accesses: Vec::new(),
            allocations: Vec::new(),
            has_parameter_validation: false,
            parameter_validation_results: Vec::new(),
        }
    }
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

impl CanonicalSerialize for ValidationTypeInfo {
    fn serialize_with_mode<W: std::io::Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        // Serialize the enum as a u8 tag and optional data
        match self {
            ValidationTypeInfo::LengthCheck => 0u8.serialize_with_mode(&mut writer, compress)?,
            ValidationTypeInfo::RangeCheck => 1u8.serialize_with_mode(&mut writer, compress)?,
            ValidationTypeInfo::TypeCheck => 2u8.serialize_with_mode(&mut writer, compress)?,
            ValidationTypeInfo::BoundsCheck => 3u8.serialize_with_mode(&mut writer, compress)?,
            ValidationTypeInfo::Composite => 4u8.serialize_with_mode(&mut writer, compress)?,
            ValidationTypeInfo::Rejection => 5u8.serialize_with_mode(&mut writer, compress)?,
            ValidationTypeInfo::ProtocolSpecific(protocol_name) => {
                6u8.serialize_with_mode(&mut writer, compress)?;
                protocol_name.serialize_with_mode(&mut writer, compress)?
            },
            ValidationTypeInfo::Other => 7u8.serialize_with_mode(&mut writer, compress)?,
        }
        
        Ok(())
    }
    
    fn serialized_size(&self, compress: Compress) -> usize {
        // Size of the tag byte
        let mut size = 1; 
        
        // Add size of any additional data
        match self {
            ValidationTypeInfo::ProtocolSpecific(protocol_name) => {
                size += protocol_name.serialized_size(compress);
            },
            _ => {}, // Other variants just have the tag
        }
        
        size
    }
}

impl CanonicalDeserialize for ValidationTypeInfo {
    fn deserialize_with_mode<R: std::io::Read>(mut reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        // Deserialize the enum tag and optional data
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        
        match tag {
            0 => Ok(ValidationTypeInfo::LengthCheck),
            1 => Ok(ValidationTypeInfo::RangeCheck),
            2 => Ok(ValidationTypeInfo::TypeCheck),
            3 => Ok(ValidationTypeInfo::BoundsCheck),
            4 => Ok(ValidationTypeInfo::Composite),
            5 => Ok(ValidationTypeInfo::Rejection),
            6 => {
                let protocol_name = String::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(ValidationTypeInfo::ProtocolSpecific(protocol_name))
            },
            7 => Ok(ValidationTypeInfo::Other),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl CanonicalSerialize for ParameterValidationInfo {
    fn serialize_with_mode<W: std::io::Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        // Serialize the fields
        match self.max_allowed_length {
            Some(max) => {
                true.serialize_with_mode(&mut writer, compress)?; // Has max length
                max.serialize_with_mode(&mut writer, compress)?
            },
            None => {
                false.serialize_with_mode(&mut writer, compress)? // No max length
            }
        }
        
        self.validates_length.serialize_with_mode(&mut writer, compress)?;
        
        match self.parameter_index {
            Some(idx) => {
                true.serialize_with_mode(&mut writer, compress)?; // Has parameter index
                idx.serialize_with_mode(&mut writer, compress)?
            },
            None => {
                false.serialize_with_mode(&mut writer, compress)? // No parameter index
            }
        }
        
        self.validation_strategy.serialize_with_mode(&mut writer, compress)?;
        self.validation_type.serialize_with_mode(&mut writer, compress)?;
        
        // Serialize metadata
        match &self.metadata {
            Some(metadata) => {
                true.serialize_with_mode(&mut writer, compress)?; // Has metadata
                metadata.serialize_with_mode(&mut writer, compress)?
            },
            None => {
                false.serialize_with_mode(&mut writer, compress)? // No metadata
            }
        }
        
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut size = 1; // For has_max_allowed_length bool
        if let Some(max_len) = self.max_allowed_length {
            size += max_len.serialized_size(compress);
        }
        
        size += 1; // For validates_length bool
        
        size += 1; // For has_parameter_index bool
        if let Some(param_idx) = self.parameter_index {
            size += param_idx.serialized_size(compress);
        }
        
        size += self.validation_strategy.serialized_size(compress);
        size += self.validation_type.serialized_size(compress);
        
        // Size of metadata
        size += 1; // For has_metadata bool
        if let Some(ref metadata) = self.metadata {
            size += metadata.serialized_size(compress);
        }
        
        size
    }
}

impl CanonicalDeserialize for ParameterValidationInfo {
    fn deserialize_with_mode<R: std::io::Read>(mut reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        // Deserialize the fields
        let has_max = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        let max_allowed_length = if has_max {
            Some(u64::deserialize_with_mode(&mut reader, compress, validate)?)
        } else {
            None
        };
        
        let validates_length = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        
        let has_idx = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        let parameter_index = if has_idx {
            Some(u32::deserialize_with_mode(&mut reader, compress, validate)?)
        } else {
            None
        };
        
        let validation_strategy = String::deserialize_with_mode(&mut reader, compress, validate)?;
        let validation_type = ValidationTypeInfo::deserialize_with_mode(&mut reader, compress, validate)?;
        
        // Deserialize metadata
        let has_metadata = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        let metadata = if has_metadata {
            Some(String::deserialize_with_mode(&mut reader, compress, validate)?)
        } else {
            None
        };
        
        Ok(Self {
            max_allowed_length,
            validates_length,
            parameter_index,
            validation_strategy,
            validation_type,
            metadata,
        })
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
        
        // Serialize parameter validation info
        self.has_parameter_validation.serialize_with_mode(&mut writer, compress)?;
        (self.parameter_validation_results.len() as u32).serialize_with_mode(&mut writer, compress)?;
        for validation in &self.parameter_validation_results {
            validation.serialize_with_mode(&mut writer, compress)?;
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
        
        // Size of parameter validation info
        size += self.has_parameter_validation.serialized_size(compress);
        size += 4; // length of parameter_validation_results
        for validation in &self.parameter_validation_results {
            size += validation.serialized_size(compress);
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
            // For backwards compatibility, deserialize without parameter validation
            has_parameter_validation: false,
            parameter_validation_results: Vec::new(),
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
