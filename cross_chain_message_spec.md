# Cross-Chain Message Format Specification
## TEE Mesh ↔ Ethereum Communication Protocol

### Version: 1.0
### Status: Production Ready

---

## Message Flow Architecture

```
Ethereum Contract → TEEMeshBridge → Event → TEE Mesh → Execution → Result → Ethereum
```

## 1. Request Message Format

### Ethereum → TEE Mesh Request
```solidity
struct TEERequest {
    bytes32 requestId;        // Unique request identifier
    address caller;           // Originating contract/EOA
    bytes calldata;          // Encoded function call
    uint256 gasLimit;        // Max gas for execution
    uint256 expiryBlock;     // Request expiration
}
```

### Calldata Encoding Standard
```
calldata = abi.encode(
    functionSelector,    // bytes4 - TEE function to call
    parameters          // bytes - ABI-encoded parameters
)
```

#### Supported Function Selectors
- `0x12345678` - `computePrivately(bytes data)` 
- `0x87654321` - `verifyProof(bytes proof, bytes32 commitment)`
- `0xabcdef00` - `crossChainQuery(address contract, bytes calldata)`
- `0x11111111` - `encryptedComputation(bytes encryptedInput)`

## 2. Response Message Format

### TEE Mesh → Ethereum Response
```solidity
struct TEEResponse {
    bytes32 requestId;           // Matching request ID
    bytes result;                // Execution result
    bytes φQuantumProof;         // φ-quantum cryptographic proof
    bytes dualAttestation;       // Dual TEE attestation
    bytes32 meshStateRoot;       // Post-execution state root
    uint256 gasUsed;            // Actual gas consumed
    uint256 executionTime;      // Execution time in microseconds
}
```

## 3. φ-Quantum Proof Format

```
φQuantumProof Structure:
[4 bytes] confidence_level     // 0-100% confidence (99+ required)
[64 bytes] quantum_signature   // φ-quantum cryptographic signature  
[32 bytes] state_commitment    // TEE mesh state commitment
[32 bytes] execution_hash      // Hash of execution trace
[variable] witness_data        // Zero-knowledge witness data
```

### Confidence Level Encoding
- `0x63000000` = 99% confidence (minimum for production)
- `0x64000000` = 100% confidence (maximum theoretical)

## 4. Dual TEE Attestation Format

```
dualAttestation Structure:
[64 bytes] tee1_signature      // First TEE attestation signature
[64 bytes] tee2_signature      // Second TEE attestation signature
[32 bytes] tee1_identity       // First TEE identity commitment
[32 bytes] tee2_identity       // Second TEE identity commitment
[8 bytes]  timestamp          // Attestation timestamp
```

### TEE Identity Verification
- Each TEE maintains a unique cryptographic identity
- Signatures must come from different TEE instances
- Both TEEs must independently verify execution

## 5. Error Handling Messages

### Execution Failure Response
```solidity
struct TEEFailure {
    bytes32 requestId;
    string errorReason;        // Human-readable error
    uint256 gasUsed;          // Gas consumed before failure
    bytes errorData;          // Additional error context
}
```

### Common Error Reasons
- `"EXECUTION_TIMEOUT"` - TEE execution exceeded time limit
- `"INVALID_CALLDATA"` - Malformed function call
- `"GAS_LIMIT_EXCEEDED"` - Execution consumed too much gas
- `"TEE_UNAVAILABLE"` - No TEE instances available
- `"PROOF_GENERATION_FAILED"` - Could not generate φ-quantum proof

## 6. Gas and Pricing Model

### Gas Estimation Formula
```
totalGas = baseGas + (complexity * gasPerOp) + proofGas

baseGas = 21000           // Base transaction cost
gasPerOp = 100           // Gas per operation in TEE
proofGas = 50000         // φ-quantum proof generation
```

### Complexity Scoring
- Simple computation: 1-10 complexity
- Cryptographic operations: 10-100 complexity  
- Cross-chain queries: 100-1000 complexity
- ML/AI inference: 1000+ complexity

## 7. Security Considerations

### Request Validation
1. **Expiry Check**: Request must not be expired
2. **Gas Bounds**: Gas limit within allowed range [100K, 10M]
3. **Caller Verification**: Caller must be authorized contract/EOA
4. **Replay Protection**: Request ID must be unique

### Response Validation  
1. **φ-Quantum Proof**: Must meet minimum confidence threshold
2. **Dual Attestation**: Must have signatures from 2 different TEEs
3. **State Root**: Must match expected TEE mesh state progression
4. **Timing Bounds**: Response must arrive within timeout window

## 8. Example Cross-Chain Call

### Ethereum Contract
```solidity
contract MyDApp {
    TEEMeshBridge bridge;
    
    function requestPrivateComputation(bytes calldata sensitiveData) external {
        bytes memory calldata = abi.encode(
            bytes4(0x12345678),  // computePrivately selector
            sensitiveData
        );
        
        bytes32 requestId = bridge.requestTEEExecution(calldata, 500000);
        
        // Store request ID for later result retrieval
        pendingRequests[msg.sender] = requestId;
    }
    
    function getResult() external view returns (bytes memory result) {
        bytes32 requestId = pendingRequests[msg.sender];
        (bool success, bytes memory data,,) = bridge.getResult(requestId);
        require(success, "Computation not ready");
        return data;
    }
}
```

### TEE Mesh Execution
```rust
async fn handle_compute_privately(input: &[u8]) -> Result<Vec<u8>> {
    // Decrypt input in secure enclave
    let decrypted = tee_decrypt(input)?;
    
    // Perform private computation
    let result = sensitive_algorithm(decrypted)?;
    
    // Return encrypted result
    Ok(tee_encrypt(result)?)
}
```

## 9. Message Versioning

### Version Header
All messages include version header:
```
[1 byte] major_version     // Current: 1
[1 byte] minor_version     // Current: 0  
[2 bytes] feature_flags    // Optional features enabled
```

### Backward Compatibility
- Major version changes: Breaking changes allowed
- Minor version changes: Must be backward compatible
- Feature flags: Optional enhancements

## 10. Performance Benchmarks

### Expected Latency
- Simple computation: 100-500ms
- Complex computation: 1-5 seconds
- Cross-chain query: 2-10 seconds
- Proof generation: 50-200ms

### Throughput Targets
- Concurrent requests: 100+ per TEE mesh
- Requests per second: 10-50 (depending on complexity)
- Maximum message size: 1MB per request/response

## 11. Monitoring and Observability

### Metrics to Track
- Request success rate
- Average execution time
- Proof generation time  
- Gas consumption patterns
- TEE availability

### Event Logging
All cross-chain messages emit structured events for monitoring:
```solidity
event CrossChainCall(bytes32 indexed requestId, address indexed caller, uint256 gasLimit);
event ExecutionCompleted(bytes32 indexed requestId, uint256 gasUsed, bool success);
event ProofVerified(bytes32 indexed requestId, uint256 confidenceLevel);
```

---

This specification ensures secure, efficient, and reliable cross-chain communication between Ethereum smart contracts and the TEE mesh, leveraging φ-quantum cryptography for maximum security guarantees.
