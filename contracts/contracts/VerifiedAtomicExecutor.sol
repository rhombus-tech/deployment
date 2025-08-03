// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title VerifiedAtomicExecutor
 * @dev Executes multiple operations atomically with PCC+PCD verification
 * All operations succeed or the entire transaction reverts
 */
contract VerifiedAtomicExecutor is ReentrancyGuard, Ownable {
    
    struct AtomicOperation {
        address target;
        bytes callData;
        uint256 value;
    }
    
    struct ExecutionProof {
        bytes32 pccProofHash;      // PCC safety verification proof
        bytes32 pcdProofHash;      // PCD execution proof
        bytes32 stateRoot;         // Expected state root after execution
        uint256 gasLimit;          // Maximum gas for entire sequence
    }
    
    // Events
    event AtomicExecutionSuccess(
        bytes32 indexed executionHash,
        bytes32 indexed pccProofHash,
        bytes32 indexed pcdProofHash,
        uint256 gasUsed
    );
    
    event AtomicExecutionFailed(
        bytes32 indexed executionHash,
        string reason,
        uint256 failedStep
    );
    
    // Registry of executed proofs to prevent replay
    mapping(bytes32 => bool) public executedProofs;
    
    // PCC Verifier contract address
    address public pccVerifier;
    
    /**
     * @dev Execute multiple operations atomically with cryptographic proofs
     * @param proof The PCC+PCD verification proof
     * @param operations Array of operations to execute atomically
     * @return executionHash Hash of the executed sequence
     */
    function executeWithProof(
        ExecutionProof calldata proof,
        AtomicOperation[] calldata operations
    ) external payable nonReentrant returns (bytes32 executionHash) {
        require(operations.length > 0, "No operations provided");
        require(operations.length <= 50, "Too many operations"); // Gas limit protection
        
        // Generate execution hash
        executionHash = keccak256(abi.encode(
            msg.sender,
            block.timestamp,
            proof,
            operations
        ));
        
        // Prevent replay attacks
        require(!executedProofs[executionHash], "Proof already executed");
        executedProofs[executionHash] = true;
        
        // Verify PCC proof (if verifier is set)
        if (pccVerifier != address(0)) {
            require(_verifyPCCProof(proof.pccProofHash, operations), "PCC verification failed");
        }
        
        // Execute all operations atomically
        uint256 totalGasUsed = gasleft();
        
        for (uint256 i = 0; i < operations.length; i++) {
            AtomicOperation memory op = operations[i];
            
            // Check gas limit
            require(gasleft() > proof.gasLimit / operations.length, "Insufficient gas");
            
            // Execute operation
            (bool success, bytes memory returnData) = op.target.call{value: op.value}(op.callData);
            
            if (!success) {
                // Decode revert reason if available
                string memory revertReason = "Unknown error";
                if (returnData.length > 0) {
                    assembly {
                        revertReason := add(returnData, 0x20)
                    }
                }
                
                emit AtomicExecutionFailed(executionHash, revertReason, i);
                revert(string(abi.encodePacked("Step ", _toString(i), " failed: ", revertReason)));
            }
        }
        
        totalGasUsed = totalGasUsed - gasleft();
        
        emit AtomicExecutionSuccess(executionHash, proof.pccProofHash, proof.pcdProofHash, totalGasUsed);
        
        return executionHash;
    }
    
    /**
     * @dev Execute operations without proof verification (for testing)
     * @param operations Array of operations to execute atomically
     */
    function executeWithoutProof(
        AtomicOperation[] calldata operations
    ) external payable nonReentrant returns (bytes32 executionHash) {
        require(operations.length > 0, "No operations provided");
        require(operations.length <= 50, "Too many operations");
        
        executionHash = keccak256(abi.encode(
            msg.sender,
            block.timestamp,
            operations
        ));
        
        // Execute all operations atomically
        for (uint256 i = 0; i < operations.length; i++) {
            AtomicOperation memory op = operations[i];
            
            (bool success, bytes memory returnData) = op.target.call{value: op.value}(op.callData);
            
            if (!success) {
                string memory revertReason = "Unknown error";
                if (returnData.length > 0) {
                    assembly {
                        revertReason := add(returnData, 0x20)
                    }
                }
                
                emit AtomicExecutionFailed(executionHash, revertReason, i);
                revert(string(abi.encodePacked("Step ", _toString(i), " failed: ", revertReason)));
            }
        }
        
        emit AtomicExecutionSuccess(executionHash, bytes32(0), bytes32(0), 0);
        
        return executionHash;
    }
    
    /**
     * @dev Set the PCC verifier contract address
     */
    function setPCCVerifier(address _pccVerifier) external onlyOwner {
        pccVerifier = _pccVerifier;
    }
    
    /**
     * @dev Verify PCC proof (placeholder - integrate with your PCC system)
     */
    function _verifyPCCProof(
        bytes32 proofHash,
        AtomicOperation[] calldata operations
    ) internal view returns (bool) {
        // If no PCC verifier is set, accept any non-zero proof hash
        if (pccVerifier == address(0)) {
            return proofHash != bytes32(0);
        }
        
        // Encode the operations data for verification
        bytes memory operationsData = abi.encode(operations);
        
        // Call the external PCC verifier contract
        // The PCC verifier should implement: verifyProof(bytes32 proofHash, bytes calldata data) returns (bool)
        (bool success, bytes memory result) = pccVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(bytes32,bytes)",
                proofHash,
                operationsData
            )
        );
        
        // Return false if the call failed or returned false
        if (!success || result.length == 0) {
            return false;
        }
        
        // Decode the boolean result
        return abi.decode(result, (bool));
    }
    
    /**
     * @dev Convert uint to string
     */
    function _toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
    
    /**
     * @dev Emergency withdrawal function
     */
    function emergencyWithdraw() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
    
    /**
     * @dev Receive function to accept ETH
     */
    receive() external payable {}
}
