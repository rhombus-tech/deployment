// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IPCCVerifier
 * @dev Interface for Proof Carrying Code (PCC) verification
 */
interface IPCCVerifier {
    /**
     * @dev Verify a PCC proof for the given data
     * @param proofHash The hash of the PCC proof
     * @param data The data being verified (encoded operations)
     * @return Whether the proof is valid
     */
    function verifyProof(bytes32 proofHash, bytes calldata data) external view returns (bool);
    
    /**
     * @dev Verify a PCC proof with additional context
     * @param proofHash The hash of the PCC proof
     * @param data The data being verified
     * @param context Additional context for verification
     * @return Whether the proof is valid
     */
    function verifyProofWithContext(
        bytes32 proofHash, 
        bytes calldata data, 
        bytes calldata context
    ) external view returns (bool);
    
    /**
     * @dev Get the current verification parameters
     * @return enabled Whether verification is enabled
     * @return strictMode Whether strict verification mode is active
     */
    function getVerificationConfig() external view returns (bool enabled, bool strictMode);
}
