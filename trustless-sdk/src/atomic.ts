/**
 * Atomic Executor
 * 
 * Handles atomic multi-transaction execution
 */

import type {
  TrustlessConfig,
  AtomicBundle,
  AtomicProof,
  TrustlessProof,
  SubmitResult,
  ProvingCallback,
} from './types';

import { TrustlessCore } from './core';
import { WasmLoader } from './wasm-loader';
import { ethers } from 'ethers';

/**
 * Atomic execution engine
 */
export class AtomicExecutor {
  private config: TrustlessConfig;
  private provider: ethers.Provider | null = null;
  private core: TrustlessCore;

  constructor(config: TrustlessConfig) {
    this.config = config;
    this.core = new TrustlessCore(config);
  }

  /**
   * Initialize atomic executor
   */
  async initialize(): Promise<void> {
    await this.core.initialize();
    
    // Initialize provider for atomic contract
    if (this.config.rpcUrl) {
      this.provider = new ethers.JsonRpcProvider(this.config.rpcUrl);
    } else if (this.config.network) {
      this.provider = ethers.getDefaultProvider(this.config.network);
    }
  }

  /**
   * Prove an atomic bundle
   */
  async proveBundle(
    bundle: AtomicBundle,
    callback?: ProvingCallback
  ): Promise<AtomicProof> {
    const proofs: TrustlessProof[] = [];
    
    // Prove each transaction in the bundle
    for (let i = 0; i < bundle.transactions.length; i++) {
      const tx = bundle.transactions[i];
      
      // Update progress callback
      const txCallback: ProvingCallback = (event) => {
        if (callback) {
          if (event.type === 'SECURITY_ANALYSIS' || event.type === 'PROOF_GENERATION') {
            const overallProgress = (i / bundle.transactions.length) * 100 + 
                                   (event.progress / bundle.transactions.length);
            callback({ ...event, progress: overallProgress });
          } else {
            callback(event);
          }
        }
      };
      
      const proof = await this.core.prove(tx, txCallback);
      proofs.push(proof);
    }

    // Create atomic bundle with WASM
    const wasm = WasmLoader.getWasm();
    const bundleBytes = this.serializeBundle(bundle, proofs);
    const atomicBytes = await wasm.create_atomic_bundle(bundleBytes);
    
    // Calculate bundle hash
    const bundleHash = ethers.keccak256(atomicBytes);
    
    // Estimate total gas
    const totalGasEstimate = proofs.reduce(
      (sum, p) => sum + (p.transaction.gasLimit ? BigInt(p.transaction.gasLimit) : 21000n),
      0n
    );

    return {
      proofs,
      bundleHash,
      guaranteedAtomic: true,
      totalGasEstimate,
    };
  }

  /**
   * Submit an atomic bundle
   */
  async submit(atomicProof: AtomicProof): Promise<SubmitResult> {
    if (!this.provider) {
      throw new Error('Provider not configured');
    }

    // Get atomic executor contract address
    const executorAddress = this.config.atomicExecutorContract || 
                           this.getDefaultExecutorAddress();

    try {
      // Prepare atomic execution call
      const atomicCalldata = this.prepareAtomicCalldata(atomicProof);
      
      // Create transaction to atomic executor
      const tx = {
        to: executorAddress,
        data: atomicCalldata,
        gasLimit: atomicProof.totalGasEstimate * 110n / 100n, // +10% buffer
      };

      // Send transaction
      const sentTx = await this.provider.broadcastTransaction(
        ethers.Transaction.from(tx).serialized
      );

      // Wait for receipt
      const receipt = await sentTx.wait();

      return {
        success: true,
        transactionHash: receipt?.hash,
        receipt: receipt as any,
      };
    } catch (error) {
      return {
        success: false,
        error: error as Error,
      };
    }
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    await this.core.cleanup();
    this.provider = null;
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  private serializeBundle(bundle: AtomicBundle, proofs: TrustlessProof[]): Uint8Array {
    const data = {
      transactions: bundle.transactions.map((tx, i) => ({
        to: tx.to,
        data: tx.data || '0x',
        value: (tx.value || 0n).toString(),
        proof: Array.from(proofs[i].zkProof.proof),
      })),
      revertOnFailure: bundle.revertOnFailure !== false,
    };
    return new TextEncoder().encode(JSON.stringify(data));
  }

  private prepareAtomicCalldata(atomicProof: AtomicProof): string {
    // Encode atomic execution calldata
    // This would call the VerifiedAtomicExecutor.executeAtomic() function
    
    const operations = atomicProof.proofs.map(p => ({
      target: p.transaction.to,
      callData: p.transaction.data || '0x',
      value: p.transaction.value || 0n,
    }));

    const executionProof = {
      pccProofHash: atomicProof.proofs[0].security.pccProofHash,
      pcdProofHash: atomicProof.bundleHash,
      stateRoot: '0x0000000000000000000000000000000000000000000000000000000000000000',
      gasLimit: atomicProof.totalGasEstimate,
    };

    // ABI encode the executeAtomic call
    const iface = new ethers.Interface([
      'function executeAtomic(tuple(address target, bytes callData, uint256 value)[] operations, tuple(bytes32 pccProofHash, bytes32 pcdProofHash, bytes32 stateRoot, uint256 gasLimit) proof) returns (bytes[] results)'
    ]);

    return iface.encodeFunctionData('executeAtomic', [operations, executionProof]);
  }

  private getDefaultExecutorAddress(): string {
    // Default atomic executor contract addresses per network
    const addresses: Record<string, string> = {
      mainnet: '0x59b670e9fA9D0A427751Af201D676719a970857b',
      goerli: '0x59b670e9fA9D0A427751Af201D676719a970857b',
      sepolia: '0x59b670e9fA9D0A427751Af201D676719a970857b',
      localhost: '0x59b670e9fA9D0A427751Af201D676719a970857b',
    };

    return addresses[this.config.network || 'mainnet'] || addresses.mainnet;
  }
}
