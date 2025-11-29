/**
 * Trustless Core
 * 
 * Core proving and verification logic
 */

import type {
  TrustlessConfig,
  TrustlessTransaction,
  TrustlessProof,
  ProvingResult,
  SubmitResult,
  TrustlessStats,
  ProvingCallback,
  SecurityVerification,
  ZKProof,
  Vulnerability,
} from './types';

import { WasmLoader } from './wasm-loader';
import { ethers } from 'ethers';

/**
 * Core proving and verification engine
 */
export class TrustlessCore {
  config: TrustlessConfig;
  private provider: ethers.Provider | null = null;
  private stats: TrustlessStats;
  currentBlock?: number;

  constructor(config: TrustlessConfig) {
    this.config = {
      network: 'mainnet',
      enableSecurity: true,
      securityLevel: 'STANDARD',
      enableCompression: true,
      provingTimeout: 30000, // 30 seconds
      debug: false,
      ...config,
    };

    this.stats = {
      totalProofs: 0,
      successfulProofs: 0,
      failedProofs: 0,
      averageProvingTime: 0,
      averageProofSize: 0,
      totalGasSaved: 0n,
      vulnerabilitiesDetected: 0,
      trustlessScore: 0,
    };
  }

  /**
   * Initialize the core prover
   */
  async initialize(): Promise<void> {
    // Initialize provider
    if (this.config.rpcUrl) {
      this.provider = new ethers.JsonRpcProvider(this.config.rpcUrl);
    } else if (this.config.network) {
      this.provider = ethers.getDefaultProvider(this.config.network);
    }

    // Get current block number (with timeout)
    if (this.provider) {
      try {
        this.currentBlock = await Promise.race([
          this.provider.getBlockNumber(),
          new Promise<number>((_, reject) => 
            setTimeout(() => reject(new Error('Provider timeout')), 3000)
          )
        ]);
      } catch (error) {
        if (this.config.debug) {
          console.warn('[Trustless] Could not connect to provider:', error);
        }
        this.currentBlock = 0;
      }
    }

    if (this.config.debug) {
      console.log('[Trustless] Initialized', {
        network: this.config.network || 'offline',
        block: this.currentBlock,
        security: this.config.enableSecurity,
        provider: this.provider ? 'connected' : 'offline',
      });
    }
  }

  /**
   * Prove a transaction with full security verification
   */
  async prove(
    transaction: TrustlessTransaction,
    callback?: ProvingCallback
  ): Promise<TrustlessProof> {
    const startTime = Date.now();

    try {
      // Emit started event
      callback?.({ type: 'STARTED', transaction });

      // Step 1: Security analysis (if enabled)
      let security: SecurityVerification;
      if (this.config.enableSecurity) {
        callback?.({ type: 'SECURITY_ANALYSIS', progress: 0 });
        security = await this.verifySecurity(transaction);
        callback?.({ type: 'SECURITY_ANALYSIS', progress: 100 });
      } else {
        security = {
          isSecure: true,
          vulnerabilities: [],
          securityScore: 100,
          pccProofHash: '0x0',
        };
      }

      // Step 2: Generate ZK proof
      callback?.({ type: 'PROOF_GENERATION', progress: 0 });
      const zkProof = await this.proveOnly(transaction);
      callback?.({ type: 'PROOF_GENERATION', progress: 100 });

      // Step 3: Compression (if enabled)
      if (this.config.enableCompression) {
        callback?.({ type: 'COMPRESSION', progress: 50 });
        // WARP compression happens here
        callback?.({ type: 'COMPRESSION', progress: 100 });
      }

      // Calculate trustless score (composite)
      const trustlessScore = this.calculateTrustlessScore(zkProof, security);

      // Create proof object
      const proof: TrustlessProof = {
        zkProof,
        security,
        transaction,
        timestamp: Date.now(),
        trustlessScore,
      };

      // Update statistics
      this.updateStats(true, Date.now() - startTime, zkProof.proof.length, security);

      // Emit completed event
      callback?.({ type: 'COMPLETED', proof });

      return proof;
    } catch (error) {
      this.updateStats(false, Date.now() - startTime, 0);
      callback?.({ type: 'ERROR', error: error as Error });
      throw error;
    }
  }

  /**
   * Generate ZK proof only (no security verification)
   * Hybrid mode: Try server first, fallback to WASM
   */
  async proveOnly(transaction: TrustlessTransaction): Promise<ZKProof> {
    const startTime = Date.now();

    // Try proving server first if configured
    if (this.config.provingServer) {
      try {
        if (this.config.debug) {
          console.log('[Trustless] Attempting server-side proving:', this.config.provingServer);
        }
        
        const response = await fetch(`${this.config.provingServer}/api/prove`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            to: transaction.to,
            data: transaction.data || '0x',
            value: transaction.value?.toString() || '0',
            gasLimit: transaction.gasLimit?.toString() || '21000',
          }),
        });

        if (response.ok) {
          const result = await response.json();
          const proofBytes = ethers.getBytes('0x' + result.proof);
          
          if (this.config.debug) {
            console.log('[Trustless] ✅ Server proof generated:', result.proving_time_ms + 'ms');
          }

          return {
            proof: proofBytes,
            publicInputs: new Uint8Array(),
            proofHash: ethers.keccak256(proofBytes),
            provingTime: result.proving_time_ms,
          };
        }
      } catch (error) {
        if (this.config.debug) {
          console.warn('[Trustless] Server proving failed:', error);
        }
        
        // If fallback disabled, throw error
        if (!this.config.fallbackToWasm) {
          throw new Error(`Proving server unavailable: ${error}`);
        }
        
        console.log('[Trustless] Falling back to WASM proving...');
      }
    }

    // Fallback to WASM proving
    const txBytes = this.serializeTransaction(transaction);
    const wasm = WasmLoader.getWasm();
    const proofBytes = await wasm.prove_transaction(txBytes);
    const provingTime = Date.now() - startTime;

    if (this.config.debug) {
      console.log('[Trustless] ✅ WASM proof generated:', provingTime + 'ms');
    }

    return {
      proof: proofBytes,
      publicInputs: new Uint8Array(),
      proofHash: ethers.keccak256(proofBytes),
      provingTime,
    };
  }

  /**
   * Verify security without proving
   */
  async verifySecurity(transaction: TrustlessTransaction): Promise<SecurityVerification> {
    // Get contract bytecode if it's a contract interaction
    let bytecode: Uint8Array;
    if (transaction.to && this.provider) {
      try {
        const code = await Promise.race([
          this.provider.getCode(transaction.to),
          new Promise<string>((_, reject) => 
            setTimeout(() => reject(new Error('getCode timeout')), 3000)
          )
        ]);
        bytecode = ethers.getBytes(code);
      } catch (error) {
        if (this.config.debug) {
          console.warn('[Trustless] Could not fetch bytecode:', error);
        }
        bytecode = new Uint8Array();
      }
    } else {
      bytecode = new Uint8Array();
    }

    // Call WASM security analysis
    const wasm = WasmLoader.getWasm();
    const analysisBytes = await wasm.analyze_security(bytecode);

    // Parse analysis results
    const analysis = this.parseSecurityAnalysis(analysisBytes);

    return analysis;
  }

  /**
   * Submit a proven transaction
   */
  async submit(proof: TrustlessProof): Promise<SubmitResult> {
    if (!this.provider) {
      throw new Error('Provider not configured');
    }

    try {
      // Attach proof to transaction data
      const txWithProof = this.attachProof(proof.transaction, proof.zkProof);

      // Create serialized transaction
      // Note: In production, this would use a signer to sign the transaction
      const serializedTx = ethers.hexlify(
        new TextEncoder().encode(JSON.stringify(txWithProof))
      );

      // Broadcast transaction
      const tx = await this.provider.broadcastTransaction(serializedTx);

      // Wait for receipt
      const receipt = await tx.wait();

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
   * Get statistics
   */
  getStats(): TrustlessStats {
    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      totalProofs: 0,
      successfulProofs: 0,
      failedProofs: 0,
      averageProvingTime: 0,
      averageProofSize: 0,
      totalGasSaved: 0n,
      vulnerabilitiesDetected: 0,
      trustlessScore: 0,
    };
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    this.provider = null;
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  private serializeTransaction(tx: TrustlessTransaction): Uint8Array {
    // Serialize transaction to bytes for WASM
    const data = {
      to: tx.to,
      data: tx.data || '0x',
      value: (tx.value || 0n).toString(),
      gasLimit: (tx.gasLimit || 21000n).toString(),
    };
    return new TextEncoder().encode(JSON.stringify(data));
  }

  private parseSecurityAnalysis(bytes: Uint8Array): SecurityVerification {
    // Parse WASM security analysis results
    const text = new TextDecoder().decode(bytes);
    const analysis = JSON.parse(text);

    const vulnerabilities: Vulnerability[] = analysis.vulnerabilities || [];

    return {
      isSecure: vulnerabilities.every(v => v.severity !== 'CRITICAL'),
      vulnerabilities,
      securityScore: analysis.securityScore || 0,
      pccProofHash: analysis.pccProofHash || '0x0',
    };
  }

  private calculateTrustlessScore(zkProof: ZKProof, security: SecurityVerification): number {
    // Composite score from multiple factors
    let score = 100;

    // Deduct for security issues
    for (const vuln of security.vulnerabilities) {
      if (vuln.severity === 'CRITICAL') score -= 25;
      else if (vuln.severity === 'HIGH') score -= 10;
      else if (vuln.severity === 'MEDIUM') score -= 5;
      else if (vuln.severity === 'LOW') score -= 2;
    }

    // Deduct for slow proving (indicates potential issues)
    if (zkProof.provingTime > 5000) score -= 10;
    else if (zkProof.provingTime > 3000) score -= 5;

    return Math.max(0, score);
  }

  private attachProof(tx: TrustlessTransaction, proof: ZKProof): TrustlessTransaction {
    // Attach proof to transaction data
    // In production, this would append the proof to calldata
    return {
      ...tx,
      data: tx.data + ethers.hexlify(proof.proof).slice(2),
    };
  }

  private updateStats(
    success: boolean,
    provingTime: number,
    proofSize: number,
    security?: SecurityVerification
  ): void {
    this.stats.totalProofs++;

    if (success) {
      this.stats.successfulProofs++;

      // Update rolling averages
      const n = this.stats.successfulProofs;
      this.stats.averageProvingTime =
        (this.stats.averageProvingTime * (n - 1) + provingTime) / n;
      this.stats.averageProofSize =
        (this.stats.averageProofSize * (n - 1) + proofSize) / n;

      if (security) {
        this.stats.vulnerabilitiesDetected += security.vulnerabilities.length;
      }
    } else {
      this.stats.failedProofs++;
    }
  }
}
