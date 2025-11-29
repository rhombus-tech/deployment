/**
 * @trustless/sdk
 * 
 * Client-side proving and atomic execution for Ethereum
 * Making trustlessness accessible to everyone
 * 
 * @example
 * ```typescript
 * import { Trustless } from '@trustless/sdk';
 * 
 * // Initialize
 * await Trustless.init({ network: 'mainnet' });
 * 
 * // Prove a transaction (< 2 seconds)
 * const proof = await Trustless.prove({
 *   to: '0x...',
 *   data: '0x...',
 *   value: 1000000000000000000n
 * });
 * 
 * // Submit with proof
 * const receipt = await Trustless.submit(proof);
 * ```
 */

import type {
  TrustlessConfig,
  TrustlessTransaction,
  TrustlessProof,
  AtomicBundle,
  AtomicProof,
  ProvingResult,
  SubmitResult,
  InitStatus,
  TrustlessStats,
  ProvingCallback,
  SecurityVerification,
  ZKProof,
} from './types';

export * from './types';

// Internal imports
import { TrustlessCore } from './core';
import { WasmLoader } from './wasm-loader';
import { AtomicExecutor } from './atomic';

/**
 * Main Trustless SDK class
 * 
 * Provides the primary API for client-side proving and trustless execution
 */
export class Trustless {
  private static instance: TrustlessCore | null = null;
  private static atomicExecutor: AtomicExecutor | null = null;
  private static initPromise: Promise<void> | null = null;

  /**
   * Initialize the Trustless SDK
   * 
   * Must be called before using any other methods
   * 
   * @param config - Configuration options
   * @returns Promise that resolves when initialization is complete
   * 
   * @example
   * ```typescript
   * await Trustless.init({ 
   *   network: 'mainnet',
   *   enableSecurity: true 
   * });
   * ```
   */
  static async init(config: TrustlessConfig = {}): Promise<void> {
    // Return existing initialization if in progress
    if (this.initPromise) {
      return this.initPromise;
    }

    // Create new initialization promise
    this.initPromise = (async () => {
      try {
        // Load WASM module
        await WasmLoader.load();

        // Initialize core prover
        this.instance = new TrustlessCore(config);
        await this.instance.initialize();

        // Initialize atomic executor
        this.atomicExecutor = new AtomicExecutor(config);
        await this.atomicExecutor.initialize();

      } catch (error) {
        this.initPromise = null;
        throw new Error(`Failed to initialize Trustless SDK: ${error}`);
      }
    })();

    return this.initPromise;
  }

  /**
   * Check if SDK is initialized
   */
  static get isInitialized(): boolean {
    return this.instance !== null && this.atomicExecutor !== null;
  }

  /**
   * Get initialization status
   */
  static getStatus(): InitStatus {
    return {
      initialized: this.isInitialized,
      wasmLoaded: WasmLoader.isLoaded,
      network: this.instance?.config.network || 'unknown',
      blockNumber: this.instance?.currentBlock,
    };
  }

  /**
   * Prove a transaction trustlessly
   * 
   * Generates a ZK proof and performs security verification
   * Proving time: typically < 2 seconds
   * 
   * @param transaction - Transaction to prove
   * @param callback - Optional callback for progress updates
   * @returns Promise resolving to trustless proof
   * 
   * @example
   * ```typescript
   * const proof = await Trustless.prove({
   *   to: uniswapRouter,
   *   data: swapCalldata,
   *   value: 1000000000000000000n
   * });
   * 
   * console.log('Trustless Score:', proof.trustlessScore); // 0-100
   * console.log('Security:', proof.security.isSecure);
   * console.log('Proving Time:', proof.zkProof.provingTime, 'ms');
   * ```
   */
  static async prove(
    transaction: TrustlessTransaction,
    callback?: ProvingCallback
  ): Promise<TrustlessProof> {
    this.ensureInitialized();
    return this.instance!.prove(transaction, callback);
  }

  /**
   * Submit a proven transaction to the blockchain
   * 
   * @param proof - Trustless proof from prove()
   * @returns Promise resolving to transaction receipt
   * 
   * @example
   * ```typescript
   * const proof = await Trustless.prove(transaction);
   * const receipt = await Trustless.submit(proof);
   * console.log('Transaction hash:', receipt.transactionHash);
   * ```
   */
  static async submit(proof: TrustlessProof): Promise<SubmitResult> {
    this.ensureInitialized();
    return this.instance!.submit(proof);
  }

  /**
   * Prove and submit in one call (convenience method)
   * 
   * @param transaction - Transaction to prove and submit
   * @returns Promise resolving to submit result with proof included
   * 
   * @example
   * ```typescript
   * const result = await Trustless.proveAndSubmit({
   *   to: '0x...',
   *   data: '0x...'
   * });
   * 
   * if (result.success) {
   *   console.log('Transaction submitted:', result.transactionHash);
   * }
   * ```
   */
  static async proveAndSubmit(
    transaction: TrustlessTransaction,
    callback?: ProvingCallback
  ): Promise<SubmitResult & { proof?: TrustlessProof }> {
    this.ensureInitialized();
    
    const proof = await this.prove(transaction, callback);
    const result = await this.submit(proof);
    
    return {
      ...result,
      proof,
    };
  }

  /**
   * Execute multiple transactions atomically
   * 
   * All transactions execute together or all fail together
   * No partial execution possible
   * 
   * @param bundle - Bundle of transactions to execute atomically
   * @param callback - Optional callback for progress updates
   * @returns Promise resolving to atomic proof
   * 
   * @example
   * ```typescript
   * const atomicProof = await Trustless.atomic({
   *   transactions: [
   *     { to: tokenA, data: approveCalldata },
   *     { to: dex, data: swapCalldata },
   *     { to: tokenB, data: transferCalldata }
   *   ]
   * });
   * 
   * console.log('Guaranteed atomic:', atomicProof.guaranteedAtomic); // true
   * const receipt = await Trustless.submitAtomic(atomicProof);
   * ```
   */
  static async atomic(
    bundle: AtomicBundle,
    callback?: ProvingCallback
  ): Promise<AtomicProof> {
    this.ensureInitialized();
    return this.atomicExecutor!.proveBundle(bundle, callback);
  }

  /**
   * Submit an atomic proof
   * 
   * @param atomicProof - Atomic proof from atomic()
   * @returns Promise resolving to submit result
   */
  static async submitAtomic(atomicProof: AtomicProof): Promise<SubmitResult> {
    this.ensureInitialized();
    return this.atomicExecutor!.submit(atomicProof);
  }

  /**
   * Verify security of a transaction without proving
   * 
   * Faster than full proving (typically < 100ms)
   * Useful for pre-flight checks
   * 
   * @param transaction - Transaction to analyze
   * @returns Promise resolving to security verification
   * 
   * @example
   * ```typescript
   * const security = await Trustless.verifySecurity({
   *   to: contract,
   *   data: calldata
   * });
   * 
   * if (!security.isSecure) {
   *   console.warn('Vulnerabilities:', security.vulnerabilities);
   * }
   * ```
   */
  static async verifySecurity(
    transaction: TrustlessTransaction
  ): Promise<SecurityVerification> {
    this.ensureInitialized();
    return this.instance!.verifySecurity(transaction);
  }

  /**
   * Generate a ZK proof only (no security verification)
   * 
   * Faster than full proving if you don't need security checks
   * 
   * @param transaction - Transaction to prove
   * @returns Promise resolving to ZK proof
   */
  static async proveOnly(transaction: TrustlessTransaction): Promise<ZKProof> {
    this.ensureInitialized();
    return this.instance!.proveOnly(transaction);
  }

  /**
   * Get SDK statistics
   * 
   * @returns Current statistics
   * 
   * @example
   * ```typescript
   * const stats = Trustless.getStats();
   * console.log('Total proofs generated:', stats.totalProofs);
   * console.log('Average proving time:', stats.averageProvingTime, 'ms');
   * console.log('Average trustless score:', stats.trustlessScore);
   * ```
   */
  static getStats(): TrustlessStats {
    this.ensureInitialized();
    return this.instance!.getStats();
  }

  /**
   * Reset statistics
   */
  static resetStats(): void {
    this.ensureInitialized();
    this.instance!.resetStats();
  }

  /**
   * Cleanup and release resources
   * 
   * Call when done using the SDK
   */
  static async cleanup(): Promise<void> {
    if (this.instance) {
      await this.instance.cleanup();
      this.instance = null;
    }
    if (this.atomicExecutor) {
      await this.atomicExecutor.cleanup();
      this.atomicExecutor = null;
    }
    this.initPromise = null;
  }

  /**
   * Ensure SDK is initialized, throw if not
   */
  private static ensureInitialized(): void {
    if (!this.isInitialized) {
      throw new Error(
        'Trustless SDK not initialized. Call Trustless.init() first.'
      );
    }
  }
}

/**
 * Default export for convenience
 */
export default Trustless;

/**
 * Named exports for tree-shaking
 */
export { TrustlessCore, WasmLoader, AtomicExecutor };
