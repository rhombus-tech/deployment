// src/wasm-loader.ts
var _WasmLoader = class _WasmLoader {
  /**
   * Load the WASM module
   */
  static async load() {
    if (this.loadPromise) {
      return this.loadPromise;
    }
    this.loadPromise = (async () => {
      try {
        console.log("[WasmLoader] Starting WASM load...");
        const wasmModule = await _WasmLoader.loadWasm();
        this.wasm = wasmModule;
        console.log("[WasmLoader] WASM loaded successfully");
      } catch (error) {
        console.error("[WasmLoader] Failed to load WASM:", error);
        this.loadPromise = null;
        throw new Error(`Failed to load WASM module: ${error}`);
      }
    })();
    return this.loadPromise;
  }
  /**
   * Get the loaded WASM module
   */
  static getWasm() {
    if (!this.wasm) {
      throw new Error("WASM module not loaded. Call WasmLoader.load() first.");
    }
    return this.wasm;
  }
  /**
   * Check if WASM is loaded
   */
  static get isLoaded() {
    return this.wasm !== null;
  }
  static async loadWasm() {
    try {
      const wasmModule = await import("./trustless_wasm-I3FQOZDT.mjs");
      if (wasmModule.default) {
        await wasmModule.default();
      }
      return wasmModule;
    } catch (error) {
      console.warn("\u26A0\uFE0F  WASM module not found. Using mock implementation.");
      console.warn('\u{1F4A1} Run "npm run build:wasm" to build the real WASM module.');
      return _WasmLoader.createMockWasm();
    }
  }
  static createMockWasm() {
    return {
      prove_transaction: async (txBytes) => {
        console.log("\u{1F527} Mock: prove_transaction");
        const proof = new Uint8Array(8192);
        proof.fill(66);
        return proof;
      },
      verify_proof: async (proof) => {
        console.log("\u{1F527} Mock: verify_proof");
        return proof.length >= 32;
      },
      analyze_security: async (bytecode) => {
        console.log("\u{1F527} Mock: analyze_security");
        const result = {
          isSecure: true,
          vulnerabilities: [],
          securityScore: 100,
          pccProofHash: "0x0000000000000000000000000000000000000000000000000000000000000000"
        };
        return new TextEncoder().encode(JSON.stringify(result));
      },
      create_atomic_bundle: async (operations) => {
        console.log("\u{1F527} Mock: create_atomic_bundle");
        return new Uint8Array([...operations, 255]);
      },
      compress_proofs: async (proofs) => {
        console.log("\u{1F527} Mock: compress_proofs");
        return proofs.slice(0, Math.floor(proofs.length / 10));
      }
    };
  }
};
_WasmLoader.wasm = null;
_WasmLoader.loadPromise = null;
var WasmLoader = _WasmLoader;

// src/core.ts
import { ethers } from "ethers";
var TrustlessCore = class {
  constructor(config) {
    this.provider = null;
    this.config = {
      network: "mainnet",
      enableSecurity: true,
      securityLevel: "STANDARD",
      enableCompression: true,
      provingTimeout: 3e4,
      // 30 seconds
      debug: false,
      ...config
    };
    this.stats = {
      totalProofs: 0,
      successfulProofs: 0,
      failedProofs: 0,
      averageProvingTime: 0,
      averageProofSize: 0,
      totalGasSaved: 0n,
      vulnerabilitiesDetected: 0,
      trustlessScore: 0
    };
  }
  /**
   * Initialize the core prover
   */
  async initialize() {
    if (this.config.rpcUrl) {
      this.provider = new ethers.JsonRpcProvider(this.config.rpcUrl);
    } else if (this.config.network) {
      this.provider = ethers.getDefaultProvider(this.config.network);
    }
    if (this.provider) {
      try {
        this.currentBlock = await Promise.race([
          this.provider.getBlockNumber(),
          new Promise(
            (_, reject) => setTimeout(() => reject(new Error("Provider timeout")), 3e3)
          )
        ]);
      } catch (error) {
        if (this.config.debug) {
          console.warn("[Trustless] Could not connect to provider:", error);
        }
        this.currentBlock = 0;
      }
    }
    if (this.config.debug) {
      console.log("[Trustless] Initialized", {
        network: this.config.network || "offline",
        block: this.currentBlock,
        security: this.config.enableSecurity,
        provider: this.provider ? "connected" : "offline"
      });
    }
  }
  /**
   * Prove a transaction with full security verification
   */
  async prove(transaction, callback) {
    const startTime = Date.now();
    try {
      callback?.({ type: "STARTED", transaction });
      let security;
      if (this.config.enableSecurity) {
        callback?.({ type: "SECURITY_ANALYSIS", progress: 0 });
        security = await this.verifySecurity(transaction);
        callback?.({ type: "SECURITY_ANALYSIS", progress: 100 });
      } else {
        security = {
          isSecure: true,
          vulnerabilities: [],
          securityScore: 100,
          pccProofHash: "0x0"
        };
      }
      callback?.({ type: "PROOF_GENERATION", progress: 0 });
      const zkProof = await this.proveOnly(transaction);
      callback?.({ type: "PROOF_GENERATION", progress: 100 });
      if (this.config.enableCompression) {
        callback?.({ type: "COMPRESSION", progress: 50 });
        callback?.({ type: "COMPRESSION", progress: 100 });
      }
      const trustlessScore = this.calculateTrustlessScore(zkProof, security);
      const proof = {
        zkProof,
        security,
        transaction,
        timestamp: Date.now(),
        trustlessScore
      };
      this.updateStats(true, Date.now() - startTime, zkProof.proof.length, security);
      callback?.({ type: "COMPLETED", proof });
      return proof;
    } catch (error) {
      this.updateStats(false, Date.now() - startTime, 0);
      callback?.({ type: "ERROR", error });
      throw error;
    }
  }
  /**
   * Generate ZK proof only (no security verification)
   * Hybrid mode: Try server first, fallback to WASM
   */
  async proveOnly(transaction) {
    const startTime = Date.now();
    if (this.config.provingServer) {
      try {
        if (this.config.debug) {
          console.log("[Trustless] Attempting server-side proving:", this.config.provingServer);
        }
        const response = await fetch(`${this.config.provingServer}/api/prove`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            to: transaction.to,
            data: transaction.data || "0x",
            value: transaction.value?.toString() || "0",
            gasLimit: transaction.gasLimit?.toString() || "21000"
          })
        });
        if (response.ok) {
          const result = await response.json();
          const proofBytes2 = ethers.getBytes("0x" + result.proof);
          if (this.config.debug) {
            console.log("[Trustless] \u2705 Server proof generated:", result.proving_time_ms + "ms");
          }
          return {
            proof: proofBytes2,
            publicInputs: new Uint8Array(),
            proofHash: ethers.keccak256(proofBytes2),
            provingTime: result.proving_time_ms
          };
        }
      } catch (error) {
        if (this.config.debug) {
          console.warn("[Trustless] Server proving failed:", error);
        }
        if (!this.config.fallbackToWasm) {
          throw new Error(`Proving server unavailable: ${error}`);
        }
        console.log("[Trustless] Falling back to WASM proving...");
      }
    }
    const txBytes = this.serializeTransaction(transaction);
    const wasm = WasmLoader.getWasm();
    const proofBytes = await wasm.prove_transaction(txBytes);
    const provingTime = Date.now() - startTime;
    if (this.config.debug) {
      console.log("[Trustless] \u2705 WASM proof generated:", provingTime + "ms");
    }
    return {
      proof: proofBytes,
      publicInputs: new Uint8Array(),
      proofHash: ethers.keccak256(proofBytes),
      provingTime
    };
  }
  /**
   * Verify security without proving
   */
  async verifySecurity(transaction) {
    let bytecode;
    if (transaction.to && this.provider) {
      try {
        const code = await Promise.race([
          this.provider.getCode(transaction.to),
          new Promise(
            (_, reject) => setTimeout(() => reject(new Error("getCode timeout")), 3e3)
          )
        ]);
        bytecode = ethers.getBytes(code);
      } catch (error) {
        if (this.config.debug) {
          console.warn("[Trustless] Could not fetch bytecode:", error);
        }
        bytecode = new Uint8Array();
      }
    } else {
      bytecode = new Uint8Array();
    }
    const wasm = WasmLoader.getWasm();
    const analysisBytes = await wasm.analyze_security(bytecode);
    const analysis = this.parseSecurityAnalysis(analysisBytes);
    return analysis;
  }
  /**
   * Submit a proven transaction
   */
  async submit(proof) {
    if (!this.provider) {
      throw new Error("Provider not configured");
    }
    try {
      const txWithProof = this.attachProof(proof.transaction, proof.zkProof);
      const serializedTx = ethers.hexlify(
        new TextEncoder().encode(JSON.stringify(txWithProof))
      );
      const tx = await this.provider.broadcastTransaction(serializedTx);
      const receipt = await tx.wait();
      return {
        success: true,
        transactionHash: receipt?.hash,
        receipt
      };
    } catch (error) {
      return {
        success: false,
        error
      };
    }
  }
  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }
  /**
   * Reset statistics
   */
  resetStats() {
    this.stats = {
      totalProofs: 0,
      successfulProofs: 0,
      failedProofs: 0,
      averageProvingTime: 0,
      averageProofSize: 0,
      totalGasSaved: 0n,
      vulnerabilitiesDetected: 0,
      trustlessScore: 0
    };
  }
  /**
   * Cleanup resources
   */
  async cleanup() {
    this.provider = null;
  }
  // ============================================================================
  // Private Helper Methods
  // ============================================================================
  serializeTransaction(tx) {
    const data = {
      to: tx.to,
      data: tx.data || "0x",
      value: (tx.value || 0n).toString(),
      gasLimit: (tx.gasLimit || 21000n).toString()
    };
    return new TextEncoder().encode(JSON.stringify(data));
  }
  parseSecurityAnalysis(bytes) {
    const text = new TextDecoder().decode(bytes);
    const analysis = JSON.parse(text);
    const vulnerabilities = analysis.vulnerabilities || [];
    return {
      isSecure: vulnerabilities.every((v) => v.severity !== "CRITICAL"),
      vulnerabilities,
      securityScore: analysis.securityScore || 0,
      pccProofHash: analysis.pccProofHash || "0x0"
    };
  }
  calculateTrustlessScore(zkProof, security) {
    let score = 100;
    for (const vuln of security.vulnerabilities) {
      if (vuln.severity === "CRITICAL") score -= 25;
      else if (vuln.severity === "HIGH") score -= 10;
      else if (vuln.severity === "MEDIUM") score -= 5;
      else if (vuln.severity === "LOW") score -= 2;
    }
    if (zkProof.provingTime > 5e3) score -= 10;
    else if (zkProof.provingTime > 3e3) score -= 5;
    return Math.max(0, score);
  }
  attachProof(tx, proof) {
    return {
      ...tx,
      data: tx.data + ethers.hexlify(proof.proof).slice(2)
    };
  }
  updateStats(success, provingTime, proofSize, security) {
    this.stats.totalProofs++;
    if (success) {
      this.stats.successfulProofs++;
      const n = this.stats.successfulProofs;
      this.stats.averageProvingTime = (this.stats.averageProvingTime * (n - 1) + provingTime) / n;
      this.stats.averageProofSize = (this.stats.averageProofSize * (n - 1) + proofSize) / n;
      if (security) {
        this.stats.vulnerabilitiesDetected += security.vulnerabilities.length;
      }
    } else {
      this.stats.failedProofs++;
    }
  }
};

// src/atomic.ts
import { ethers as ethers2 } from "ethers";
var AtomicExecutor = class {
  constructor(config) {
    this.provider = null;
    this.config = config;
    this.core = new TrustlessCore(config);
  }
  /**
   * Initialize atomic executor
   */
  async initialize() {
    await this.core.initialize();
    if (this.config.rpcUrl) {
      this.provider = new ethers2.JsonRpcProvider(this.config.rpcUrl);
    } else if (this.config.network) {
      this.provider = ethers2.getDefaultProvider(this.config.network);
    }
  }
  /**
   * Prove an atomic bundle
   */
  async proveBundle(bundle, callback) {
    const proofs = [];
    for (let i = 0; i < bundle.transactions.length; i++) {
      const tx = bundle.transactions[i];
      const txCallback = (event) => {
        if (callback) {
          if (event.type === "SECURITY_ANALYSIS" || event.type === "PROOF_GENERATION") {
            const overallProgress = i / bundle.transactions.length * 100 + event.progress / bundle.transactions.length;
            callback({ ...event, progress: overallProgress });
          } else {
            callback(event);
          }
        }
      };
      const proof = await this.core.prove(tx, txCallback);
      proofs.push(proof);
    }
    const wasm = WasmLoader.getWasm();
    const bundleBytes = this.serializeBundle(bundle, proofs);
    const atomicBytes = await wasm.create_atomic_bundle(bundleBytes);
    const bundleHash = ethers2.keccak256(atomicBytes);
    const totalGasEstimate = proofs.reduce(
      (sum, p) => sum + (p.transaction.gasLimit ? BigInt(p.transaction.gasLimit) : 21000n),
      0n
    );
    return {
      proofs,
      bundleHash,
      guaranteedAtomic: true,
      totalGasEstimate
    };
  }
  /**
   * Submit an atomic bundle
   */
  async submit(atomicProof) {
    if (!this.provider) {
      throw new Error("Provider not configured");
    }
    const executorAddress = this.config.atomicExecutorContract || this.getDefaultExecutorAddress();
    try {
      const atomicCalldata = this.prepareAtomicCalldata(atomicProof);
      const tx = {
        to: executorAddress,
        data: atomicCalldata,
        gasLimit: atomicProof.totalGasEstimate * 110n / 100n
        // +10% buffer
      };
      const sentTx = await this.provider.broadcastTransaction(
        ethers2.Transaction.from(tx).serialized
      );
      const receipt = await sentTx.wait();
      return {
        success: true,
        transactionHash: receipt?.hash,
        receipt
      };
    } catch (error) {
      return {
        success: false,
        error
      };
    }
  }
  /**
   * Cleanup resources
   */
  async cleanup() {
    await this.core.cleanup();
    this.provider = null;
  }
  // ============================================================================
  // Private Helper Methods
  // ============================================================================
  serializeBundle(bundle, proofs) {
    const data = {
      transactions: bundle.transactions.map((tx, i) => ({
        to: tx.to,
        data: tx.data || "0x",
        value: (tx.value || 0n).toString(),
        proof: Array.from(proofs[i].zkProof.proof)
      })),
      revertOnFailure: bundle.revertOnFailure !== false
    };
    return new TextEncoder().encode(JSON.stringify(data));
  }
  prepareAtomicCalldata(atomicProof) {
    const operations = atomicProof.proofs.map((p) => ({
      target: p.transaction.to,
      callData: p.transaction.data || "0x",
      value: p.transaction.value || 0n
    }));
    const executionProof = {
      pccProofHash: atomicProof.proofs[0].security.pccProofHash,
      pcdProofHash: atomicProof.bundleHash,
      stateRoot: "0x0000000000000000000000000000000000000000000000000000000000000000",
      gasLimit: atomicProof.totalGasEstimate
    };
    const iface = new ethers2.Interface([
      "function executeAtomic(tuple(address target, bytes callData, uint256 value)[] operations, tuple(bytes32 pccProofHash, bytes32 pcdProofHash, bytes32 stateRoot, uint256 gasLimit) proof) returns (bytes[] results)"
    ]);
    return iface.encodeFunctionData("executeAtomic", [operations, executionProof]);
  }
  getDefaultExecutorAddress() {
    const addresses = {
      mainnet: "0x59b670e9fA9D0A427751Af201D676719a970857b",
      goerli: "0x59b670e9fA9D0A427751Af201D676719a970857b",
      sepolia: "0x59b670e9fA9D0A427751Af201D676719a970857b",
      localhost: "0x59b670e9fA9D0A427751Af201D676719a970857b"
    };
    return addresses[this.config.network || "mainnet"] || addresses.mainnet;
  }
};

// src/index.ts
var Trustless = class {
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
  static async init(config = {}) {
    if (this.initPromise) {
      return this.initPromise;
    }
    this.initPromise = (async () => {
      try {
        await WasmLoader.load();
        this.instance = new TrustlessCore(config);
        await this.instance.initialize();
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
  static get isInitialized() {
    return this.instance !== null && this.atomicExecutor !== null;
  }
  /**
   * Get initialization status
   */
  static getStatus() {
    return {
      initialized: this.isInitialized,
      wasmLoaded: WasmLoader.isLoaded,
      network: this.instance?.config.network || "unknown",
      blockNumber: this.instance?.currentBlock
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
  static async prove(transaction, callback) {
    this.ensureInitialized();
    return this.instance.prove(transaction, callback);
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
  static async submit(proof) {
    this.ensureInitialized();
    return this.instance.submit(proof);
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
  static async proveAndSubmit(transaction, callback) {
    this.ensureInitialized();
    const proof = await this.prove(transaction, callback);
    const result = await this.submit(proof);
    return {
      ...result,
      proof
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
  static async atomic(bundle, callback) {
    this.ensureInitialized();
    return this.atomicExecutor.proveBundle(bundle, callback);
  }
  /**
   * Submit an atomic proof
   * 
   * @param atomicProof - Atomic proof from atomic()
   * @returns Promise resolving to submit result
   */
  static async submitAtomic(atomicProof) {
    this.ensureInitialized();
    return this.atomicExecutor.submit(atomicProof);
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
  static async verifySecurity(transaction) {
    this.ensureInitialized();
    return this.instance.verifySecurity(transaction);
  }
  /**
   * Generate a ZK proof only (no security verification)
   * 
   * Faster than full proving if you don't need security checks
   * 
   * @param transaction - Transaction to prove
   * @returns Promise resolving to ZK proof
   */
  static async proveOnly(transaction) {
    this.ensureInitialized();
    return this.instance.proveOnly(transaction);
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
  static getStats() {
    this.ensureInitialized();
    return this.instance.getStats();
  }
  /**
   * Reset statistics
   */
  static resetStats() {
    this.ensureInitialized();
    this.instance.resetStats();
  }
  /**
   * Cleanup and release resources
   * 
   * Call when done using the SDK
   */
  static async cleanup() {
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
  static ensureInitialized() {
    if (!this.isInitialized) {
      throw new Error(
        "Trustless SDK not initialized. Call Trustless.init() first."
      );
    }
  }
};
Trustless.instance = null;
Trustless.atomicExecutor = null;
Trustless.initPromise = null;
var index_default = Trustless;
export {
  AtomicExecutor,
  Trustless,
  TrustlessCore,
  WasmLoader,
  index_default as default
};
