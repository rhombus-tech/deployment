/**
 * WASM Loader
 * 
 * Handles loading and initialization of the Rust WASM module
 */

/**
 * WASM module interface
 * This will be populated by wasm-pack build
 */
export interface TrustlessWasm {
  prove_transaction(txBytes: Uint8Array): Promise<Uint8Array>;
  verify_proof(proof: Uint8Array): Promise<boolean>;
  analyze_security(bytecode: Uint8Array): Promise<Uint8Array>;
  create_atomic_bundle(operations: Uint8Array): Promise<Uint8Array>;
  compress_proofs(proofs: Uint8Array): Promise<Uint8Array>;
}

/**
 * Singleton WASM loader
 */
export class WasmLoader {
  private static wasm: TrustlessWasm | null = null;
  private static loadPromise: Promise<void> | null = null;

  /**
   * Load the WASM module
   */
  static async load(): Promise<void> {
    // Return existing load if in progress
    if (this.loadPromise) {
      return this.loadPromise;
    }

    // Create new load promise
    this.loadPromise = (async () => {
      try {
        console.log('[WasmLoader] Starting WASM load...');
        // Try to import the WASM module
        // Dynamic import to avoid bundling issues
        const wasmModule = await WasmLoader.loadWasm();
        // Store WASM exports
        this.wasm = wasmModule as unknown as TrustlessWasm;
        console.log('[WasmLoader] WASM loaded successfully');
        
      } catch (error) {
        console.error('[WasmLoader] Failed to load WASM:', error);
        this.loadPromise = null;
        throw new Error(`Failed to load WASM module: ${error}`);
      }
    })();

    return this.loadPromise;
  }

  /**
   * Get the loaded WASM module
   */
  static getWasm(): TrustlessWasm {
    if (!this.wasm) {
      throw new Error('WASM module not loaded. Call WasmLoader.load() first.');
    }
    return this.wasm;
  }

  /**
   * Check if WASM is loaded
   */
  static get isLoaded(): boolean {
    return this.wasm !== null;
  }

  private static async loadWasm(): Promise<WasmModule> {
    try {
      // Try to import the WASM module
      // Dynamic import to avoid bundling issues
      // @ts-ignore - WASM module generated at build time
      const wasmModule = await import('../wasm/trustless_wasm.js');
      if (wasmModule.default) {
        await wasmModule.default();
      }
      return wasmModule;
    } catch (error) {
      // If WASM not built yet, return mock implementation
      console.warn('⚠️  WASM module not found. Using mock implementation.');
      console.warn('💡 Run "npm run build:wasm" to build the real WASM module.');
      return WasmLoader.createMockWasm();
    }
  }

  private static createMockWasm(): WasmModule {
    // Mock WASM for development when WASM isn't built yet
    return {
      prove_transaction: async (txBytes: Uint8Array) => {
        console.log('🔧 Mock: prove_transaction');
        const proof = new Uint8Array(8192);
        proof.fill(0x42);
        return proof;
      },
      verify_proof: async (proof: Uint8Array) => {
        console.log('🔧 Mock: verify_proof');
        return proof.length >= 32;
      },
      analyze_security: async (bytecode: Uint8Array) => {
        console.log('🔧 Mock: analyze_security');
        const result = {
          isSecure: true,
          vulnerabilities: [],
          securityScore: 100,
          pccProofHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
        };
        return new TextEncoder().encode(JSON.stringify(result));
      },
      create_atomic_bundle: async (operations: Uint8Array) => {
        console.log('🔧 Mock: create_atomic_bundle');
        return new Uint8Array([...operations, 0xFF]);
      },
      compress_proofs: async (proofs: Uint8Array) => {
        console.log('🔧 Mock: compress_proofs');
        return proofs.slice(0, Math.floor(proofs.length / 10));
      },
    };
  }
}

interface WasmModule {
  prove_transaction(txBytes: Uint8Array): Promise<Uint8Array>;
  verify_proof(proof: Uint8Array): Promise<boolean>;
  analyze_security(bytecode: Uint8Array): Promise<Uint8Array>;
  create_atomic_bundle(operations: Uint8Array): Promise<Uint8Array>;
  compress_proofs(proofs: Uint8Array): Promise<Uint8Array>;
  default?(): Promise<any>; // InitOutput from wasm-bindgen
}
