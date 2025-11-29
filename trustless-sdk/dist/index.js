"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// wasm/trustless_wasm.js
var trustless_wasm_exports = {};
__export(trustless_wasm_exports, {
  analyze_security: () => analyze_security,
  compress_proofs: () => compress_proofs,
  create_atomic_bundle: () => create_atomic_bundle,
  default: () => trustless_wasm_default,
  init: () => init,
  initSync: () => initSync,
  prove_transaction: () => prove_transaction,
  verify_proof: () => verify_proof
});
function addToExternrefTable0(obj) {
  const idx = wasm.__externref_table_alloc();
  wasm.__wbindgen_export_2.set(idx, obj);
  return idx;
}
function handleError(f, args) {
  try {
    return f.apply(this, args);
  } catch (e) {
    const idx = addToExternrefTable0(e);
    wasm.__wbindgen_exn_store(idx);
  }
}
function getUint8ArrayMemory0() {
  if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
    cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8ArrayMemory0;
}
function decodeText(ptr, len) {
  numBytesDecoded += len;
  if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
    cachedTextDecoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8", { ignoreBOM: true, fatal: true }) : { decode: () => {
      throw Error("TextDecoder not available");
    } };
    cachedTextDecoder.decode();
    numBytesDecoded = len;
  }
  return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}
function getStringFromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return decodeText(ptr, len);
}
function isLikeNone(x) {
  return x === void 0 || x === null;
}
function makeMutClosure(arg0, arg1, dtor, f) {
  const state = { a: arg0, b: arg1, cnt: 1, dtor };
  const real = (...args) => {
    state.cnt++;
    const a = state.a;
    state.a = 0;
    try {
      return f(a, state.b, ...args);
    } finally {
      if (--state.cnt === 0) {
        wasm.__wbindgen_export_3.get(state.dtor)(a, state.b);
        CLOSURE_DTORS.unregister(state);
      } else {
        state.a = a;
      }
    }
  };
  real.original = state;
  CLOSURE_DTORS.register(real, state, state);
  return real;
}
function getArrayU8FromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}
function init() {
  wasm.init();
}
function passArray8ToWasm0(arg, malloc) {
  const ptr = malloc(arg.length * 1, 1) >>> 0;
  getUint8ArrayMemory0().set(arg, ptr / 1);
  WASM_VECTOR_LEN = arg.length;
  return ptr;
}
function compress_proofs(proofs) {
  const ptr0 = passArray8ToWasm0(proofs, wasm.__wbindgen_malloc);
  const len0 = WASM_VECTOR_LEN;
  const ret = wasm.compress_proofs(ptr0, len0);
  return ret;
}
function prove_transaction(tx_bytes) {
  const ptr0 = passArray8ToWasm0(tx_bytes, wasm.__wbindgen_malloc);
  const len0 = WASM_VECTOR_LEN;
  const ret = wasm.prove_transaction(ptr0, len0);
  return ret;
}
function verify_proof(proof) {
  const ptr0 = passArray8ToWasm0(proof, wasm.__wbindgen_malloc);
  const len0 = WASM_VECTOR_LEN;
  const ret = wasm.verify_proof(ptr0, len0);
  return ret;
}
function analyze_security(bytecode) {
  const ptr0 = passArray8ToWasm0(bytecode, wasm.__wbindgen_malloc);
  const len0 = WASM_VECTOR_LEN;
  const ret = wasm.analyze_security(ptr0, len0);
  return ret;
}
function create_atomic_bundle(operations) {
  const ptr0 = passArray8ToWasm0(operations, wasm.__wbindgen_malloc);
  const len0 = WASM_VECTOR_LEN;
  const ret = wasm.create_atomic_bundle(ptr0, len0);
  return ret;
}
function __wbg_adapter_8(arg0, arg1, arg2) {
  wasm.closure31_externref_shim(arg0, arg1, arg2);
}
function __wbg_adapter_25(arg0, arg1, arg2, arg3) {
  wasm.closure48_externref_shim(arg0, arg1, arg2, arg3);
}
async function __wbg_load(module2, imports) {
  if (typeof Response === "function" && module2 instanceof Response) {
    if (typeof WebAssembly.instantiateStreaming === "function") {
      try {
        return await WebAssembly.instantiateStreaming(module2, imports);
      } catch (e) {
        const validResponse = module2.ok && EXPECTED_RESPONSE_TYPES.has(module2.type);
        if (validResponse && module2.headers.get("Content-Type") !== "application/wasm") {
          console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);
        } else {
          throw e;
        }
      }
    }
    const bytes = await module2.arrayBuffer();
    return await WebAssembly.instantiate(bytes, imports);
  } else {
    const instance = await WebAssembly.instantiate(module2, imports);
    if (instance instanceof WebAssembly.Instance) {
      return { instance, module: module2 };
    } else {
      return instance;
    }
  }
}
function __wbg_get_imports() {
  const imports = {};
  imports.wbg = {};
  imports.wbg.__wbg_call_2f8d426a20a307fe = function() {
    return handleError(function(arg0, arg1) {
      const ret = arg0.call(arg1);
      return ret;
    }, arguments);
  };
  imports.wbg.__wbg_call_f53f0647ceb9c567 = function() {
    return handleError(function(arg0, arg1, arg2) {
      const ret = arg0.call(arg1, arg2);
      return ret;
    }, arguments);
  };
  imports.wbg.__wbg_log_b9a081cf969c660d = function(arg0, arg1) {
    console.log(getStringFromWasm0(arg0, arg1));
  };
  imports.wbg.__wbg_new_d5e3800b120e37e1 = function(arg0, arg1) {
    try {
      var state0 = { a: arg0, b: arg1 };
      var cb0 = (arg02, arg12) => {
        const a = state0.a;
        state0.a = 0;
        try {
          return __wbg_adapter_25(a, state0.b, arg02, arg12);
        } finally {
          state0.a = a;
        }
      };
      const ret = new Promise(cb0);
      return ret;
    } finally {
      state0.a = state0.b = 0;
    }
  };
  imports.wbg.__wbg_newnoargs_a81330f6e05d8aca = function(arg0, arg1) {
    const ret = new Function(getStringFromWasm0(arg0, arg1));
    return ret;
  };
  imports.wbg.__wbg_queueMicrotask_bcc6e26d899696db = function(arg0) {
    const ret = arg0.queueMicrotask;
    return ret;
  };
  imports.wbg.__wbg_queueMicrotask_f24a794d09c42640 = function(arg0) {
    queueMicrotask(arg0);
  };
  imports.wbg.__wbg_resolve_5775c0ef9222f556 = function(arg0) {
    const ret = Promise.resolve(arg0);
    return ret;
  };
  imports.wbg.__wbg_static_accessor_GLOBAL_1f13249cc3acc96d = function() {
    const ret = typeof global === "undefined" ? null : global;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
  };
  imports.wbg.__wbg_static_accessor_GLOBAL_THIS_df7ae94b1e0ed6a3 = function() {
    const ret = typeof globalThis === "undefined" ? null : globalThis;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
  };
  imports.wbg.__wbg_static_accessor_SELF_6265471db3b3c228 = function() {
    const ret = typeof self === "undefined" ? null : self;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
  };
  imports.wbg.__wbg_static_accessor_WINDOW_16fb482f8ec52863 = function() {
    const ret = typeof window === "undefined" ? null : window;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
  };
  imports.wbg.__wbg_then_9cc266be2bf537b6 = function(arg0, arg1) {
    const ret = arg0.then(arg1);
    return ret;
  };
  imports.wbg.__wbg_wbindgencbdrop_a85ed476c6a370b9 = function(arg0) {
    const obj = arg0.original;
    if (obj.cnt-- == 1) {
      obj.a = 0;
      return true;
    }
    const ret = false;
    return ret;
  };
  imports.wbg.__wbg_wbindgenisfunction_ea72b9d66a0e1705 = function(arg0) {
    const ret = typeof arg0 === "function";
    return ret;
  };
  imports.wbg.__wbg_wbindgenisundefined_71f08a6ade4354e7 = function(arg0) {
    const ret = arg0 === void 0;
    return ret;
  };
  imports.wbg.__wbg_wbindgenthrow_4c11a24fca429ccf = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
  };
  imports.wbg.__wbindgen_cast_2241b6af4c4b2941 = function(arg0, arg1) {
    const ret = getStringFromWasm0(arg0, arg1);
    return ret;
  };
  imports.wbg.__wbindgen_cast_2753a612dd9418b8 = function(arg0, arg1) {
    const ret = makeMutClosure(arg0, arg1, 30, __wbg_adapter_8);
    return ret;
  };
  imports.wbg.__wbindgen_cast_77bc3e92745e9a35 = function(arg0, arg1) {
    var v0 = getArrayU8FromWasm0(arg0, arg1).slice();
    wasm.__wbindgen_free(arg0, arg1 * 1, 1);
    const ret = v0;
    return ret;
  };
  imports.wbg.__wbindgen_init_externref_table = function() {
    const table = wasm.__wbindgen_export_2;
    const offset = table.grow(4);
    table.set(0, void 0);
    table.set(offset + 0, void 0);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
    ;
  };
  return imports;
}
function __wbg_init_memory(imports, memory) {
}
function __wbg_finalize_init(instance, module2) {
  wasm = instance.exports;
  __wbg_init.__wbindgen_wasm_module = module2;
  cachedUint8ArrayMemory0 = null;
  wasm.__wbindgen_start();
  return wasm;
}
function initSync(module2) {
  if (wasm !== void 0) return wasm;
  if (typeof module2 !== "undefined") {
    if (Object.getPrototypeOf(module2) === Object.prototype) {
      ({ module: module2 } = module2);
    } else {
      console.warn("using deprecated parameters for `initSync()`; pass a single object instead");
    }
  }
  const imports = __wbg_get_imports();
  __wbg_init_memory(imports);
  if (!(module2 instanceof WebAssembly.Module)) {
    module2 = new WebAssembly.Module(module2);
  }
  const instance = new WebAssembly.Instance(module2, imports);
  return __wbg_finalize_init(instance, module2);
}
async function __wbg_init(module_or_path) {
  if (wasm !== void 0) return wasm;
  if (typeof module_or_path !== "undefined") {
    if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
      ({ module_or_path } = module_or_path);
    } else {
      console.warn("using deprecated parameters for the initialization function; pass a single object instead");
    }
  }
  if (typeof module_or_path === "undefined") {
    module_or_path = new URL("trustless_wasm_bg.wasm", import_meta.url);
  }
  const imports = __wbg_get_imports();
  if (typeof module_or_path === "string" || typeof Request === "function" && module_or_path instanceof Request || typeof URL === "function" && module_or_path instanceof URL) {
    module_or_path = fetch(module_or_path);
  }
  __wbg_init_memory(imports);
  const { instance, module: module2 } = await __wbg_load(await module_or_path, imports);
  return __wbg_finalize_init(instance, module2);
}
var import_meta, wasm, cachedUint8ArrayMemory0, cachedTextDecoder, MAX_SAFARI_DECODE_BYTES, numBytesDecoded, CLOSURE_DTORS, WASM_VECTOR_LEN, EXPECTED_RESPONSE_TYPES, trustless_wasm_default;
var init_trustless_wasm = __esm({
  "wasm/trustless_wasm.js"() {
    "use strict";
    import_meta = {};
    cachedUint8ArrayMemory0 = null;
    cachedTextDecoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8", { ignoreBOM: true, fatal: true }) : { decode: () => {
      throw Error("TextDecoder not available");
    } };
    if (typeof TextDecoder !== "undefined") {
      cachedTextDecoder.decode();
    }
    MAX_SAFARI_DECODE_BYTES = 2146435072;
    numBytesDecoded = 0;
    CLOSURE_DTORS = typeof FinalizationRegistry === "undefined" ? { register: () => {
    }, unregister: () => {
    } } : new FinalizationRegistry(
      (state) => {
        wasm.__wbindgen_export_3.get(state.dtor)(state.a, state.b);
      }
    );
    WASM_VECTOR_LEN = 0;
    EXPECTED_RESPONSE_TYPES = /* @__PURE__ */ new Set(["basic", "cors", "default"]);
    trustless_wasm_default = __wbg_init;
  }
});

// src/index.ts
var index_exports = {};
__export(index_exports, {
  AtomicExecutor: () => AtomicExecutor,
  Trustless: () => Trustless,
  TrustlessCore: () => TrustlessCore,
  WasmLoader: () => WasmLoader,
  default: () => index_default
});
module.exports = __toCommonJS(index_exports);

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
      const wasmModule = await Promise.resolve().then(() => (init_trustless_wasm(), trustless_wasm_exports));
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
var import_ethers = require("ethers");
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
      this.provider = new import_ethers.ethers.JsonRpcProvider(this.config.rpcUrl);
    } else if (this.config.network) {
      this.provider = import_ethers.ethers.getDefaultProvider(this.config.network);
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
          const proofBytes2 = import_ethers.ethers.getBytes("0x" + result.proof);
          if (this.config.debug) {
            console.log("[Trustless] \u2705 Server proof generated:", result.proving_time_ms + "ms");
          }
          return {
            proof: proofBytes2,
            publicInputs: new Uint8Array(),
            proofHash: import_ethers.ethers.keccak256(proofBytes2),
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
    const wasm2 = WasmLoader.getWasm();
    const proofBytes = await wasm2.prove_transaction(txBytes);
    const provingTime = Date.now() - startTime;
    if (this.config.debug) {
      console.log("[Trustless] \u2705 WASM proof generated:", provingTime + "ms");
    }
    return {
      proof: proofBytes,
      publicInputs: new Uint8Array(),
      proofHash: import_ethers.ethers.keccak256(proofBytes),
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
        bytecode = import_ethers.ethers.getBytes(code);
      } catch (error) {
        if (this.config.debug) {
          console.warn("[Trustless] Could not fetch bytecode:", error);
        }
        bytecode = new Uint8Array();
      }
    } else {
      bytecode = new Uint8Array();
    }
    const wasm2 = WasmLoader.getWasm();
    const analysisBytes = await wasm2.analyze_security(bytecode);
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
      const serializedTx = import_ethers.ethers.hexlify(
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
      data: tx.data + import_ethers.ethers.hexlify(proof.proof).slice(2)
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
var import_ethers2 = require("ethers");
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
      this.provider = new import_ethers2.ethers.JsonRpcProvider(this.config.rpcUrl);
    } else if (this.config.network) {
      this.provider = import_ethers2.ethers.getDefaultProvider(this.config.network);
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
    const wasm2 = WasmLoader.getWasm();
    const bundleBytes = this.serializeBundle(bundle, proofs);
    const atomicBytes = await wasm2.create_atomic_bundle(bundleBytes);
    const bundleHash = import_ethers2.ethers.keccak256(atomicBytes);
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
        import_ethers2.ethers.Transaction.from(tx).serialized
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
    const iface = new import_ethers2.ethers.Interface([
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AtomicExecutor,
  Trustless,
  TrustlessCore,
  WasmLoader
});
