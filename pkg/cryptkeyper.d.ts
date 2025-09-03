/* tslint:disable */
/* eslint-disable */
/**
 * Initialize the WASM module (call this first)
 */
export function main(): void;
/**
 * Module initialization and feature detection
 */
export function init_cryptkeyper(): string;
/**
 * Check if the environment supports the required WebCrypto features
 */
export function check_webcrypto_support(): boolean;
/**
 * Minimal test struct for isolating WASM issues
 */
export class DebugTester {
  private constructor();
  free(): void;
  /**
   * Test basic XMSS instance creation without any operations
   */
  static test_basic_creation(): string;
  /**
   * Test hash function operations in isolation
   */
  static test_hash_functions(): string;
  /**
   * Test WOTS+ parameter calculations
   */
  static test_wots_params(): string;
  /**
   * Test base-w conversion without crypto operations
   */
  static test_base_w_conversion(message: Uint8Array): string;
  /**
   * Test individual WOTS+ chain generation (the likely failure point)
   */
  static test_single_chain(): string;
  /**
   * Test WOTS+ signing in isolation 
   */
  static test_signing_pipeline(): string;
  /**
   * Test memory access patterns that might cause unreachable
   */
  static test_memory_access(): string;
}
/**
 * Utility functions for WebAssembly environment
 */
export class WasmUtils {
  private constructor();
  free(): void;
  /**
   * Generate cryptographically secure random bytes using WebCrypto
   */
  static generate_random_seed(): Promise<any>;
  /**
   * Get available parameter sets with their properties
   */
  static get_parameter_sets(): any;
  /**
   * Get library version and build information
   */
  static version_info(): string;
  /**
   * Performance benchmark for parameter selection
   */
  static benchmark_parameter_set(_parameter_set: number): Promise<any>;
}
/**
 * WebAssembly wrapper for XMSS key pair
 */
export class WasmXmssKeyPair {
  free(): void;
  /**
   * Generate a new XMSS key pair
   * 
   * # Parameters
   * - `parameter_set`: Parameter set identifier (0-8 for different configurations)
   * - `seed`: 32-byte seed for key generation (optional, will use WebCrypto if not provided)
   */
  constructor(parameter_set: number, seed?: Uint8Array | null);
  /**
   * Sign a message (TEMPORARY SIMPLIFIED VERSION FOR DEBUGGING)
   * 
   * # Parameters  
   * - `message`: The message to sign as Uint8Array
   * 
   * # Returns
   * A signature that can be verified with the public key
   */
  sign(message: Uint8Array): WasmXmssSignature;
  /**
   * Export the private key (be very careful with this!)
   */
  export_private_key(): Uint8Array;
  /**
   * Get the public key
   */
  readonly public_key: WasmXmssPublicKey;
  /**
   * Get the number of remaining signatures
   */
  readonly remaining_signatures: bigint;
  /**
   * Get the maximum number of signatures for this parameter set
   */
  readonly max_signatures: bigint;
  /**
   * Get parameter set information
   */
  readonly parameter_info: string;
}
/**
 * WebAssembly wrapper for XMSS public key
 */
export class WasmXmssPublicKey {
  free(): void;
  /**
   * Create public key from bytes
   */
  constructor(bytes: Uint8Array);
  /**
   * Verify a signature
   * 
   * # Parameters
   * - `message`: The original message as Uint8Array
   * - `signature`: The signature to verify
   * 
   * # Returns
   * True if the signature is valid, false otherwise
   */
  verify(message: Uint8Array, signature: WasmXmssSignature): boolean;
  /**
   * Get public key as Uint8Array
   */
  readonly bytes: Uint8Array;
  /**
   * Get public key size in bytes
   */
  readonly size: number;
}
/**
 * WebAssembly wrapper for XMSS signature
 */
export class WasmXmssSignature {
  free(): void;
  /**
   * Create signature from bytes
   */
  constructor(bytes: Uint8Array);
  /**
   * Get signature as Uint8Array
   */
  readonly bytes: Uint8Array;
  /**
   * Get signature size in bytes
   */
  readonly size: number;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_debugtester_free: (a: number, b: number) => void;
  readonly debugtester_test_basic_creation: () => [number, number, number, number];
  readonly debugtester_test_hash_functions: () => [number, number, number, number];
  readonly debugtester_test_wots_params: () => [number, number, number, number];
  readonly debugtester_test_base_w_conversion: (a: any) => [number, number, number, number];
  readonly debugtester_test_single_chain: () => [number, number, number, number];
  readonly debugtester_test_signing_pipeline: () => [number, number, number, number];
  readonly debugtester_test_memory_access: () => [number, number, number, number];
  readonly __wbg_wasmxmsskeypair_free: (a: number, b: number) => void;
  readonly __wbg_wasmxmsssignature_free: (a: number, b: number) => void;
  readonly __wbg_wasmxmsspublickey_free: (a: number, b: number) => void;
  readonly wasmxmsskeypair_new: (a: number, b: number) => [number, number, number];
  readonly wasmxmsskeypair_public_key: (a: number) => number;
  readonly wasmxmsskeypair_sign: (a: number, b: any) => [number, number, number];
  readonly wasmxmsskeypair_remaining_signatures: (a: number) => bigint;
  readonly wasmxmsskeypair_max_signatures: (a: number) => bigint;
  readonly wasmxmsskeypair_export_private_key: (a: number) => any;
  readonly wasmxmsskeypair_parameter_info: (a: number) => [number, number];
  readonly wasmxmsssignature_bytes: (a: number) => any;
  readonly wasmxmsspublickey_bytes: (a: number) => any;
  readonly wasmxmsspublickey_size: (a: number) => number;
  readonly wasmxmsspublickey_from_bytes: (a: any) => number;
  readonly wasmxmsspublickey_verify: (a: number, b: any, c: number) => [number, number, number];
  readonly __wbg_wasmutils_free: (a: number, b: number) => void;
  readonly wasmutils_get_parameter_sets: () => any;
  readonly wasmutils_version_info: () => [number, number];
  readonly wasmutils_benchmark_parameter_set: (a: number) => any;
  readonly init_cryptkeyper: () => [number, number];
  readonly check_webcrypto_support: () => number;
  readonly wasmxmsssignature_size: (a: number) => number;
  readonly main: () => void;
  readonly wasmutils_generate_random_seed: () => any;
  readonly wasmxmsssignature_from_bytes: (a: any) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
