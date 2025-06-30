/**
 * TypeScript definitions for CryptKeyPer WASM bindings
 * 
 * RFC 8391 compliant XMSS (eXtended Merkle Signature Scheme) 
 * post-quantum cryptography implementation for WebAssembly
 */

declare module "cryptkeyper-wasm" {
  /**
   * XMSS Key Pair for post-quantum digital signatures
   */
  export class WasmXmssKeyPair {
    /**
     * Generate a new XMSS key pair
     * @param parameter_set Parameter set ID (0-8)
     *   0: XMSS-SHA256-W16-H10 (1024 signatures)
     *   1: XMSS-SHA256-W16-H16 (65K signatures)  
     *   2: XMSS-SHA256-W16-H20 (1M signatures)
     *   3-5: SHA512 variants
     *   6-8: SHAKE128 variants
     * @param seed 32-byte cryptographic seed (required)
     */
    constructor(parameter_set: number, seed: Uint8Array);

    /** Get the public key */
    readonly public_key: WasmXmssPublicKey;

    /** Number of signatures remaining */
    readonly remaining_signatures: number;

    /** Maximum signatures for this parameter set */
    readonly max_signatures: number;

    /** Parameter set information string */
    readonly parameter_info: string;

    /**
     * Sign a message with post-quantum security
     * @param message Message to sign
     * @returns XMSS signature
     */
    sign(message: Uint8Array): WasmXmssSignature;

    /**
     * Export private key (WARNING: Handle with extreme care!)
     * @returns 32-byte private seed
     */
    export_private_key(): Uint8Array;
  }

  /**
   * XMSS Digital Signature
   */
  export class WasmXmssSignature {
    /**
     * Create signature from bytes
     * @param bytes Signature bytes
     */
    constructor(bytes: Uint8Array);

    /** Signature as byte array */
    readonly bytes: Uint8Array;

    /** Signature size in bytes */
    readonly size: number;
  }

  /**
   * XMSS Public Key
   */
  export class WasmXmssPublicKey {
    /**
     * Create public key from bytes
     * @param bytes Public key bytes
     */
    constructor(bytes: Uint8Array);

    /** Public key as byte array */
    readonly bytes: Uint8Array;

    /** Public key size in bytes */
    readonly size: number;

    /**
     * Verify an XMSS signature
     * @param message Original message
     * @param signature Signature to verify
     * @returns True if signature is valid
     */
    verify(message: Uint8Array, signature: WasmXmssSignature): boolean;
  }

  /**
   * Utility functions for WASM environment
   */
  export class WasmUtils {
    /**
     * Generate cryptographically secure random seed
     * @returns Promise resolving to 32 random bytes
     */
    static generate_random_seed(): Promise<Uint8Array>;

    /**
     * Get information about all available parameter sets
     * @returns Array of parameter set descriptions
     */
    static get_parameter_sets(): Array<{
      id: string;
      name: string;
      signatures: string;
      description: string;
    }>;

    /**
     * Get library version and build information
     * @returns Version string
     */
    static version_info(): string;

    /**
     * Benchmark a parameter set for performance estimation
     * @param parameter_set Parameter set ID
     * @returns Promise with benchmark results
     */
    static benchmark_parameter_set(parameter_set: number): Promise<{
      keygen_time_ms: number;
      sign_time_ms: number;
      verify_time_ms: number;
      signature_size_bytes: number;
      public_key_size_bytes: number;
    }>;
  }

  /**
   * Initialize the CryptKeyPer WASM module
   * Call this before using other functions
   * @returns Success message
   */
  export function init_cryptkeyper(): string;

  /**
   * Check if WebCrypto API is supported
   * @returns True if crypto.getRandomValues is available
   */
  export function check_webcrypto_support(): boolean;

  /**
   * Parameter Set Configuration
   */
  export interface ParameterSetConfig {
    /** Parameter set ID (0-8) */
    id: number;
    /** Human-readable name */
    name: string;
    /** Hash function (SHA256, SHA512, SHAKE128) */
    hash: "SHA256" | "SHA512" | "SHAKE128";
    /** Winternitz parameter */
    winternitz: number;
    /** Tree height */
    height: number;
    /** Maximum signatures */
    max_signatures: number;
    /** Estimated security level in bits */
    security_level: number;
    /** Recommended use case */
    use_case: "IoT" | "General" | "Long-term";
  }

  /**
   * Predefined parameter set configurations
   */
  export const PARAMETER_SETS: readonly ParameterSetConfig[];

  /**
   * Error types that can be thrown by CryptKeyPer
   */
  export class CryptKeyperError extends Error {
    constructor(message: string);
  }
}

/**
 * Usage Examples:
 * 
 * ```typescript
 * import { 
 *   WasmXmssKeyPair, 
 *   WasmUtils, 
 *   init_cryptkeyper 
 * } from 'cryptkeyper-wasm';
 * 
 * // Initialize the module
 * init_cryptkeyper();
 * 
 * // Generate a random seed
 * const seed = crypto.getRandomValues(new Uint8Array(32));
 * 
 * // Create key pair (medium security, SHA256)
 * const keyPair = new WasmXmssKeyPair(1, seed);
 * 
 * // Sign a message
 * const message = new TextEncoder().encode("Hello, post-quantum world!");
 * const signature = keyPair.sign(message);
 * 
 * // Verify signature
 * const isValid = keyPair.public_key.verify(message, signature);
 * console.log("Signature valid:", isValid);
 * 
 * // Check remaining signatures
 * console.log("Remaining signatures:", keyPair.remaining_signatures);
 * ```
 */