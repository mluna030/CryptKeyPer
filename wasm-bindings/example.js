/**
 * CryptKeyPer WASM Example
 * 
 * Demonstrates post-quantum digital signatures using XMSS
 * in a web browser or Node.js environment
 */

import init, { 
  WasmXmssKeyPair, 
  WasmXmssSignature,
  WasmXmssPublicKey,
  WasmUtils,
  init_cryptkeyper,
  check_webcrypto_support 
} from './pkg/cryptkeyper_wasm.js';

async function main() {
  // Initialize the WASM module
  await init();
  console.log(init_cryptkeyper());

  // Check environment support
  if (!check_webcrypto_support()) {
    console.error("WebCrypto API not supported!");
    return;
  }

  console.log("CryptKeyPer WASM Demo - Post-Quantum Signatures");
  console.log("=" .repeat(60));

  // Display available parameter sets
  console.log("\nAvailable Parameter Sets:");
  const paramSets = WasmUtils.get_parameter_sets();
  paramSets.forEach(param => {
    console.log(`  ${param.id}: ${param.name} - ${param.signatures} (${param.description})`);
  });

  console.log("\nGenerating XMSS Key Pair...");
  
  // Generate a cryptographically secure random seed
  const seed = crypto.getRandomValues(new Uint8Array(32));
  console.log(`Seed: ${Array.from(seed).map(b => b.toString(16).padStart(2, '0')).join('')}`);

  // Create key pair with medium security (65K signatures)
  const parameterSet = 1; // XMSS-SHA256-W16-H16
  let keyPair;
  
  try {
    keyPair = new WasmXmssKeyPair(parameterSet, seed);
    console.log(`Key pair generated successfully!`);
    console.log(`${keyPair.parameter_info}`);
    console.log(`Max signatures: ${keyPair.max_signatures.toLocaleString()}`);
    console.log(`Remaining: ${keyPair.remaining_signatures.toLocaleString()}`);
  } catch (error) {
    console.error(`Key generation failed: ${error}`);
    return;
  }

  // Get public key
  const publicKey = keyPair.public_key;
  console.log(`Public key size: ${publicKey.size} bytes`);
  console.log(`Public key: ${Array.from(publicKey.bytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);

  console.log("\n✍Signing Messages...");

  // Messages to sign
  const messages = [
    "Hello, post-quantum world!",
    "XMSS provides quantum-resistant signatures",
    "CryptKeyPer implements RFC 8391",
    "WebAssembly makes crypto accessible everywhere"
  ];

  const signatures = [];

  for (let i = 0; i < messages.length; i++) {
    const message = messages[i];
    const messageBytes = new TextEncoder().encode(message);
    
    console.log(`\nMessage ${i + 1}: "${message}"`);
    
    try {
      const startTime = performance.now();
      const signature = keyPair.sign(messageBytes);
      const signTime = performance.now() - startTime;
      
      signatures.push({ message: messageBytes, signature });
      
      console.log(`Signed in ${signTime.toFixed(2)}ms`);
      console.log(`Signature size: ${signature.size} bytes`);
      console.log(`Remaining signatures: ${keyPair.remaining_signatures.toLocaleString()}`);
    } catch (error) {
      console.error(`Signing failed: ${error}`);
    }
  }

  console.log("\n🔍 Verifying Signatures...");

  // Verify all signatures
  let allValid = true;
  for (let i = 0; i < signatures.length; i++) {
    const { message, signature } = signatures[i];
    const messageText = new TextDecoder().decode(message);
    
    try {
      const startTime = performance.now();
      const isValid = publicKey.verify(message, signature);
      const verifyTime = performance.now() - startTime;
      
      console.log(`"${messageText}"`);
      console.log(`${isValid ? 'Y' : 'N'} Verification: ${isValid ? 'VALID' : 'INVALID'} (${verifyTime.toFixed(2)}ms)`);
      
      if (!isValid) allValid = false;
    } catch (error) {
      console.error(`Verification failed: ${error}`);
      allValid = false;
    }
  }

  console.log(`\nOverall Result: ${allValid ? 'All signatures valid!' : 'Some signatures invalid!'}`);

  console.log("\nTesting Invalid Signature...");
  
  // Test with tampered message
  const originalMessage = new TextEncoder().encode("Original message");
  const tamperedMessage = new TextEncoder().encode("Tampered message");
  
  try {
    const originalSignature = keyPair.sign(originalMessage);
    const tamperedResult = publicKey.verify(tamperedMessage, originalSignature);
    
    console.log(`Tampered message verification: ${tamperedResult ? 'FAILED (should be false!)' : 'CORRECTLY REJECTED'}`);
  } catch (error) {
    console.error(`Tamper test failed: ${error}`);
  }

  console.log("\nPerformance Summary:");
  console.log(`Public key size: ${publicKey.size} bytes`);
  console.log(`Signature size: ${signatures.length > 0 ? signatures[0].signature.size : 'N/A'} bytes`);
  console.log(`Total signatures created: ${signatures.length}`);
  console.log(`Signatures remaining: ${keyPair.remaining_signatures.toLocaleString()}`);

  console.log("\nAdvanced Features Demo:");
  
  // Demonstrate key export/import (be careful in production!)
  console.log("Exporting private key...");
  const privateKey = keyPair.export_private_key();
  console.log(`Private key: ${Array.from(privateKey.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('')}... (32 bytes total)`);
  
  // Demonstrate public key serialization
  console.log("Serializing public key...");
  const publicKeyBytes = publicKey.bytes;
  const recreatedPublicKey = new WasmXmssPublicKey(publicKeyBytes);
  console.log(`Public key serialization: ${recreatedPublicKey.size === publicKey.size ? 'SUCCESS' : 'FAILED'}`);

  // Version information
  console.log("\nLibrary Information:");
  console.log(WasmUtils.version_info());

  console.log("\nDemo completed successfully!");
  console.log("Your messages are now quantum-safe! 🔮");
}

// Error handling wrapper
async function runDemo() {
  try {
    await main();
  } catch (error) {
    console.error("Demo failed:", error);
    console.error("Stack trace:", error.stack);
  }
}

// Run the demo
if (typeof window !== 'undefined') {
  // Browser environment
  document.addEventListener('DOMContentLoaded', runDemo);
} else {
  // Node.js environment
  runDemo();
}

/**
 * Additional utility functions for integration
 */

export class CryptKeyperIntegration {
  /**
   * Create a key pair from a password (uses PBKDF2 to derive seed)
   */
  static async createKeyPairFromPassword(password, parameterSet = 1, salt = null) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    
    // Generate salt if not provided
    if (!salt) {
      salt = crypto.getRandomValues(new Uint8Array(16));
    }
    
    // Derive key using PBKDF2
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBytes,
      'PBKDF2',
      false,
      ['deriveBits']
    );
    
    const seed = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256 // 32 bytes
    );
    
    return {
      keyPair: new WasmXmssKeyPair(parameterSet, new Uint8Array(seed)),
      salt: salt
    };
  }

  /**
   * Sign a file or large data
   */
  static async signFile(keyPair, fileData) {
    // For large files, we'd typically hash first
    const hash = await crypto.subtle.digest('SHA-256', fileData);
    return keyPair.sign(new Uint8Array(hash));
  }

  /**
   * Batch verify multiple signatures
   */
  static batchVerify(publicKey, messagesAndSignatures) {
    const results = [];
    for (const { message, signature } of messagesAndSignatures) {
      try {
        const isValid = publicKey.verify(message, signature);
        results.push({ valid: isValid, error: null });
      } catch (error) {
        results.push({ valid: false, error: error.message });
      }
    }
    return results;
  }
}

export { runDemo };
