let wasm;
export function __wbg_set_wasm(val) {
    wasm = val;
}


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

const lTextDecoder = typeof TextDecoder === 'undefined' ? (0, module.require)('util').TextDecoder : TextDecoder;

let cachedTextDecoder = new lTextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

const lTextEncoder = typeof TextEncoder === 'undefined' ? (0, module.require)('util').TextEncoder : TextEncoder;

let cachedTextEncoder = new lTextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}
/**
 * Initialize the WASM module (call this first)
 */
export function main() {
    wasm.main();
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_export_2.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}
/**
 * Module initialization and feature detection
 * @returns {string}
 */
export function init_cryptkeyper() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.init_cryptkeyper();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Check if the environment supports the required WebCrypto features
 * @returns {boolean}
 */
export function check_webcrypto_support() {
    const ret = wasm.check_webcrypto_support();
    return ret !== 0;
}

const WasmUtilsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmutils_free(ptr >>> 0, 1));
/**
 * Utility functions for WebAssembly environment
 */
export class WasmUtils {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmUtilsFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmutils_free(ptr, 0);
    }
    /**
     * Generate cryptographically secure random bytes using WebCrypto
     * @returns {Promise<any>}
     */
    static generate_random_seed() {
        const ret = wasm.wasmutils_generate_random_seed();
        return ret;
    }
    /**
     * Get available parameter sets with their properties
     * @returns {any}
     */
    static get_parameter_sets() {
        const ret = wasm.wasmutils_get_parameter_sets();
        return ret;
    }
    /**
     * Get library version and build information
     * @returns {string}
     */
    static version_info() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmutils_version_info();
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Performance benchmark for parameter selection
     * @param {number} parameter_set
     * @returns {Promise<any>}
     */
    static benchmark_parameter_set(parameter_set) {
        const ret = wasm.wasmutils_benchmark_parameter_set(parameter_set);
        return ret;
    }
}

const WasmXmssKeyPairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmxmsskeypair_free(ptr >>> 0, 1));
/**
 * WebAssembly wrapper for XMSS key pair
 */
export class WasmXmssKeyPair {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmXmssKeyPairFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmxmsskeypair_free(ptr, 0);
    }
    /**
     * Generate a new XMSS key pair
     *
     * # Parameters
     * - `parameter_set`: Parameter set identifier (0-8 for different configurations)
     * - `seed`: 32-byte seed for key generation (optional, will use WebCrypto if not provided)
     * @param {number} parameter_set
     * @param {Uint8Array | null} [seed]
     */
    constructor(parameter_set, seed) {
        const ret = wasm.wasmxmsskeypair_new(parameter_set, isLikeNone(seed) ? 0 : addToExternrefTable0(seed));
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmXmssKeyPairFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Get the public key
     * @returns {WasmXmssPublicKey}
     */
    get public_key() {
        const ret = wasm.wasmxmsskeypair_public_key(this.__wbg_ptr);
        return WasmXmssPublicKey.__wrap(ret);
    }
    /**
     * Sign a message
     *
     * # Parameters
     * - `message`: The message to sign as Uint8Array
     *
     * # Returns
     * A signature that can be verified with the public key
     * @param {Uint8Array} message
     * @returns {WasmXmssSignature}
     */
    sign(message) {
        const ret = wasm.wasmxmsskeypair_sign(this.__wbg_ptr, message);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmXmssSignature.__wrap(ret[0]);
    }
    /**
     * Get the number of remaining signatures
     * @returns {bigint}
     */
    get remaining_signatures() {
        const ret = wasm.wasmxmsskeypair_remaining_signatures(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * Get the maximum number of signatures for this parameter set
     * @returns {bigint}
     */
    get max_signatures() {
        const ret = wasm.wasmxmsskeypair_max_signatures(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * Export the private key (be very careful with this!)
     * @returns {Uint8Array}
     */
    export_private_key() {
        const ret = wasm.wasmxmsskeypair_export_private_key(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get parameter set information
     * @returns {string}
     */
    get parameter_info() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmxmsskeypair_parameter_info(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}

const WasmXmssPublicKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmxmsspublickey_free(ptr >>> 0, 1));
/**
 * WebAssembly wrapper for XMSS public key
 */
export class WasmXmssPublicKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmXmssPublicKey.prototype);
        obj.__wbg_ptr = ptr;
        WasmXmssPublicKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmXmssPublicKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmxmsspublickey_free(ptr, 0);
    }
    /**
     * Get public key as Uint8Array
     * @returns {Uint8Array}
     */
    get bytes() {
        const ret = wasm.wasmxmsspublickey_bytes(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get public key size in bytes
     * @returns {number}
     */
    get size() {
        const ret = wasm.wasmxmsspublickey_size(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Create public key from bytes
     * @param {Uint8Array} bytes
     */
    constructor(bytes) {
        const ret = wasm.wasmxmsspublickey_from_bytes(bytes);
        this.__wbg_ptr = ret >>> 0;
        WasmXmssPublicKeyFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Verify a signature
     *
     * # Parameters
     * - `message`: The original message as Uint8Array
     * - `signature`: The signature to verify
     *
     * # Returns
     * True if the signature is valid, false otherwise
     * @param {Uint8Array} message
     * @param {WasmXmssSignature} signature
     * @returns {boolean}
     */
    verify(message, signature) {
        _assertClass(signature, WasmXmssSignature);
        const ret = wasm.wasmxmsspublickey_verify(this.__wbg_ptr, message, signature.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
}

const WasmXmssSignatureFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmxmsssignature_free(ptr >>> 0, 1));
/**
 * WebAssembly wrapper for XMSS signature
 */
export class WasmXmssSignature {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmXmssSignature.prototype);
        obj.__wbg_ptr = ptr;
        WasmXmssSignatureFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmXmssSignatureFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmxmsssignature_free(ptr, 0);
    }
    /**
     * Get signature as Uint8Array
     * @returns {Uint8Array}
     */
    get bytes() {
        const ret = wasm.wasmxmsssignature_bytes(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get signature size in bytes
     * @returns {number}
     */
    get size() {
        const ret = wasm.wasmxmsspublickey_size(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Create signature from bytes
     * @param {Uint8Array} bytes
     */
    constructor(bytes) {
        const ret = wasm.wasmxmsssignature_from_bytes(bytes);
        this.__wbg_ptr = ret >>> 0;
        WasmXmssSignatureFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}

export function __wbg_buffer_609cc3eee51ed158(arg0) {
    const ret = arg0.buffer;
    return ret;
};

export function __wbg_call_672a4d21634d4a24() { return handleError(function (arg0, arg1) {
    const ret = arg0.call(arg1);
    return ret;
}, arguments) };

export function __wbg_call_7cccdd69e0791ae2() { return handleError(function (arg0, arg1, arg2) {
    const ret = arg0.call(arg1, arg2);
    return ret;
}, arguments) };

export function __wbg_crypto_ed58b8e10a292839(arg0) {
    const ret = arg0.crypto;
    return ret;
};

export function __wbg_error_7534b8e9a36f1ab4(arg0, arg1) {
    let deferred0_0;
    let deferred0_1;
    try {
        deferred0_0 = arg0;
        deferred0_1 = arg1;
        console.error(getStringFromWasm0(arg0, arg1));
    } finally {
        wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
    }
};

export function __wbg_getRandomValues_bcb4912f16000dc4() { return handleError(function (arg0, arg1) {
    arg0.getRandomValues(arg1);
}, arguments) };

export function __wbg_length_a446193dc22c12f8(arg0) {
    const ret = arg0.length;
    return ret;
};

export function __wbg_msCrypto_0a36e2ec3a343d26(arg0) {
    const ret = arg0.msCrypto;
    return ret;
};

export function __wbg_new_78feb108b6472713() {
    const ret = new Array();
    return ret;
};

export function __wbg_new_8a6f238a6ece86ea() {
    const ret = new Error();
    return ret;
};

export function __wbg_new_a12002a7f91c75be(arg0) {
    const ret = new Uint8Array(arg0);
    return ret;
};

export function __wbg_newnoargs_105ed471475aaf50(arg0, arg1) {
    const ret = new Function(getStringFromWasm0(arg0, arg1));
    return ret;
};

export function __wbg_newwithbyteoffsetandlength_d97e637ebe145a9a(arg0, arg1, arg2) {
    const ret = new Uint8Array(arg0, arg1 >>> 0, arg2 >>> 0);
    return ret;
};

export function __wbg_newwithlength_a381634e90c276d4(arg0) {
    const ret = new Uint8Array(arg0 >>> 0);
    return ret;
};

export function __wbg_node_02999533c4ea02e3(arg0) {
    const ret = arg0.node;
    return ret;
};

export function __wbg_process_5c1d670bc53614b8(arg0) {
    const ret = arg0.process;
    return ret;
};

export function __wbg_randomFillSync_ab2cfe79ebbf2740() { return handleError(function (arg0, arg1) {
    arg0.randomFillSync(arg1);
}, arguments) };

export function __wbg_require_79b1e9274cde3c87() { return handleError(function () {
    const ret = module.require;
    return ret;
}, arguments) };

export function __wbg_resolve_4851785c9c5f573d(arg0) {
    const ret = Promise.resolve(arg0);
    return ret;
};

export function __wbg_set_37837023f3d740e8(arg0, arg1, arg2) {
    arg0[arg1 >>> 0] = arg2;
};

export function __wbg_set_65595bdd868b3009(arg0, arg1, arg2) {
    arg0.set(arg1, arg2 >>> 0);
};

export function __wbg_stack_0ed75d68575b0f3c(arg0, arg1) {
    const ret = arg1.stack;
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
};

export function __wbg_static_accessor_GLOBAL_88a902d13a557d07() {
    const ret = typeof global === 'undefined' ? null : global;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

export function __wbg_static_accessor_GLOBAL_THIS_56578be7e9f832b0() {
    const ret = typeof globalThis === 'undefined' ? null : globalThis;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

export function __wbg_static_accessor_SELF_37c5d418e4bf5819() {
    const ret = typeof self === 'undefined' ? null : self;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

export function __wbg_static_accessor_WINDOW_5de37043a91a9c40() {
    const ret = typeof window === 'undefined' ? null : window;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

export function __wbg_subarray_aa9065fa9dc5df96(arg0, arg1, arg2) {
    const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
    return ret;
};

export function __wbg_versions_c71aa1626a93e0a1(arg0) {
    const ret = arg0.versions;
    return ret;
};

export function __wbindgen_init_externref_table() {
    const table = wasm.__wbindgen_export_2;
    const offset = table.grow(4);
    table.set(0, undefined);
    table.set(offset + 0, undefined);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
    ;
};

export function __wbindgen_is_function(arg0) {
    const ret = typeof(arg0) === 'function';
    return ret;
};

export function __wbindgen_is_object(arg0) {
    const val = arg0;
    const ret = typeof(val) === 'object' && val !== null;
    return ret;
};

export function __wbindgen_is_string(arg0) {
    const ret = typeof(arg0) === 'string';
    return ret;
};

export function __wbindgen_is_undefined(arg0) {
    const ret = arg0 === undefined;
    return ret;
};

export function __wbindgen_memory() {
    const ret = wasm.memory;
    return ret;
};

export function __wbindgen_string_new(arg0, arg1) {
    const ret = getStringFromWasm0(arg0, arg1);
    return ret;
};

export function __wbindgen_throw(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

