"""
CryptKeyPer: RFC 8391 compliant XMSS post-quantum signatures for Python

This package provides Python bindings for CryptKeyPer, a high-performance
implementation of the eXtended Merkle Signature Scheme (XMSS) for
post-quantum cryptography.

Example:
    >>> import cryptkeyper
    >>> # Create a key pair
    >>> keypair = cryptkeyper.XmssKeyPair("XMSS-SHA256-W16-H10")
    >>> # Sign a message  
    >>> signature = keypair.sign(b"Hello, post-quantum world!")
    >>> # Verify the signature
    >>> is_valid = keypair.public_key.verify(b"Hello, post-quantum world!", signature)
    >>> print(f"Signature valid: {is_valid}")
"""

from ._cryptkeyper import (
    XmssKeyPair,
    XmssSignature, 
    XmssPublicKey,
    CryptKeyperUtils,
    quick_sign,
    quick_verify,
    __version__,
)

__all__ = [
    "XmssKeyPair",
    "XmssSignature",
    "XmssPublicKey", 
    "CryptKeyperUtils",
    "quick_sign",
    "quick_verify",
    "__version__",
    # Convenience re-exports
    "generate_keypair",
    "available_parameter_sets",
    "estimate_sizes",
]

# Convenience functions
def generate_keypair(parameter_set: str = "XMSS-SHA256-W16-H16", seed: bytes = None) -> XmssKeyPair:
    """Generate a new XMSS key pair with sensible defaults.
    
    Args:
        parameter_set: XMSS parameter set name (default: medium security)
        seed: Optional 32-byte seed for deterministic generation
        
    Returns:
        XmssKeyPair: New key pair ready for signing
        
    Example:
        >>> keypair = cryptkeyper.generate_keypair()
        >>> print(f"Generated keypair with {keypair.max_signatures:,} max signatures")
    """
    if seed is None:
        seed = CryptKeyperUtils.generate_random_seed()
    return XmssKeyPair(parameter_set, seed)

def available_parameter_sets() -> dict:
    """Get information about all available XMSS parameter sets.
    
    Returns:
        dict: Parameter set names mapped to their properties
        
    Example:
        >>> params = cryptkeyper.available_parameter_sets()
        >>> for name, info in params.items():
        ...     print(f"{name}: {info['signatures']} - {info['description']}")
    """
    return CryptKeyperUtils.get_parameter_sets()

def estimate_sizes() -> dict:
    """Get estimated signature sizes for all parameter sets.
    
    Returns:
        dict: Parameter set names mapped to signature sizes in bytes
        
    Example:
        >>> sizes = cryptkeyper.estimate_sizes()
        >>> for param, size in sizes.items():
        ...     print(f"{param}: ~{size:,} byte signatures")
    """
    return CryptKeyperUtils.estimate_signature_sizes()

# Package metadata
__author__ = "Michael Luna"
__email__ = "michael.angelo.luna1@gmail.com"
__license__ = "MIT OR Apache-2.0"
__url__ = "https://github.com/mluna030/CryptKeyPer"
__description__ = "RFC 8391 compliant XMSS post-quantum signatures"