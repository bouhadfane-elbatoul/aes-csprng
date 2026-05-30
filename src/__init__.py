"""
AES-128 CSPRNG — Générateur de nombres pseudo-aléatoires cryptographiquement sûr.

Usage rapide :
    from src.csprng import AES_CTR_CSPRNG

    prng = AES_CTR_CSPRNG()          # seed automatique depuis l'entropie système
    random_bytes = prng.generate_bytes(32)
    random_int   = prng.generate_int(128)
"""

from .csprng  import AES_CTR_CSPRNG
from .entropy import EntropyPool
from .aes_core import aes_encrypt_block, aes_key_expansion

__all__ = ["AES_CTR_CSPRNG", "EntropyPool", "aes_encrypt_block", "aes_key_expansion"]
__version__ = "1.0.0"