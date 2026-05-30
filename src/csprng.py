"""
csprng.py — Générateur de nombres pseudo-aléatoires cryptographiquement sûr
            basé sur AES-128 en mode CTR.

Architecture :
    seed (256 bits)
      ├── key     = seed[0:16]   (128 bits)  →  clé AES
      └── counter = seed[16:32]  (128 bits)  →  compteur initial

    Pour chaque bloc de 128 bits de sortie :
        block = AES_encrypt(key, counter)
        counter += 1  (mod 2^128)

Sécurité :
    - Seed de 256 bits → 128 bits de sécurité (limité par la taille de clé AES).
    - Chaque bloc est indépendant grâce au mode CTR.
    - Reseeding automatique toutes les 2^48 blocs (recommandation birthday-bound).
"""

from .aes_core import aes_encrypt_block, aes_key_expansion
from .entropy  import EntropyPool


class AES_CTR_CSPRNG:
    """
    CSPRNG basé sur AES-128 en mode Counter (CTR).

    Utilisation rapide :
        prng = AES_CTR_CSPRNG()
        bytes_aléatoires = prng.generate_bytes(32)
        entier_128_bits  = prng.generate_int(128)
    """

    RESEED_INTERVAL = 2 ** 48   # blocs entre deux reseedings obligatoires

    def __init__(self, seed: bytes | None = None) -> None:
        """
        Initialise le PRNG.

        Args:
            seed: Seed optionnel de 32 octets minimum.
                  Si None, l'entropie est collectée automatiquement.
        """
        if seed is None:
            pool = EntropyPool()
            pool.gather()
            seed = pool.derive_seed()

        if len(seed) < 32:
            raise ValueError("Le seed doit faire au moins 32 octets.")

        self._key:        bytes = seed[:16]
        self._counter:    int   = int.from_bytes(seed[16:32], "big")
        self._round_keys        = aes_key_expansion(self._key)
        self._block_count: int  = 0

    # -----------------------------------------------------------------------
    # Helpers internes
    # -----------------------------------------------------------------------

    def _counter_bytes(self) -> bytes:
        """Retourne le compteur courant encodé en big-endian sur 16 octets."""
        return self._counter.to_bytes(16, "big")

    def _increment_counter(self) -> None:
        """Incrémente le compteur modulo 2^128."""
        self._counter = (self._counter + 1) % (2 ** 128)

    # -----------------------------------------------------------------------
    # API publique
    # -----------------------------------------------------------------------

    def reseed(self, additional_entropy: bytes | None = None) -> None:
        """
        Renouvelle la clé et le compteur depuis de l'entropie fraîche.
        Mélange optionnellement des octets supplémentaires fournis par l'appelant.
        """
        pool = EntropyPool()
        pool.gather()
        new_seed = pool.derive_seed()

        if additional_entropy:
            ae = additional_entropy[:32].ljust(32, b'\x00')
            new_seed = bytes(a ^ b for a, b in zip(new_seed, ae))

        self._key        = new_seed[:16]
        self._counter    = int.from_bytes(new_seed[16:32], "big")
        self._round_keys = aes_key_expansion(self._key)
        self._block_count = 0

    def generate_block(self) -> bytes:
        """
        Génère un bloc de 128 bits (16 octets) aléatoires.

            block = AES_encrypt(key, counter) ; counter++
        """
        if self._block_count >= self.RESEED_INTERVAL:
            self.reseed()

        block = aes_encrypt_block(self._counter_bytes(), self._round_keys)
        self._increment_counter()
        self._block_count += 1
        return block

    def generate_bytes(self, n: int) -> bytes:
        """
        Génère exactement n octets pseudo-aléatoires.

        Args:
            n: Nombre d'octets souhaité (≥ 0).
        """
        if n < 0:
            raise ValueError("n doit être un entier positif ou nul.")
        result = bytearray()
        while len(result) < n:
            result.extend(self.generate_block())
        return bytes(result[:n])

    def generate_int(self, n_bits: int = 128) -> int:
        """
        Génère un entier aléatoire non signé de n_bits bits.

        Args:
            n_bits: Largeur en bits (défaut : 128).

        Returns:
            Entier dans [0, 2^n_bits).
        """
        n_bytes = (n_bits + 7) // 8
        raw     = self.generate_bytes(n_bytes)
        value   = int.from_bytes(raw, "big")
        return value & ((1 << n_bits) - 1)

    def generate_stream(self):
        """Générateur infini d'entiers pseudo-aléatoires de 128 bits."""
        while True:
            yield self.generate_int(128)