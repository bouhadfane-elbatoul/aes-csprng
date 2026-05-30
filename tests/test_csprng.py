"""
Tests unitaires pour le générateur AES-CTR CSPRNG (src/csprng.py).

Lancer avec : pytest tests/test_csprng.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.csprng import AES_CTR_CSPRNG
from src.entropy import EntropyPool
from src.nist_tests import frequency_monobit_test, runs_test


# Seed fixe pour les tests déterministes
FIXED_SEED = bytes(range(32))   # 00 01 02 ... 1F


# =============================================================================
# 1. Tests d'initialisation
# =============================================================================

class TestInit:
    def test_init_with_fixed_seed(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        assert prng._key == FIXED_SEED[:16]

    def test_init_without_seed_uses_entropy(self):
        """Sans seed fourni, le générateur doit s'initialiser via l'entropie système."""
        prng = AES_CTR_CSPRNG()
        assert len(prng._key) == 16

    def test_seed_too_short_raises(self):
        import pytest
        with pytest.raises(ValueError):
            AES_CTR_CSPRNG(seed=b"too_short")

    def test_two_auto_seeds_differ(self):
        """Deux instances sans seed doivent produire des clés différentes."""
        p1 = AES_CTR_CSPRNG()
        p2 = AES_CTR_CSPRNG()
        assert p1._key != p2._key


# =============================================================================
# 2. Tests generate_block
# =============================================================================

class TestGenerateBlock:
    def test_block_is_16_bytes(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        block = prng.generate_block()
        assert len(block) == 16

    def test_consecutive_blocks_differ(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        b1 = prng.generate_block()
        b2 = prng.generate_block()
        assert b1 != b2

    def test_counter_increments(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        ctr_before = prng._counter
        prng.generate_block()
        assert prng._counter == ctr_before + 1

    def test_deterministic_with_fixed_seed(self):
        """Même seed → même séquence."""
        p1 = AES_CTR_CSPRNG(seed=FIXED_SEED)
        p2 = AES_CTR_CSPRNG(seed=FIXED_SEED)
        assert p1.generate_block() == p2.generate_block()
        assert p1.generate_block() == p2.generate_block()


# =============================================================================
# 3. Tests generate_bytes
# =============================================================================

class TestGenerateBytes:
    def test_exact_length(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        for n in [1, 15, 16, 17, 31, 32, 100, 256]:
            result = prng.generate_bytes(n)
            assert len(result) == n, f"Attendu {n} octets, obtenu {len(result)}"

    def test_zero_bytes(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        assert prng.generate_bytes(0) == b""

    def test_negative_raises(self):
        import pytest
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        with pytest.raises(ValueError):
            prng.generate_bytes(-1)

    def test_two_calls_differ(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        r1 = prng.generate_bytes(32)
        r2 = prng.generate_bytes(32)
        assert r1 != r2

    def test_different_seeds_differ(self):
        p1 = AES_CTR_CSPRNG(seed=FIXED_SEED)
        p2 = AES_CTR_CSPRNG(seed=bytes(reversed(range(32))))
        assert p1.generate_bytes(32) != p2.generate_bytes(32)


# =============================================================================
# 4. Tests generate_int
# =============================================================================

class TestGenerateInt:
    def test_default_128_bits(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        val = prng.generate_int(128)
        assert 0 <= val < 2**128

    def test_custom_bit_widths(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        for bits in [8, 16, 32, 64, 128, 256]:
            val = prng.generate_int(bits)
            assert 0 <= val < 2**bits

    def test_consecutive_ints_differ(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        assert prng.generate_int() != prng.generate_int()


# =============================================================================
# 5. Tests generate_stream
# =============================================================================

class TestGenerateStream:
    def test_stream_produces_values(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        gen = prng.generate_stream()
        values = [next(gen) for _ in range(10)]
        assert len(values) == 10

    def test_stream_values_are_128_bit(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        gen = prng.generate_stream()
        for _ in range(5):
            val = next(gen)
            assert 0 <= val < 2**128

    def test_stream_values_differ(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        gen = prng.generate_stream()
        values = [next(gen) for _ in range(20)]
        assert len(set(values)) == 20, "Des valeurs identiques dans le stream !"


# =============================================================================
# 6. Tests reseed
# =============================================================================

class TestReseed:
    def test_reseed_changes_key(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        key_before = prng._key
        prng.reseed()
        assert prng._key != key_before

    def test_reseed_resets_block_count(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        for _ in range(10):
            prng.generate_block()
        assert prng._block_count == 10
        prng.reseed()
        assert prng._block_count == 0

    def test_reseed_with_additional_entropy(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        extra = b"supplemental_entropy_bytes_32xxx"
        prng.reseed(additional_entropy=extra)
        assert prng._block_count == 0

    def test_output_after_reseed_differs(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        b1 = prng.generate_bytes(32)
        prng.reseed()
        b2 = prng.generate_bytes(32)
        assert b1 != b2


# =============================================================================
# 7. Tests statistiques NIST SP 800-22
# =============================================================================

class TestNISTStatistics:
    def test_frequency_monobit_passes(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        result = frequency_monobit_test(prng, n_bits=20_000)
        assert result["passed"], (
            f"Frequency Monobit FAIL — p-value={result['p_value']:.6f}, "
            f"proportion={result['proportion']:.4%}"
        )

    def test_frequency_monobit_proportion_near_half(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        result = frequency_monobit_test(prng, n_bits=20_000)
        # La proportion de 1 doit être proche de 50 % (±2 %)
        assert 0.48 <= result["proportion"] <= 0.52, (
            f"Proportion de 1-bits trop éloignée de 50 % : {result['proportion']:.4%}"
        )

    def test_runs_test_passes(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        result = runs_test(prng, n_bits=20_000)
        if "NOT APPLICABLE" not in result["verdict"]:
            assert result["passed"], (
                f"Runs Test FAIL — p-value={result['p_value']:.6f}"
            )

    def test_p_value_above_threshold(self):
        prng = AES_CTR_CSPRNG(seed=FIXED_SEED)
        result = frequency_monobit_test(prng, n_bits=20_000)
        assert result["p_value"] >= 0.01


# =============================================================================
# 8. Tests EntropyPool
# =============================================================================

class TestEntropyPool:
    def test_derive_seed_is_32_bytes(self):
        pool = EntropyPool()
        pool.gather()
        seed = pool.derive_seed()
        assert len(seed) == 32

    def test_two_seeds_differ(self):
        p1 = EntropyPool()
        p1.gather()
        p2 = EntropyPool()
        p2.gather()
        assert p1.derive_seed() != p2.derive_seed()

    def test_gather_without_explicit_call(self):
        """derive_seed() doit appeler gather() automatiquement si pool vide."""
        pool = EntropyPool()
        seed = pool.derive_seed()
        assert len(seed) == 32