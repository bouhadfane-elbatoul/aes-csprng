"""
Tests unitaires pour l'implémentation AES-128 (src/aes_core.py).

Vecteurs de test officiels extraits de :
  - NIST FIPS 197, Appendix B et C
  - NIST AES Known Answer Tests (KAT)

Lancer avec : pytest tests/test_aes.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.aes_core import (
    aes_key_expansion,
    aes_encrypt_block,
    _sub_bytes,
    _shift_rows,
    _mix_columns,
    _add_round_key,
    _gf_mul,
    AES_SBOX,
)


# =============================================================================
# 1. Tests GF(2^8) — arithmétique de Galois
# =============================================================================

class TestGaloisField:
    def test_mul_by_one_is_identity(self):
        """Multiplier par 1 dans GF(2^8) doit retourner l'élément lui-même."""
        for x in [0x00, 0x01, 0x53, 0xAB, 0xFF]:
            assert _gf_mul(x, 1) == x

    def test_mul_by_zero(self):
        """Multiplier par 0 doit toujours donner 0."""
        for x in [0x01, 0x53, 0xFF]:
            assert _gf_mul(x, 0) == 0

    def test_known_values(self):
        """Valeurs de référence extraites de FIPS 197 Section 4.2."""
        assert _gf_mul(0x57, 0x02) == 0xAE
        assert _gf_mul(0x57, 0x04) == 0x47   # 0xAE xor 0xE9 -> réduction
        assert _gf_mul(0x57, 0x08) == 0x8E
        assert _gf_mul(0x57, 0x10) == 0x07

    def test_commutativity(self):
        """La multiplication GF(2^8) est commutative."""
        assert _gf_mul(0x53, 0xCA) == _gf_mul(0xCA, 0x53)

    def test_mul2_range(self):
        """xtime (mul par 2) doit rester dans [0, 255]."""
        for x in range(256):
            result = _gf_mul(x, 2)
            assert 0 <= result <= 255


# =============================================================================
# 2. Tests S-Box
# =============================================================================

class TestSBox:
    def test_sbox_size(self):
        assert len(AES_SBOX) == 256

    def test_known_sbox_values(self):
        """Valeurs S-Box connues de FIPS 197."""
        assert AES_SBOX[0x00] == 0x63
        assert AES_SBOX[0x01] == 0x7C
        assert AES_SBOX[0x53] == 0xED
        assert AES_SBOX[0xFF] == 0x16
        assert AES_SBOX[0xF0] == 0x8C

    def test_sbox_is_bijection(self):
        """La S-Box doit être une bijection (pas de doublons)."""
        assert len(set(AES_SBOX)) == 256


# =============================================================================
# 3. Tests transformations AES
# =============================================================================

class TestSubBytes:
    def test_all_zeros(self):
        state = bytearray(16)
        result = _sub_bytes(state)
        assert all(b == 0x63 for b in result)

    def test_identity_state(self):
        """Chaque octet 0x00..0x0F doit être substitué par la S-Box."""
        state = bytearray(range(16))
        result = _sub_bytes(state)
        for i in range(16):
            assert result[i] == AES_SBOX[i]


class TestShiftRows:
    def test_row0_unchanged(self):
        """La ligne 0 (octets 0,4,8,12 en colonne-major) ne doit pas bouger."""
        state = bytearray(range(16))
        result = _shift_rows(state)
        assert result[0] == state[0]

    def test_known_vector(self):
        """
        Vecteur de FIPS 197 Appendix B après SubBytes avant MixColumns
        à la fin du round 1.
        """
        after_sub = bytearray([
            0xD4, 0xBF, 0x5D, 0x30,
            0xE0, 0xB4, 0x52, 0xAE,
            0xB8, 0x41, 0x11, 0xF1,
            0x1E, 0x27, 0x98, 0xE5,
        ])
        expected = bytearray([
            0xD4, 0xE0, 0xB8, 0x1E,
            0xBF, 0xB4, 0x41, 0x27,
            0x5D, 0x52, 0x11, 0x98,
            0x30, 0xAE, 0xF1, 0xE5,
        ])
        assert _shift_rows(after_sub) == expected


class TestMixColumns:
    def test_known_vector(self):
        """
        Vecteur de FIPS 197 Appendix B après ShiftRows, avant AddRoundKey
        à la fin du round 1.
        """
        after_shift = bytearray([
            0xD4, 0xE0, 0xB8, 0x1E,
            0xBF, 0xB4, 0x41, 0x27,
            0x5D, 0x52, 0x11, 0x98,
            0x30, 0xAE, 0xF1, 0xE5,
        ])
        expected = bytearray([
            0x04, 0xE0, 0x48, 0x28,
            0x66, 0xCB, 0xF8, 0x06,
            0x81, 0x19, 0xD3, 0x26,
            0xE5, 0x9A, 0x7A, 0x4C,
        ])
        assert _mix_columns(after_shift) == expected


# =============================================================================
# 4. Tests Key Expansion
# =============================================================================

class TestKeyExpansion:
    def test_produces_11_round_keys(self):
        key = bytes(range(16))
        rks = aes_key_expansion(key)
        assert len(rks) == 11

    def test_each_round_key_is_16_bytes(self):
        key = bytes(range(16))
        rks = aes_key_expansion(key)
        for rk in rks:
            assert len(rk) == 16

    def test_first_round_key_equals_key(self):
        """Le premier round key doit être identique à la clé originale."""
        key = bytes(range(16))
        rks = aes_key_expansion(key)
        assert bytes(rks[0]) == key

    def test_fips197_key_schedule(self):
        """
        Vecteur officiel FIPS 197 Appendix A.1
        Clé : 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
        """
        key = bytes([
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C,
        ])
        rks = aes_key_expansion(key)

        # Round key 1 : a0 fa fe 17 88 54 2c b1 23 a3 39 39 2a 6c 76 05
        expected_rk1 = bytes([
            0xA0, 0xFA, 0xFE, 0x17,
            0x88, 0x54, 0x2C, 0xB1,
            0x23, 0xA3, 0x39, 0x39,
            0x2A, 0x6C, 0x76, 0x05,
        ])
        assert bytes(rks[1]) == expected_rk1

    def test_wrong_key_length_raises(self):
        import pytest
        with pytest.raises(ValueError):
            aes_key_expansion(b"short")


# =============================================================================
# 5. Tests AES-128 chiffrement complet (NIST KAT)
# =============================================================================

class TestAESEncrypt:
    def test_fips197_appendix_b(self):
        """
        Vecteur complet FIPS 197 Appendix B.
        Plaintext  : 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
        Key        : 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
        Ciphertext : 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
        """
        plaintext = bytes([
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
            0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34,
        ])
        key = bytes([
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        ])
        expected = bytes([
            0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
            0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32,
        ])
        rks = aes_key_expansion(key)
        assert aes_encrypt_block(plaintext, rks) == expected

    def test_all_zeros(self):
        """
        NIST KAT : clé = 00..00, plaintext = 00..00
        Ciphertext attendu : 66 e9 4b d4 ef 8a 2c 3b 88 4c fa 59 ca 34 2b 2e
        """
        key       = bytes(16)
        plaintext = bytes(16)
        expected  = bytes([
            0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B,
            0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E,
        ])
        rks = aes_key_expansion(key)
        assert aes_encrypt_block(plaintext, rks) == expected

    def test_all_ones(self):
        """
        NIST KAT : clé = ff..ff, plaintext = ff..ff
        Ciphertext attendu : a1 f6 25 8c 87 7d 5f cd 89 64 48 45 38 bf c9 2c
        """
        key       = bytes([0xFF] * 16)
        plaintext = bytes([0xFF] * 16)
        expected  = bytes([
            0xA1, 0xF6, 0x25, 0x8C, 0x87, 0x7D, 0x5F, 0xCD,
            0x89, 0x64, 0x48, 0x45, 0x38, 0xBF, 0xC9, 0x2C,
        ])
        rks = aes_key_expansion(key)
        assert aes_encrypt_block(plaintext, rks) == expected

    def test_output_is_16_bytes(self):
        rks = aes_key_expansion(bytes(16))
        result = aes_encrypt_block(bytes(16), rks)
        assert len(result) == 16

    def test_different_keys_give_different_output(self):
        pt  = bytes(16)
        rk1 = aes_key_expansion(bytes(16))
        rk2 = aes_key_expansion(bytes([1] * 16))
        assert aes_encrypt_block(pt, rk1) != aes_encrypt_block(pt, rk2)

    def test_different_plaintexts_give_different_output(self):
        rks = aes_key_expansion(bytes(16))
        ct1 = aes_encrypt_block(bytes(16), rks)
        ct2 = aes_encrypt_block(bytes([1] * 16), rks)
        assert ct1 != ct2

    def test_wrong_block_size_raises(self):
        import pytest
        rks = aes_key_expansion(bytes(16))
        with pytest.raises(ValueError):
            aes_encrypt_block(b"too short", rks)