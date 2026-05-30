"""
nist_tests.py — Tests statistiques NIST SP 800-22.

Implémente deux tests de base pour valider la qualité du CSPRNG :
  - Test 1 : Frequency (Monobit) Test
  - Test 3 : Runs Test
"""

from __future__ import annotations
import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .csprng import AES_CTR_CSPRNG


def frequency_monobit_test(prng: AES_CTR_CSPRNG,
                            n_bits: int = 20_000) -> dict:
    """
    NIST SP 800-22 — Test 1 : Frequency (Monobit) Test.

    Vérifie que la proportion de bits à 1 est proche de 1/2,
    comme attendu pour une séquence parfaitement aléatoire.

    Méthode :
        1. Générer n_bits depuis le PRNG.
        2. Compter les 1 (s1) et les 0 (s0).
        3. S_obs = |s1 - s0| / sqrt(n_bits)
        4. p-value = erfc(S_obs / sqrt(2))
        5. Si p >= 0.01 → la séquence est acceptable au seuil 1 %.

    Args:
        prng:   Instance initialisée de AES_CTR_CSPRNG.
        n_bits: Nombre de bits à tester (NIST recommande >= 100).

    Returns:
        Dictionnaire avec les résultats détaillés du test.
    """
    raw = prng.generate_bytes((n_bits + 7) // 8)

    count_ones = sum(bin(b).count('1') for b in raw[:n_bits // 8])

    remainder = n_bits % 8
    if remainder:
        last_byte = raw[n_bits // 8]
        mask = 0xFF << (8 - remainder) & 0xFF
        count_ones += bin(last_byte & mask).count('1')

    count_zeros = n_bits - count_ones
    S_obs   = abs(count_ones - count_zeros) / math.sqrt(n_bits)
    p_value = math.erfc(S_obs / math.sqrt(2))
    passed  = p_value >= 0.01

    return {
        "test":       "NIST Frequency (Monobit)",
        "n_bits":     n_bits,
        "ones":       count_ones,
        "zeros":      count_zeros,
        "proportion": count_ones / n_bits,
        "S_obs":      S_obs,
        "p_value":    p_value,
        "passed":     passed,
        "verdict":    "PASS ✓" if passed else "FAIL ✗",
    }


def runs_test(prng: AES_CTR_CSPRNG, n_bits: int = 20_000) -> dict:
    """
    NIST SP 800-22 — Test 3 : Runs Test.

    Un "run" est une suite ininterrompue de bits identiques.
    Ce test vérifie que le nombre de runs (oscillations 0/1)
    est cohérent avec une séquence aléatoire.

    Args:
        prng:   Instance initialisée de AES_CTR_CSPRNG.
        n_bits: Nombre de bits à tester.

    Returns:
        Dictionnaire avec les résultats détaillés du test.
    """
    raw  = prng.generate_bytes((n_bits + 7) // 8)
    bits = []
    for b in raw:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)
            if len(bits) == n_bits:
                break
        if len(bits) == n_bits:
            break

    pi  = bits.count(1) / n_bits
    tau = 2 / math.sqrt(n_bits)

    if abs(pi - 0.5) >= tau:
        return {
            "test":    "NIST Runs Test",
            "verdict": "NOT APPLICABLE (pre-condition frequence non satisfaite)",
            "pi":      pi,
        }

    V        = 1 + sum(1 for i in range(n_bits - 1) if bits[i] != bits[i + 1])
    expected = 2 * n_bits * pi * (1 - pi)
    std_dev  = math.sqrt(2 * n_bits) * pi * (1 - pi)
    p_value  = math.erfc(abs(V - expected) / (math.sqrt(2) * std_dev))
    passed   = p_value >= 0.01

    return {
        "test":     "NIST Runs Test",
        "n_bits":   n_bits,
        "pi":       pi,
        "V":        V,
        "expected": expected,
        "p_value":  p_value,
        "passed":   passed,
        "verdict":  "PASS ✓" if passed else "FAIL ✗",
    }