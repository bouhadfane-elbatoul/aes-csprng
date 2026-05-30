"""
demo.py — Demonstration complete du generateur AES-128 CSPRNG.

Lancer depuis la racine du projet :
    python -m src.demo
"""

from __future__ import annotations
import time
from .entropy    import EntropyPool
from .csprng     import AES_CTR_CSPRNG
from .nist_tests import frequency_monobit_test, runs_test


def _separator(char: str = "─", width: int = 68) -> str:
    return char * width


def demo() -> None:
    print(_separator("═"))
    print("  AES-128 CSPRNG — Demonstration")
    print(_separator("═"))

    # ------------------------------------------------------------------
    # Etape 1 : Collecte d'entropie
    # ------------------------------------------------------------------
    print("\n[1] Collecte d'entropie depuis les sources multiples ...")
    pool = EntropyPool()

    t0 = time.perf_counter()
    pool.gather()
    elapsed = (time.perf_counter() - t0) * 1000

    seed = pool.derive_seed()
    print(f"    Entropie collectee en {elapsed:.1f} ms")
    print(f"    Seed SHA-256 : {seed.hex()}")

    # ------------------------------------------------------------------
    # Etape 2 : Initialisation du generateur
    # ------------------------------------------------------------------
    print("\n[2] Initialisation du generateur AES-128 CTR-PRNG ...")
    prng = AES_CTR_CSPRNG(seed=seed)
    print(f"    Cle AES     : {prng._key.hex()}")
    print(f"    Compteur[0] : {prng._counter_bytes().hex()}")

    # ------------------------------------------------------------------
    # Etape 3 : 10 premiers entiers 128 bits
    # ------------------------------------------------------------------
    print("\n[3] 10 premiers entiers pseudo-aleatoires de 128 bits :")
    print(_separator())
    print(f"  {'#':>3}  {'Hex (32 caracteres)':32}  {'Decimal (debut)'}")
    print(_separator())

    for i in range(10):
        val  = prng.generate_int(128)
        hexs = f"{val:032x}"
        dec  = str(val)[:19] + "..."
        print(f"  {i+1:>3}  {hexs}  {dec}")

    print(_separator())

    # ------------------------------------------------------------------
    # Etape 4 : Tests statistiques NIST SP 800-22
    # ------------------------------------------------------------------
    print("\n[4] Tests de randomite (NIST SP 800-22) :")

    freq = frequency_monobit_test(prng, n_bits=20_000)
    print(f"\n  * {freq['test']}")
    print(f"    Bits testes  : {freq['n_bits']:,}")
    print(f"    Uns          : {freq['ones']:,}  ({freq['proportion']:.4%})")
    print(f"    Zeros        : {freq['zeros']:,}  ({1-freq['proportion']:.4%})")
    print(f"    S_obs        : {freq['S_obs']:.6f}")
    print(f"    p-value      : {freq['p_value']:.6f}")
    print(f"    Resultat     : {freq['verdict']}")

    runs = runs_test(prng, n_bits=20_000)
    print(f"\n  * {runs['test']}")
    if "NOT APPLICABLE" in runs["verdict"]:
        print(f"    Resultat : {runs['verdict']}")
    else:
        print(f"    Bits testes  : {runs['n_bits']:,}")
        print(f"    pi (uns)     : {runs['pi']:.6f}")
        print(f"    Runs (V)     : {runs['V']:,}")
        print(f"    V attendu    : {runs['expected']:.1f}")
        print(f"    p-value      : {runs['p_value']:.6f}")
        print(f"    Resultat     : {runs['verdict']}")

    # ------------------------------------------------------------------
    # Etape 5 : 64 octets bruts
    # ------------------------------------------------------------------
    print("\n[5] Generation de 64 octets aleatoires (hex) :")
    raw64 = prng.generate_bytes(64)
    for row in range(4):
        chunk = raw64[row*16:(row+1)*16]
        print("    " + " ".join(f"{b:02x}" for b in chunk))

    print(f"\n{_separator('═')}")
    print("  Termine. Le generateur est pret :")
    print("    prng.generate_block()    -> 16 octets")
    print("    prng.generate_bytes(n)   -> n octets")
    print("    prng.generate_int(bits)  -> entier de <bits> bits")
    print("    prng.generate_stream()   -> generateur infini")
    print(_separator("═"))


if __name__ == "__main__":
    demo()