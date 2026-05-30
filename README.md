# AES-128 CSPRNG

Générateur de nombres pseudo-aléatoires cryptographiquement sûr (CSPRNG) basé sur AES-128 en mode CTR, implémenté from scratch en Python.

> Projet universitaire — École supérieure en Sciences et Technologies de l'Informatique et du Numérique  
> Encadré par : Dr Bouchoucha Lydia

---

## Architecture

```
seed (256 bits)  →  key (128 bits) + counter (128 bits)
                          ↓
          block = AES_encrypt(key, counter)
                    counter += 1
```

**Composants :**
- `aes_core.py` — AES-128 from scratch (SubBytes, ShiftRows, MixColumns, AddRoundKey, Key Expansion)
- `entropy.py` — Pool d'entropie multi-sources (temps, OS, CPU jitter, souris, réseau, plateforme) → SHA-256
- `csprng.py` — Générateur AES-CTR avec reseeding automatique
- `nist_tests.py` — Tests statistiques NIST SP 800-22 (Frequency Monobit + Runs Test)

---

## Lancer la démo

```bash
python src/demo.py
```

Exemple de sortie :

```
════════════════════════════════════════════════════════════════════
  AES-128 CSPRNG – Demonstration
════════════════════════════════════════════════════════════════════

[1] Collecting entropy from multiple sources …
    Entropy gathered in 12.4 ms
    SHA-256 seed : a3f1c8...

[2] Initialising AES-128 CTR-PRNG …
[3] First 10 generated 128-bit pseudo-random values:
...
[4] Randomness tests (NIST SP 800-22):
    Result : PASS ✓
```

---

## Lancer les tests

```bash
pip install pytest
pytest tests/
```

---

## Démo visuelle (web)

Ouvrir `demo/demo-full.html` dans un navigateur — aucune installation requise.

---

## Tests statistiques (NIST SP 800-22)

| Test | Bits testés | Résultat |
|------|------------|---------|
| Frequency Monobit | 20 000 | PASS ✓ |
| Runs Test | 20 000 | PASS ✓ |

---

## Sécurité

- Clé AES 128 bits — résistante à la force brute
- Compteur 128 bits — période maximale de 2¹²⁸ blocs
- Reseeding automatique après 2⁴⁸ blocs
- Seed dérivé de sources d'entropie multiples via SHA-256

---

## Références

- NIST FIPS 197 — Advanced Encryption Standard (AES)
- NIST SP 800-90A Rev.1 — Deterministic Random Bit Generators
- NIST SP 800-22 — Statistical Tests for Random Number Generators
- Daemen & Rijmen — *The Design of Rijndael*, Springer 2002

---

## Auteurs

Bouhadfane Elbatoul

## Licence

MIT