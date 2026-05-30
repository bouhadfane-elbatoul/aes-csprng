"""
entropy.py — Pool d'entropie multi-sources.

Collecte de l'entropie depuis 6 sources indépendantes,
puis dérive un seed de 256 bits via SHA-256.

Sources :
  1. Horloge système haute résolution (nanosecondes)
  2. OS CSPRNG — os.urandom (/dev/urandom sur POSIX)
  3. Jitter CPU (variation de timing d'une boucle serrée)
  4. Simulation mouvements souris (SystemRandom)
  5. Simulation latence réseau (RTT avec bruit gaussien)
  6. Informations plateforme (machine, OS, processeur)
"""

import hashlib
import os
import time
import random
import struct
import platform


class EntropyPool:
    """
    Collecte l'entropie de multiples sources et dérive
    un seed cryptographique de 32 octets (256 bits) via SHA-256.
    """

    def __init__(self) -> None:
        self._pool: list[bytes] = []

    # -----------------------------------------------------------------------
    # Sources d'entropie individuelles
    # -----------------------------------------------------------------------

    def _collect_time(self) -> bytes:
        """Timestamp nanoseconde (précision dépend de la plateforme)."""
        ts = time.time_ns()
        return struct.pack(">Q", ts & 0xFFFF_FFFF_FFFF_FFFF)

    def _collect_os_random(self) -> bytes:
        """32 octets depuis l'OS CSPRNG (/dev/urandom ou équivalent)."""
        return os.urandom(32)

    def _collect_cpu_jitter(self) -> bytes:
        """
        Mesure la variation de temps d'une boucle de calcul serrée.
        Le jitter CPU (caches, prédicteur de branchement, pipeline)
        est difficile à prédire de l'extérieur.
        """
        samples = []
        for _ in range(8):
            t0 = time.perf_counter_ns()
            acc = 0
            for j in range(1000):
                acc ^= j * 6364136223846793005
            t1 = time.perf_counter_ns()
            samples.append((t1 - t0) ^ acc)
        return struct.pack(">8Q", *[s & 0xFFFF_FFFF_FFFF_FFFF for s in samples])

    def _collect_mouse_simulation(self) -> bytes:
        """
        Simule des déplacements souris (dx, dy).
        En production : utiliser de vrais événements curseur.
        Ici : SystemRandom (basé sur os.urandom) comme substitut.
        """
        rng = random.SystemRandom()
        coords = [(rng.randint(-500, 500), rng.randint(-500, 500))
                  for _ in range(16)]
        flat = [v for pair in coords for v in pair]
        return struct.pack(">32h", *flat)

    def _collect_network_simulation(self) -> bytes:
        """
        Simule des mesures de latence réseau (RTT en microsecondes).
        En production : mesures réelles sur plusieurs hôtes.
        """
        rng = random.SystemRandom()
        samples = []
        for _ in range(8):
            base_us = rng.randint(1_000, 200_000)
            jitter   = int(rng.gauss(0, base_us * 0.05))
            samples.append(abs(base_us + jitter))
        return struct.pack(">8I", *samples)

    def _collect_platform_info(self) -> bytes:
        """Hash des informations statiques de la plateforme."""
        info = platform.platform() + platform.processor() + platform.node()
        return info.encode()

    # -----------------------------------------------------------------------
    # Collecte et dérivation du seed
    # -----------------------------------------------------------------------

    def gather(self) -> None:
        """Collecte un échantillon de chaque source dans le pool."""
        collectors = [
            self._collect_time,
            self._collect_os_random,
            self._collect_cpu_jitter,
            self._collect_mouse_simulation,
            self._collect_network_simulation,
            self._collect_platform_info,
        ]
        for fn in collectors:
            self._pool.append(fn())

    def derive_seed(self) -> bytes:
        """
        Dérive un seed de 32 octets (256 bits) par SHA-256 de tout le pool.

            seed = SHA256(time ‖ os_random ‖ cpu_jitter ‖
                          mouse ‖ network ‖ platform_info)

        Appelle gather() automatiquement si le pool est vide.
        """
        if not self._pool:
            self.gather()

        h = hashlib.sha256()
        for chunk in self._pool:
            h.update(chunk)
        return h.digest()   # 32 octets