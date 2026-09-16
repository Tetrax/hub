"""Verrou inter-processus du répertoire de certificats.

Sérialise les activations (application web, CLI d'amorçage, hook certbot) :
une seule opération d'installation à la fois.
"""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def certificate_directory_lock(
    directory: Path,
    *,
    exclusive: bool = True,
    create: bool = True,
    mode: int = 0o640,
):
    path = Path(directory) / ".certctl.lock"
    flags = os.O_RDWR | (os.O_CREAT if create else 0)
    descriptor = os.open(path, flags, mode)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
