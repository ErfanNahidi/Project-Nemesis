"""Host resource gating thresholds shared across launcher and runtime.

The launcher (host process) and the runtime container both apply the same
preflight gates against host resources (free disk, free RAM, etc.). Before
this module existed, each side defined its own constant — they drifted
when one was updated and the other was not. Centralising the thresholds
here removes that class of bug: there is exactly one number to change,
and the import boundary that already exists (everything can import
``adscan_core``) lets both layers consume it without crossing the
host/container architectural line.

When adding a new threshold, prefer a clear, self-describing name and
include the unit in the constant name (``_GB``, ``_MB``, ``_SECONDS``)
so call sites do not have to guess.
"""

from __future__ import annotations


# Minimum free disk space (in GB) required on the Docker storage path
# before ``adscan install`` will proceed. Raised from 10 GB to 15 GB
# in v9.x after real installs filled ``/var/lib/docker`` mid-pull on
# hosts with only 10-12 GB free; the runtime image, layer cache, and
# initial workspace state together need ~12 GB worst case, and 15 GB
# leaves enough headroom for an in-place upgrade.
#
# The user can override with ``adscan install --allow-low-disk`` when
# they accept the risk.
MIN_DOCKER_INSTALL_FREE_GB: int = 15


__all__ = ("MIN_DOCKER_INSTALL_FREE_GB",)
