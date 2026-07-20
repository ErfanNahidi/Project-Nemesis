"""Composed views — fuse data from multiple services into a single
operator-facing model.

Each module here implements one composition. Services in this package never
talk to the network themselves; they read the outputs of upstream services
(``services/enumeration/*``, ``services/collector/*``) and produce a
unified, presentation-friendly type.

The composer pattern keeps the upstream services single-purpose (one
question, one answer) while the CLI/web/report layers consume one stable
type per operation.
"""

from __future__ import annotations
