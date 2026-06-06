"""identity-mask — scope-bound opaque id masking, backed by sqids."""

from .mask import (
    BASE_ALPHABET,
    Scope,
    ScopeMask,
    InvalidId,
)

__all__ = ["ScopeMask", "Scope", "InvalidId", "BASE_ALPHABET"]
__version__ = "1.0.0"
