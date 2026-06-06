# ScopeMask (Python)

ScopeMask converts internal identifiers: database keys, emails, UUIDs, etc into short, opaque strings that are safe to expose in URLs and APIs, and decodes them back to the original value on demand. Each id is bound to a scope and a secret, with a keyed integrity check.

## Install

```bash
pip install scopemask
# or
uv add scopemask
```

## Configuration

Create a `ScopeMask` with a secret. The secret is required and is the key every id is derived from; keep it private and stable.

```python
from scopemask import ScopeMask

scope_mask = ScopeMask("parity-secret")
```

Optional keyword arguments:

- `min_length`: pad every id to at least this many characters (default 16).
- `base_alphabet`: the characters ids are built from; must be unique (default A–Z, a–z, 0–9).
- `previous_secrets`: extra secrets accepted when decoding but never used for encoding, so ids made with an old secret keep working after you rotate.

```python
scope_mask = ScopeMask(
    "parity-secret",
    min_length=24,
    base_alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
    previous_secrets=("old-secret",),
)
```

## Encode and decode

```python
scope_mask.encode("user", 42)                    # "xgFeePgoWUZHCNLo"
scope_mask.decode("user", "xgFeePgoWUZHCNLo")    # 42
```

## Value types

Integers, strings, bytes, and UUIDs are supported. The original type is restored on decode.

```python
import uuid

scope_mask.encode("user", "hello")                # "yqBiRnZBIdqXslkrXM"
scope_mask.encode("user", b"\x00\x01\xff")        # "RLDIyRQmFljZ1gBD"
scope_mask.encode("user", uuid.UUID("12345678-1234-5678-1234-567812345678"))
# "miQAnixf6TYaACwhThxDJ973X5vSuKqjp2W"
```

## Scopes

The same value produces a different id in each scope.

```python
scope_mask.encode("user", 42)     # "xgFeePgoWUZHCNLo"
scope_mask.encode("order", 42)    # "8DGttE8msCZHsJVG"
```

## Prefixes

Add a prefix for readable ids. Pass the same prefix when decoding.

```python
scope_mask.encode("user", 42, prefix="id_")        # "id_xgFeePgoWUZHCNLo"
scope_mask.encode("webhook", 42, prefix="whs_")    # "whs_jU5IIH0OxGnQg5u1"
scope_mask.decode("user", "id_xgFeePgoWUZHCNLo", prefix="id_")   # 42
```

## Bound scope

Bind a scope and prefix once, then call the same methods without repeating them.

```python
users = scope_mask.scope("user", prefix="id_")

users.encode(42)                     # "id_xgFeePgoWUZHCNLo"
users.decode("id_xgFeePgoWUZHCNLo")  # 42
users.try_decode("not-a-real-id")    # None

ids = users.encode_many([1, 2, 3])
users.decode_many(ids)               # [1, 2, 3]
users.try_decode_many(ids)           # [1, 2, 3]
```

## Batch operations

```python
ids = scope_mask.encode_many("user", [1, 2, 3])
scope_mask.decode_many("user", ids)   # [1, 2, 3]
```

## Safe decoding

`decode` raises `InvalidId` on an invalid id. Use `try_decode` to get `None` instead.

```python
scope_mask.try_decode("user", "not-a-real-id")         # None
scope_mask.try_decode_many("user", ["not-a-real-id"])  # [None]
scope_mask.encode("user", None)                        # None
```
