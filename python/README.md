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

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `min_length` | `int` | `16` | Pad every id to at least this many characters. |
| `base_alphabet` | `str` | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789` | Characters ids are built from; must be unique. |
| `previous_secrets` | `tuple[str \| bytes, ...]` | `()` | Extra secrets accepted when decoding only, so ids made with an old secret keep working after being rotated. |

## Encode and decode

```python
from scopemask import ScopeMask

scope_mask = ScopeMask("parity-secret")

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


## Custom configuration

```python
from scopemask import ScopeMask

scope_mask = ScopeMask(
    "parity-secret",
    min_length=24,
    base_alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
)
scope_mask.encode("user", 42)   # "527M4BZ6EU4YX3CYWDQ2GRAE"

# secret rotation: ids minted under an old secret still decode
old = ScopeMask("old-secret")
enc = old.encode("user", 99)    # "CeAUI5UM6CeUJISr"

rotated = ScopeMask("new-secret", previous_secrets=("old-secret",))
rotated.decode("user", enc)     # 99
```

## Additional resources

See [Overview](https://khan-asfi-reza.github.io/scopemask/#overview) for more details.
