# ScopeMask (Go)

ScopeMask converts internal identifiers: database keys, emails, UUIDs, etc into short, opaque strings that are safe to expose in URLs and APIs, and decodes them back to the original value on demand. Each id is bound to a scope and a secret, with a keyed integrity check.

`Encode` and `Decode` are generic over the value type, and `Decode[T]` returns that concrete type.

## Install

```bash
go get github.com/khan-asfi-reza/scopemask/go@latest
```

## Configuration

Create a `ScopeMask` with a secret. The secret is required and is the key every id is derived from; keep it private and stable.

```go
import scopemask "github.com/khan-asfi-reza/scopemask/go"

scopeMask, _ := scopemask.New("parity-secret")
```

Optional functions:

| Function | Type | Default | Description |
|----------|------|---------|-------------|
| `WithMinLength(n)` | `uint8` | `16` | Pad every id to at least `n` characters. |
| `WithBaseAlphabet(a)` | `string` | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789` | Characters ids are built from; must be unique. |
| `WithPreviousSecrets(...)` | `...string` | none | Extra secrets accepted when decoding only, so ids made with an old secret keep working after being rotated. |

## Encode and decode

```go
import scopemask "github.com/khan-asfi-reza/scopemask/go"

scopeMask, _ := scopemask.New("parity-secret")

id, _ := scopemask.Encode(scopeMask, "user", uint64(42), "")   // "xgFeePgoWUZHCNLo"
v, _ := scopemask.Decode[uint64](scopeMask, "user", id, "")     // 42
```

## Value types

Integers, strings, byte slices, and UUIDs are supported.

```go
scopemask.Encode(scopeMask, "user", "hello", "")            // "yqBiRnZBIdqXslkrXM"
scopemask.Encode(scopeMask, "user", []byte{0, 1, 255}, "")  // "RLDIyRQmFljZ1gBD"

u, _ := scopemask.ParseUUID("12345678-1234-5678-1234-567812345678")
scopemask.Encode(scopeMask, "user", u, "")                  // "miQAnixf6TYaACwhThxDJ973X5vSuKqjp2W"
```

## Scopes

The same value produces a different id in each scope.

```go
scopemask.Encode(scopeMask, "user", uint64(42), "")    // "xgFeePgoWUZHCNLo"
scopemask.Encode(scopeMask, "order", uint64(42), "")   // "8DGttE8msCZHsJVG"
```

## Prefixes

Add a prefix for readable ids. Pass the same prefix when decoding.

```go
scopemask.Encode(scopeMask, "user", uint64(42), "id_")       // "id_xgFeePgoWUZHCNLo"
scopemask.Encode(scopeMask, "webhook", uint64(42), "whs_")   // "whs_jU5IIH0OxGnQg5u1"
scopemask.Decode[uint64](scopeMask, "user", "id_xgFeePgoWUZHCNLo", "id_")   // 42
```

## Bound scope

Bind a scope and prefix once, then pass the handle to the `*In` functions.

```go
users := scopeMask.Scope("user", "id_")

id, _ := scopemask.EncodeIn(users, uint64(42))                   // "id_xgFeePgoWUZHCNLo"
v, _ := scopemask.DecodeIn[uint64](users, id)                     // 42
_, ok := scopemask.TryDecodeIn[uint64](users, "not-a-real-id")   // ok == false

ids, _ := scopemask.EncodeManyIn(users, []uint64{1, 2, 3})
vals, _ := scopemask.DecodeManyIn[uint64](users, ids)            // [1 2 3]
tried, oks := scopemask.TryDecodeManyIn[uint64](users, ids)
```

## Batch operations

```go
ids, _ := scopemask.EncodeMany(scopeMask, "user", []uint64{1, 2, 3}, "")
vals, _ := scopemask.DecodeMany[uint64](scopeMask, "user", ids, "")   // [1 2 3]
```

## Safe decoding

`TryDecode` reports validity instead of returning an error. `Decode` returns an error matching `scopemask.ErrInvalidID` on an invalid id or wrong type.

```go
v, ok := scopemask.TryDecode[uint64](scopeMask, "user", id, "")
vals, oks := scopemask.TryDecodeMany[uint64](scopeMask, "user", ids, "")
```


## Additional resources

See [Overview](https://khan-asfi-reza.github.io/scopemask/#overview) for more details.