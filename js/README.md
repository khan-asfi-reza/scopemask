# ScopeMask (JS/TS)

ScopeMask converts internal identifiers: database keys, emails, UUIDs, etc into short, opaque strings that are safe to expose in URLs and APIs, and decodes them back to the original value on demand. Each id is bound to a scope and a secret, with a keyed integrity check.

Runs in Node, Deno, Bun, and edge runtimes such as Cloudflare Workers and Vercel Edge.

## Install

```bash
npm install scopemask
yarn add scopemask
pnpm add scopemask
```

## Configuration

Create a `ScopeMask` with a secret. The secret is required and is the key every id is derived from; keep it private and stable.

```ts
import { ScopeMask } from "scopemask";

const scopeMask = new ScopeMask("parity-secret");
```

Optional settings:

- `minLength`: pad every id to at least this many characters (default 16).
- `baseAlphabet`: the characters ids are built from; must be unique (default A–Z, a–z, 0–9).
- `previousSecrets`: extra secrets accepted when decoding but never used for encoding, so ids made with an old secret keep working after you rotate.

```ts
new ScopeMask("parity-secret", {
  minLength: 24,
  baseAlphabet: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
  previousSecrets: ["old-secret"],
});
```

## Encode and decode

```ts
scopeMask.encode("user", 42);                    // "xgFeePgoWUZHCNLo"
scopeMask.decode("user", "xgFeePgoWUZHCNLo");    // 42
```

## Value types

Numbers, bigints, strings, byte arrays, and UUIDs are supported. The original type is restored on decode.

```ts
import { UUID } from "scopemask";

scopeMask.encode("user", "hello");                  // "yqBiRnZBIdqXslkrXM"
scopeMask.encode("user", Uint8Array.of(0, 1, 255)); // "RLDIyRQmFljZ1gBD"
scopeMask.encode("user", UUID.parse("12345678-1234-5678-1234-567812345678"));
// "miQAnixf6TYaACwhThxDJ973X5vSuKqjp2W"
```

## Scopes

The same value produces a different id in each scope.

```ts
scopeMask.encode("user", 42);     // "xgFeePgoWUZHCNLo"
scopeMask.encode("order", 42);    // "8DGttE8msCZHsJVG"
```

## Prefixes

Add a prefix for readable ids. Pass the same prefix when decoding.

```ts
scopeMask.encode("user", 42, "id_");       // "id_xgFeePgoWUZHCNLo"
scopeMask.encode("webhook", 42, "whs_");   // "whs_jU5IIH0OxGnQg5u1"
scopeMask.decode("user", "id_xgFeePgoWUZHCNLo", "id_");   // 42
```

## Bound scope

Bind a scope and prefix once, then call the same methods without repeating them.

```ts
const users = scopeMask.scope("user", "id_");

users.encode(42);                     // "id_xgFeePgoWUZHCNLo"
users.decode("id_xgFeePgoWUZHCNLo");  // 42
users.tryDecode("not-a-real-id");     // null

const ids = users.encodeMany([1, 2, 3]) as string[];
users.decodeMany(ids);                // [1, 2, 3]
users.tryDecodeMany(ids);             // [1, 2, 3]
```

## Batch operations

```ts
const ids = scopeMask.encodeMany("user", [1, 2, 3]) as string[];
scopeMask.decodeMany("user", ids);   // [1, 2, 3]
```

## Safe decoding

`decode` throws `InvalidId` on an invalid id. Use `tryDecode` to get `null` instead.

```ts
scopeMask.tryDecode("user", "not-a-real-id");          // null
scopeMask.tryDecodeMany("user", ["not-a-real-id"]);    // [null]
scopeMask.encode("user", null);                        // null
```
