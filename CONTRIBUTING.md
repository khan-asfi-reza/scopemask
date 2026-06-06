# Contributing

Contributions are welcome: bug reports, fixes, docs, and new language ports. Open an issue to discuss anything substantial first, then send a pull request.

## Running the tests

Each language lives in its own directory and has its own toolchain.

### Go

```bash
cd go
go test ./...
go vet ./...
```

### Python

```bash
cd python
uv sync
uv run pytest
uv run ruff check
```

To run against every supported Python version (3.10–3.14):

```bash
uv run tox
```

### JavaScript / TypeScript

```bash
cd js
npm install
npm test
npm run typecheck
```

## Adding a new language

The three implementations are wire-compatible: the same `(secret, scope, value, prefix)` produces the same id everywhere. A new port has to reproduce that exact output, so the bar is "passes the shared parity vectors."

You will need, in the target language:

- a [sqids](https://sqids.org) port,
- HMAC-SHA256 (standard library or an audited package).

Steps:

1. **Read the wire format.** It is the contract. See the *Overview*, *Payload layout*, and *Algorithm* sections on the [documentation home page](https://khan-asfi-reza.github.io/scopemask/#overview). In short: the payload is `VERSION + TAG + body + MAC`, where `MAC` is the first 4 bytes of `HMAC-SHA256(secret, scope + 0x00 + signed)`. The payload is split into 6-byte big-endian chunks (a length number first), then encoded with sqids using a per-scope alphabet derived from the secret, with the prefix prepended.

2. **Implement the API.** Match the existing surface: `encode`, `decode`, `try_decode`, the `*_many` batch variants, and the options (`min_length`, `base_alphabet`, `previous_secrets`). Also should include the scope bound option.

3. **Verify against the parity vectors.** Load [`fixtures/parity_vectors.json`](https://github.com/khan-asfi-reza/scopemask/blob/main/fixtures/parity_vectors.json) and, for every entry, assert `encode(scope, value, prefix) == id` and that decoding `id` returns the original `value`. This is the conformance test that proves your port matches the others. Each value carries a `type` (`int`, `str`, `bytes`, `uuid`) and is stored as a string: integers as decimal, bytes as hex, UUIDs in canonical form.

4. **Wire it up.** Add a directory README, a docs page, and a CI workflow modelled on the existing ones.

If the language lacks a sqids port, that is the first thing to build (or port). Everything else depends on it producing identical output.
