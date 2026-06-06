# Changelog

All notable changes to this project are documented here. Versions follow [semantic versioning](https://semver.org); each language is versioned independently.

## 1.0.0

Initial release for Python, JavaScript/TypeScript, and Go. The three implementations are wire-compatible: an id produced in one language decodes in the others.

- Encode and decode integers, strings, bytes, and UUIDs, with the original type restored on decode.
- Scope-bound ids: the secret and scope derive a per-scope alphabet, so the same value differs across scopes.
- Keyed integrity check (truncated HMAC-SHA256) embedded in every id; a tampered id, wrong scope, or wrong secret is rejected.
- Optional prefix for readable, Stripe-style ids.
- Minimum length padding (default 16).
- Secret rotation via previous secrets, accepted on decode only.
- Batch operations, safe (non-raising) decode, and bound-scope handles.
