import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import Sqids from "sqids";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  ScopeMask,
  InvalidId,
  UUID,
  BASE_ALPHABET,
  type Maskable,
} from "../src/index.js";

const SECRET = "test-secret";

function sqidsFor(scopeMask: ScopeMask, scope: string): Sqids {
  return new Sqids({ alphabet: scopeMask.alphabetFor(scope), minLength: 16 });
}

function encodePayload(sq: Sqids, payload: number[]): string {
  const nums = [payload.length];
  for (let i = 0; i < payload.length; i += 6) {
    let n = 0;
    for (let j = i; j < Math.min(i + 6, payload.length); j++) n = n * 256 + payload[j]!;
    nums.push(n);
  }
  return sq.encode(nums);
}

function sealedId(scopeMask: ScopeMask, scope: string, inner: number[]): string {
  const signed = [1, ...inner];
  const enc = new TextEncoder();
  const scopeBytes = enc.encode(scope);
  const message = new Uint8Array(scopeBytes.length + 1 + signed.length);
  message.set(scopeBytes, 0);
  message[scopeBytes.length] = 0;
  message.set(Uint8Array.from(signed), scopeBytes.length + 1);
  const mac = [...hmac(sha256, enc.encode(SECRET), message).subarray(0, 4)];
  return encodePayload(sqidsFor(scopeMask, scope), [...signed, ...mac]);
}

interface ParityVector {
  secret: string;
  scope: string;
  prefix: string;
  type: string;
  value: string;
  id: string;
}

const PARITY_VECTORS: ParityVector[] = JSON.parse(
  readFileSync(new URL("../../fixtures/parity_vectors.json", import.meta.url), "utf8"),
);

function buildValue(type: string, value: string): Maskable {
  switch (type) {
    case "int":
      return BigInt(value);
    case "str":
      return value;
    case "bytes":
      return Uint8Array.from(value.match(/../g) ?? [], (h) => parseInt(h, 16));
    case "uuid":
      return UUID.parse(value);
    default:
      throw new Error(`unknown type ${type}`);
  }
}

function assertEncodeDecode(
  scopeMask: ScopeMask,
  scope: string,
  prefix: string,
  value: Maskable,
  minLength: number,
) {
  const encoded = scopeMask.encode(scope, value, prefix)!;
  expect(encoded.length).toBeGreaterThanOrEqual(minLength);
  expect(encoded.startsWith(prefix)).toBe(true);

  const decoded = scopeMask.decode(scope, encoded, prefix);
  if (value instanceof Uint8Array) {
    expect(decoded).toEqual(value);
  } else if (value instanceof UUID) {
    expect((decoded as UUID).toString()).toBe(value.toString());
  } else {
    expect(decoded).toBe(value);
  }
}

describe("ScopeMask", () => {
  it("encode_decode", () => {
    const values: Maskable[] = [
      1,
      2,
      0,
      42,
      2n ** 63n,
      18446744073709551615n,
      2n ** 128n + 7n,
      "user@example.com",
      "",
      "hello",
      "üñîçødé 🐍",
      Uint8Array.of(1, 2, 3, 4),
      new Uint8Array(0),
      Uint8Array.of(0, 1, 255),
      UUID.parse("12345678-1234-5678-1234-567812345678"),
    ];
    for (const minLength of [16, 24, 32, 64]) {
      for (const alphabet of [BASE_ALPHABET, "abcdefg1234#$"]) {
        for (const scope of ["", "user", "entity", "profile", "accounts", "webhook"]) {
          for (const prefix of ["", "id_", "test_", "sk"]) {
            const scopeMask = new ScopeMask(SECRET, { minLength, baseAlphabet: alphabet });
            for (const value of values) {
              assertEncodeDecode(scopeMask, scope, prefix, value, minLength);
            }
          }
        }
      }
    }
  });

  it("cross_language_parity", () => {
    for (const v of PARITY_VECTORS) {
      const scopeMask = new ScopeMask(v.secret);
      const value = buildValue(v.type, v.value);
      expect(scopeMask.encode(v.scope, value, v.prefix)).toBe(v.id);

      const decoded = scopeMask.decode(v.scope, v.id, v.prefix);
      if (v.type === "bytes") {
        expect(decoded).toEqual(value);
      } else if (v.type === "uuid") {
        expect((decoded as UUID).toString()).toBe((value as UUID).toString());
      } else if (v.type === "int") {
        expect(BigInt(decoded as number | bigint)).toBe(value as bigint);
      } else {
        expect(decoded).toBe(value);
      }
    }
  });

  it("unsupported_type_rejected", () => {
    const scopeMask = new ScopeMask(SECRET);
    expect(() => scopeMask.encode("user", 1.5)).toThrow(RangeError);
    expect(() => scopeMask.encode("user", true as unknown as Maskable)).toThrow(TypeError);
    expect(() => scopeMask.encode("user", {} as unknown as Maskable)).toThrow(TypeError);
  });

  it("scope_isolation", () => {
    const scopeMask = new ScopeMask(SECRET);
    expect(scopeMask.encode("user", 1)).not.toBe(scopeMask.encode("order", 1));
  });

  it("none_encode", () => {
    expect(new ScopeMask(SECRET).encode("user", null)).toBeNull();
  });

  it("negative_rejected", () => {
    expect(() => new ScopeMask(SECRET).encode("user", -1)).toThrow(RangeError);
  });

  it("invalid_id_rejected", () => {
    const scopeMask = new ScopeMask(SECRET);
    expect(() => scopeMask.decode("user", "")).toThrow(InvalidId);
    expect(() => scopeMask.decode("user", "whs_x", "whs_")).toThrow(InvalidId);
  });

  it("empty_secret_rejected", () => {
    expect(() => new ScopeMask("")).toThrow();
  });

  it("derive_alphabet_deterministic", () => {
    const scopeMask = new ScopeMask("s");
    const a = scopeMask.alphabetFor("user");
    const b = scopeMask.alphabetFor("user");
    const c = scopeMask.alphabetFor("order");
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect([...a].sort().join("")).toBe([...scopeMask.alphabetFor("x")].sort().join(""));
  });

  it("integrity_rejects_wrong_scope", () => {
    const scopeMask = new ScopeMask(SECRET);
    const enc = scopeMask.encode("user", 42)!;
    expect(() => scopeMask.decode("order", enc)).toThrow(InvalidId);
  });

  it("integrity_rejects_tamper", () => {
    const scopeMask = new ScopeMask(SECRET);
    const enc = scopeMask.encode("user", 42)!;
    const tampered = enc.slice(0, -1) + (enc.at(-1) === "A" ? "B" : "A");
    expect(() => scopeMask.decode("user", tampered)).toThrow(InvalidId);
  });

  it("try_decode", () => {
    const scopeMask = new ScopeMask(SECRET);
    const enc = scopeMask.encode("user", 7)!;
    expect(scopeMask.tryDecode("user", enc)).toBe(7);
    expect(scopeMask.tryDecode("user", "not-an-id")).toBeNull();
  });

  it("secret_rotation", () => {
    const old = new ScopeMask("old-secret");
    const enc = old.encode("user", 99)!;

    const rotated = new ScopeMask("new-secret", { previousSecrets: ["old-secret"] });
    expect(rotated.decode("user", enc)).toBe(99);
    expect(new ScopeMask("new-secret").tryDecode("user", enc)).toBeNull();
    expect(rotated.encode("user", 99)).not.toBe(enc);
  });

  it("batch", () => {
    const scopeMask = new ScopeMask(SECRET);
    const values = [1, 2, 3, 2 ** 40];
    const ids = scopeMask.encodeMany("user", values, "id_");
    expect(scopeMask.decodeMany("user", ids as string[], "id_")).toEqual(values);
  });

  it("try_decode_many", () => {
    const scopeMask = new ScopeMask(SECRET);
    const ids = scopeMask.encodeMany("user", [1, 2, 3], "id_") as string[];
    const got = scopeMask.tryDecodeMany("user", [ids[0]!, "not-an-id", ids[2]!], "id_");
    expect(got).toEqual([1, null, 3]);
  });

  it("decode_rejects_short_payload", () => {
    const scopeMask = new ScopeMask(SECRET);
    const id = encodePayload(sqidsFor(scopeMask, "user"), [1, 0]);
    expect(() => scopeMask.decode("user", id)).toThrow(InvalidId);
  });

  it("decode_rejects_unknown_version", () => {
    const scopeMask = new ScopeMask(SECRET);
    const id = encodePayload(sqidsFor(scopeMask, "user"), [2, 0, 5, 0, 0, 0, 0]);
    expect(() => scopeMask.decode("user", id)).toThrow(InvalidId);
  });

  it("decode_rejects_bad_checksum", () => {
    const scopeMask = new ScopeMask(SECRET);
    const id = encodePayload(sqidsFor(scopeMask, "user"), [1, 0, 5, 0, 0, 0, 0]);
    expect(() => scopeMask.decode("user", id)).toThrow(InvalidId);
  });

  it("decode_rejects_malformed_payload", () => {
    const scopeMask = new ScopeMask(SECRET);
    const id = sqidsFor(scopeMask, "user").encode([5]);
    expect(() => scopeMask.decode("user", id)).toThrow(InvalidId);
  });

  it("decode_rejects_unknown_tag", () => {
    const scopeMask = new ScopeMask(SECRET);
    const id = sealedId(scopeMask, "user", [9, 1, 2]);
    expect(() => scopeMask.decode("user", id)).toThrow(InvalidId);
  });

  it("decode_rejects_bad_uuid_length", () => {
    const scopeMask = new ScopeMask(SECRET);
    const id = sealedId(scopeMask, "user", [3, 1, 2, 3]);
    expect(() => scopeMask.decode("user", id)).toThrow(InvalidId);
  });

  it("uuid_validates_byte_length", () => {
    expect(() => new UUID(new Uint8Array(15))).toThrow();
  });

  it("uuid_parse_rejects_invalid", () => {
    expect(() => UUID.parse("not-a-uuid")).toThrow();
  });

  it("uuid_equals", () => {
    const a = UUID.parse("12345678-1234-5678-1234-567812345678");
    const b = UUID.parse("12345678-1234-5678-1234-567812345678");
    const c = UUID.parse("00000000-0000-0000-0000-000000000000");
    expect(a.equals(b)).toBe(true);
    expect(a.equals(c)).toBe(false);
  });

  it("scope_handle", () => {
    const scopeMask = new ScopeMask(SECRET);
    const users = scopeMask.scope("user", "id_");

    const enc = users.encode(42)!;
    expect(enc).toBe(scopeMask.encode("user", 42, "id_"));
    expect(users.decode(enc)).toBe(42);
    expect(users.tryDecode("not-a-real-id")).toBeNull();

    const ids = users.encodeMany([1, 2, 3]) as string[];
    expect(users.decodeMany(ids)).toEqual([1, 2, 3]);
    expect(users.tryDecodeMany([ids[0]!, "not-a-real-id", ids[2]!])).toEqual([1, null, 3]);
  });
});
