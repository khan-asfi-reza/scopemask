import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import Sqids from "sqids";

export const MIN_LENGTH = 16;
export const BASE_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const VERSION = 1;
const MAC_LEN = 4;

const TAG_INT = 0;
const TAG_STR = 1;
const TAG_BYTES = 2;
const TAG_UUID = 3;
const CHUNK = 6;

const utf8 = new TextEncoder();

function toBytes(value: Uint8Array | string): Uint8Array {
  return typeof value === "string" ? utf8.encode(value) : value;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export class UUID {
  readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    if (bytes.length !== 16) {
      throw new Error(`UUID must be 16 bytes, got ${bytes.length}`);
    }
    this.bytes = Uint8Array.from(bytes);
  }

  static parse(s: string): UUID {
    const hex = s.replace(/-/g, "");
    if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
      throw new Error(`invalid UUID: ${s}`);
    }
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return new UUID(bytes);
  }

  toString(): string {
    const h = Array.from(this.bytes, (x) => x.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  equals(other: UUID): boolean {
    return this.bytes.every((b, i) => b === other.bytes[i]);
  }
}

export type Maskable = number | bigint | string | Uint8Array | UUID;

export class InvalidId extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidId";
  }
}

function toPayload(value: Maskable): Uint8Array {
  if (value instanceof UUID) {
    return Uint8Array.of(TAG_UUID, ...value.bytes);
  }
  if (typeof value === "number" || typeof value === "bigint") {
    if (typeof value === "number" && !Number.isInteger(value)) {
      throw new RangeError(`int must be an integer, got ${value}`);
    }
    let v = BigInt(value);
    if (v < 0n) {
      throw new RangeError(`int must be non-negative, got ${value}`);
    }
    const bytes: number[] = [];
    while (v > 0n) {
      bytes.unshift(Number(v & 0xffn));
      v >>= 8n;
    }
    return Uint8Array.of(TAG_INT, ...bytes);
  }
  if (typeof value === "string") {
    return Uint8Array.of(TAG_STR, ...utf8.encode(value));
  }
  if (value instanceof Uint8Array) {
    return Uint8Array.of(TAG_BYTES, ...value);
  }
  throw new TypeError(`unsupported type for encode: ${typeof value}`);
}

function fromPayload(inner: Uint8Array): Maskable {
  if (inner.length === 0) throw new InvalidId("empty payload");
  const tag = inner[0];
  const body = inner.subarray(1);
  if (tag === TAG_INT) {
    let v = 0n;
    for (const b of body) v = (v << 8n) | BigInt(b);
    return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
  }
  if (tag === TAG_STR) return new TextDecoder().decode(body);
  if (tag === TAG_BYTES) return body.slice();
  if (tag === TAG_UUID) {
    if (body.length !== 16) throw new InvalidId(`bad UUID length ${body.length}`);
    return new UUID(body);
  }
  throw new InvalidId(`unknown type tag: ${tag}`);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function computeChecksum(secret: Uint8Array, scope: string, signed: Uint8Array): Uint8Array {
  const scopeBytes = utf8.encode(scope);
  const message = new Uint8Array(scopeBytes.length + 1 + signed.length);
  message.set(scopeBytes, 0);
  message[scopeBytes.length] = 0;
  message.set(signed, scopeBytes.length + 1);
  return hmac(sha256, secret, message).subarray(0, MAC_LEN);
}

function wrapPayload(secret: Uint8Array, scope: string, inner: Uint8Array): Uint8Array {
  const signed = Uint8Array.of(VERSION, ...inner);
  return concat(signed, computeChecksum(secret, scope, signed));
}

function payloadToNums(payload: Uint8Array): number[] {
  const nums: number[] = [payload.length];
  for (let i = 0; i < payload.length; i += CHUNK) {
    let n = 0;
    for (let j = i; j < Math.min(i + CHUNK, payload.length); j++) {
      n = n * 256 + payload[j]!;
    }
    nums.push(n);
  }
  return nums;
}

function numsToPayload(nums: number[]): Uint8Array {
  if (nums.length === 0) throw new InvalidId("empty payload");
  const length = nums[0]!;
  const out: number[] = [];
  let remaining = length;
  for (const num of nums.slice(1)) {
    const k = Math.min(CHUNK, remaining);
    const bytes: number[] = [];
    let x = num;
    for (let b = 0; b < k; b++) {
      bytes.unshift(x % 256);
      x = Math.floor(x / 256);
    }
    if (x !== 0) throw new InvalidId("chunk overflow");
    out.push(...bytes);
    remaining -= k;
  }
  if (remaining !== 0 || out.length !== length) {
    throw new InvalidId("length mismatch");
  }
  return Uint8Array.from(out);
}

export interface ScopeMaskOptions {
  previousSecrets?: (Uint8Array | string)[];
  minLength?: number;
  baseAlphabet?: string;
}

/**
 * ScopeMask provides a way to mask numbers, bigints, strings, byte arrays, and UUIDs.
 *
 * It uses a combination of sqids and hmac to generate opaque ids that are
 * scope-bound and secret-bound.
 */
export class ScopeMask {
  private readonly secrets: Uint8Array[];
  private readonly minLength: number;
  private readonly baseAlphabet: string;
  private readonly cache = new Map<string, Sqids>();

  /**
   * @param secret - Secret key for masking.
   * @param options.previousSecrets - Previous secrets for backward compatibility.
   * @param options.minLength - Minimum length of the masked id.
   * @param options.baseAlphabet - Base alphabet for sqids.
   */
  constructor(secret: Uint8Array | string, options: ScopeMaskOptions = {}) {
    if (!secret || secret.length === 0) {
      throw new Error("ScopeMask secret must be a non-empty string or Uint8Array");
    }
    this.secrets = [
      toBytes(secret),
      ...(options.previousSecrets ?? []).filter((s) => s && s.length > 0).map(toBytes),
    ];
    this.minLength = options.minLength ?? MIN_LENGTH;
    this.baseAlphabet = options.baseAlphabet ?? BASE_ALPHABET;
  }

  alphabetFor(scope: string, idx = 0): string {
    const secret = this.secrets[idx]!;
    const chars = [...this.baseAlphabet];
    let pool: Uint8Array = new Uint8Array(0);
    let pos = 0;
    let counter = 0;
    for (let i = chars.length - 1; i > 0; i--) {
      if (pos >= pool.length) {
        pool = hmac(sha256, secret, utf8.encode(`${scope}:${counter}`));
        counter += 1;
        pos = 0;
      }
      const j = pool[pos]! % (i + 1);
      pos += 1;
      [chars[i], chars[j]] = [chars[j]!, chars[i]!];
    }
    return chars.join("");
  }

  private sqidsFor(idx: number, scope: string): Sqids {
    const key = `${idx} ${scope}`;
    let sqids = this.cache.get(key);
    if (!sqids) {
      sqids = new Sqids({
        alphabet: this.alphabetFor(scope, idx),
        minLength: this.minLength,
        blocklist: new Set(),
      });
      this.cache.set(key, sqids);
    }
    return sqids;
  }

  /**
   * Encodes a value to masked string.
   *
   * @param scope - Scope of the value.
   * @param value - Value to encode.
   * @param prefix - Prefix to add to the masked id.
   * @returns Masked id.
   */
  encode(scope: string, value: Maskable | null, prefix = ""): string | null {
    if (value === null) {
      return null;
    }
    const payload = wrapPayload(this.secrets[0]!, scope, toPayload(value));
    return `${prefix}${this.sqidsFor(0, scope).encode(payloadToNums(payload))}`;
  }

  /**
   * Encodes a list of values to masked strings.
   *
   * @param scope - Scope of the values.
   * @param values - List of values to encode.
   * @param prefix - Prefix to add to the masked ids.
   * @returns List of masked ids.
   */
  encodeMany(
    scope: string,
    values: (Maskable | null)[],
    prefix = "",
  ): (string | null)[] {
    return values.map((value) => this.encode(scope, value, prefix));
  }

  /**
   * Decodes a masked string to its original value.
   *
   * @param scope - Scope of the masked id.
   * @param value - Masked id to decode.
   * @param prefix - Prefix to remove from the masked id.
   * @returns Decoded value.
   * @throws {InvalidId} If the masked id is invalid.
   */
  decode(scope: string, value: string, prefix = ""): Maskable {
    if (typeof value !== "string" || value.length === 0) {
      throw new InvalidId(`Empty or non-string id: ${value}`);
    }
    if (prefix && !value.startsWith(prefix)) {
      throw new InvalidId(
        `Invalid id for scope ${scope}: expected prefix ${prefix}, got ${value}`,
      );
    }
    const body = prefix ? value.slice(prefix.length) : value;
    for (let idx = 0; idx < this.secrets.length; idx++) {
      const sqids = this.sqidsFor(idx, scope);
      const decoded = sqids.decode(body);
      if (decoded.length === 0) {
        continue;
      }
      let payload: Uint8Array;
      try {
        if (sqids.encode(decoded) !== body) {
          continue;
        }
        payload = numsToPayload(decoded);
      } catch {
        continue;
      }
      if (payload.length < 2 + MAC_LEN) {
        continue;
      }
      const signed = payload.subarray(0, payload.length - MAC_LEN);
      const tag = payload.subarray(payload.length - MAC_LEN);
      if (
        signed[0] !== VERSION ||
        !constantTimeEqual(tag, computeChecksum(this.secrets[idx]!, scope, signed))
      ) {
        continue;
      }
      return fromPayload(signed.subarray(1));
    }
    throw new InvalidId(`Invalid id for scope ${scope}: ${value}`);
  }


  /**
   * Attempts to decode a masked string to its original value.
   *
   * @param scope - Scope of the masked id.
   * @param value - Masked id to decode.
   * @param prefix - Prefix to remove from the masked id.
   * @returns Decoded value if successful, null otherwise.
   */
  tryDecode(scope: string, value: string, prefix = ""): Maskable | null {
    try {
      return this.decode(scope, value, prefix);
    } catch (e) {
      if (e instanceof InvalidId) return null;
      throw e;
    }
  }


  /**
   * Decodes a list of masked strings to their original values.
   *
   * @param scope - Scope of the masked ids.
   * @param values - List of masked ids to decode.
   * @param prefix - Prefix to remove from the masked ids.
   * @returns List of decoded values.
   */
  decodeMany(scope: string, values: string[], prefix = ""): Maskable[] {
    return values.map((value) => this.decode(scope, value, prefix));
  }

  /**
   * Attempts to decode a list of masked strings to their original values.
   *
   * @param scope - Scope of the masked ids.
   * @param values - List of masked ids to decode.
   * @param prefix - Prefix to remove from the masked ids.
   * @returns List of decoded values, with null for any invalid id.
   */
  tryDecodeMany(scope: string, values: string[], prefix = ""): (Maskable | null)[] {
    return values.map((value) => this.tryDecode(scope, value, prefix));
  }

  /**
   * Returns a handle bound to one scope and prefix.
   *
   * @param scope - Scope to bind.
   * @param prefix - Prefix to bind.
   * @returns A handle whose encode/decode methods use the bound scope and prefix.
   */
  scope(scope: string, prefix = ""): Scope {
    return new Scope(this, scope, prefix);
  }
}

/**
 * A ScopeMask handle bound to one scope and prefix.
 *
 * It exposes the same encode and decode methods as ScopeMask, but the scope
 * and prefix are fixed when the handle is created instead of passed each call.
 */
export class Scope {
  constructor(
    private readonly mask: ScopeMask,
    private readonly scopeName: string,
    private readonly prefix = "",
  ) {}

  /**
   * Encodes a value to masked string.
   *
   * @param value - Value to encode.
   * @returns Masked id.
   */
  encode(value: Maskable | null): string | null {
    return this.mask.encode(this.scopeName, value, this.prefix);
  }

  /**
   * Encodes a list of values to masked strings.
   *
   * @param values - List of values to encode.
   * @returns List of masked ids.
   */
  encodeMany(values: (Maskable | null)[]): (string | null)[] {
    return this.mask.encodeMany(this.scopeName, values, this.prefix);
  }

  /**
   * Decodes a masked string to its original value.
   *
   * @param value - Masked id to decode.
   * @returns Decoded value.
   * @throws {InvalidId} If the masked id is invalid.
   */
  decode(value: string): Maskable {
    return this.mask.decode(this.scopeName, value, this.prefix);
  }

  /**
   * Decodes a list of masked strings to their original values.
   *
   * @param values - List of masked ids to decode.
   * @returns List of decoded values.
   */
  decodeMany(values: string[]): Maskable[] {
    return this.mask.decodeMany(this.scopeName, values, this.prefix);
  }

  /**
   * Attempts to decode a masked string to its original value.
   *
   * @param value - Masked id to decode.
   * @returns Decoded value if successful, null otherwise.
   */
  tryDecode(value: string): Maskable | null {
    return this.mask.tryDecode(this.scopeName, value, this.prefix);
  }

  /**
   * Attempts to decode a list of masked strings to their original values.
   *
   * @param values - List of masked ids to decode.
   * @returns List of decoded values, with null for any invalid id.
   */
  tryDecodeMany(values: string[]): (Maskable | null)[] {
    return this.mask.tryDecodeMany(this.scopeName, values, this.prefix);
  }
}
