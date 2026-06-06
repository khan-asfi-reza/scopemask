import hashlib
import hmac
import uuid

from sqids import Sqids


MIN_LENGTH = 16
BASE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

VERSION = 1
MAC_LEN = 4

TAG_INT = 0
TAG_STR = 1
TAG_BYTES = 2
TAG_UUID = 3

CHUNK = 6

Maskable = int | str | bytes | uuid.UUID


class InvalidId(Exception):
    pass


def to_payload(value: Maskable) -> bytes:
    if isinstance(value, bool):
        raise ValueError("bool is not supported; use int explicitly")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"int must be non-negative, got {value!r}")
        nbytes = (value.bit_length() + 7) // 8
        return bytes([TAG_INT]) + value.to_bytes(nbytes, "big")
    if isinstance(value, uuid.UUID):
        return bytes([TAG_UUID]) + value.bytes
    if isinstance(value, str):
        return bytes([TAG_STR]) + value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes([TAG_BYTES]) + bytes(value)
    raise ValueError(f"unsupported type for encode: {type(value).__name__}")


def from_payload(inner: bytes) -> Maskable:
    if not inner:
        raise InvalidId("empty payload")
    tag, body = inner[0], inner[1:]
    if tag == TAG_INT:
        return int.from_bytes(body, "big")
    if tag == TAG_STR:
        return body.decode("utf-8")
    if tag == TAG_BYTES:
        return body
    if tag == TAG_UUID:
        if len(body) != 16:
            raise InvalidId(f"bad UUID length {len(body)}")
        return uuid.UUID(bytes=body)
    raise InvalidId(f"unknown type tag: {tag}")


def compute_checksum(secret: bytes, scope: str, signed: bytes) -> bytes:
    h = hmac.new(secret, scope.encode("utf-8") + b"\x00" + signed, hashlib.sha256)
    return h.digest()[:MAC_LEN]


def wrap_payload(secret: bytes, scope: str, inner: bytes) -> bytes:
    signed = bytes([VERSION]) + inner
    return signed + compute_checksum(secret, scope, signed)


def payload_to_nums(payload: bytes) -> list[int]:
    nums = [len(payload)]
    for i in range(0, len(payload), CHUNK):
        nums.append(int.from_bytes(payload[i : i + CHUNK], "big"))
    return nums


def nums_to_payload(nums: list[int]) -> bytes:
    if not nums:
        raise InvalidId("empty payload")
    length, out, remaining = nums[0], bytearray(), nums[0]
    for n in nums[1:]:
        k = min(CHUNK, remaining)
        try:
            out += n.to_bytes(k, "big")
        except OverflowError as exc:
            raise InvalidId("chunk overflow") from exc
        remaining -= k
    if remaining != 0 or len(out) != length:
        raise InvalidId("length mismatch")
    return bytes(out)


def as_bytes(secret: str | bytes) -> bytes:
    return secret.encode() if isinstance(secret, str) else secret


class ScopeMask:
    """
    ScopeMask provides a way to mask integers, strings, and UUIDs

    It uses a combination of sqids and hmac to generate opaque ids that are
    scope-bound and secret-bound.

    Args:
        secret (str | bytes): Secret key for masking.
        previous_secrets (tuple[str | bytes, ...], optional): Previous secrets for
            backward compatibility.
        min_length (int, optional): Minimum length of the masked id.
        base_alphabet (str, optional): Base alphabet for sqids.
    """
    def __init__(
        self,
        secret: str | bytes,
        *,
        previous_secrets: tuple[str | bytes, ...] = (),
        min_length: int = MIN_LENGTH,
        base_alphabet: str = BASE_ALPHABET,
    ):
        if not secret:
            raise ValueError("ScopeMask secret must be a non-empty string or bytes")
        self._secrets = [as_bytes(secret)] + [
            as_bytes(s) for s in previous_secrets if s
        ]
        self._min_length = min_length
        self._base_alphabet = base_alphabet
        self._sqids_cache: dict[tuple[int, str], Sqids] = {}

    @property
    def secret(self) -> bytes:
        return self._secrets[0]

    @property
    def base_alphabet(self) -> str:
        return self._base_alphabet

    def alphabet_for(self, scope: str, idx: int = 0) -> str:
        secret = self._secrets[idx]
        chars = list(self._base_alphabet)
        pool, pos, counter = b"", 0, 0
        for i in range(len(chars) - 1, 0, -1):
            if pos >= len(pool):
                pool = hmac.new(
                    secret, f"{scope}:{counter}".encode(), hashlib.sha256
                ).digest()
                counter += 1
                pos = 0
            j = pool[pos] % (i + 1)
            pos += 1
            chars[i], chars[j] = chars[j], chars[i]
        return "".join(chars)

    def sqids_for(self, idx: int, scope: str) -> Sqids:
        key = (idx, scope)
        sqids = self._sqids_cache.get(key)
        if sqids is None:
            sqids = Sqids(
                alphabet=self.alphabet_for(scope, idx),
                min_length=self._min_length,
                blocklist=[],
            )
            self._sqids_cache[key] = sqids
        return sqids


    def encode(
        self, scope: str, value: Maskable | None, prefix: str = ""
    ) -> str | None:
        """
        Encodes a value to masked string.

        Args:
            scope (str): Scope of the value.
            value (Maskable | None): Value to encode.
            prefix (str, optional): Prefix to add to the masked id.
        
        Returns:
            str | None: Masked id.
        """
        if value is None:
            return None
        payload = wrap_payload(self._secrets[0], scope, to_payload(value))
        nums = payload_to_nums(payload)
        return f"{prefix}{self.sqids_for(0, scope).encode(nums)}"

    def encode_many(
        self, scope: str, values: list[Maskable | None], prefix: str = ""
    ) -> list[str | None]:
        """
        Encodes a list of values to masked strings.

        Args:
            scope (str): Scope of the values.
            values (list[Maskable | None]): List of values to encode.
            prefix (str, optional): Prefix to add to the masked ids.
        
        Returns:
            list[str | None]: List of masked ids.
        """
        return list(map(lambda value: self.encode(scope, value, prefix), values))


    def decode(self, scope: str, value: str, prefix: str = "") -> Maskable:
        """
        Decodes a masked string to its original value.

        Args:
            scope (str): Scope of the masked id.
            value (str): Masked id to decode.
            prefix (str, optional): Prefix to remove from the masked id.
        
        Returns:
            Maskable: Decoded value.

        Raises:
            InvalidId: If the masked id is invalid.
        """
        if not isinstance(value, str) or not value:
            raise InvalidId(f"Empty or non-string id: {value!r}")
        if prefix and not value.startswith(prefix):
            raise InvalidId(
                f"Invalid id for scope {scope!r}: expected prefix {prefix!r}, "
                f"got {value!r}"
            )
        body = value[len(prefix):] if prefix else value
        for idx, secret in enumerate(self._secrets):
            sqids = self.sqids_for(idx, scope)
            decoded = sqids.decode(body)
            if not decoded:
                continue
            try:
                if sqids.encode(decoded) != body:
                    continue
                payload = nums_to_payload(decoded)
            except (ValueError, InvalidId):
                continue
            if len(payload) < 2 + MAC_LEN:
                continue
            signed, tag = payload[:-MAC_LEN], payload[-MAC_LEN:]
            if signed[0] != VERSION:
                continue
            if not hmac.compare_digest(tag, compute_checksum(secret, scope, signed)):
                continue
            return from_payload(signed[1:])
        raise InvalidId(f"Invalid id for scope {scope!r}: {value!r}")


    def try_decode(
        self, scope: str, value: str, prefix: str = ""
    ) -> Maskable | None:
        """
        Attempts to decode a masked string to its original value.

        Args:
            scope (str): Scope of the masked id.
            value (str): Masked id to decode.
            prefix (str, optional): Prefix to remove from the masked id.
        
        Returns:
            Maskable | None: Decoded value if successful, None otherwise.
        """
        try:
            return self.decode(scope, value, prefix)
        except InvalidId:
            return None

    def decode_many(
        self, scope: str, values: list[str], prefix: str = ""
    ) -> list[Maskable]:
        """
        Decodes a list of masked strings to their original values.

        Args:
            scope (str): Scope of the masked ids.
            values (list[str]): List of masked ids to decode.
            prefix (str, optional): Prefix to remove from the masked ids.
        
        Returns:
            list[Maskable]: List of decoded values.
        """
        return list(map(lambda value: self.decode(scope, value, prefix), values))

    def try_decode_many(
        self, scope: str, values: list[str], prefix: str = ""
    ) -> list[Maskable | None]:
        """
        Attempts to decode a list of masked strings to their original values.

        Args:
            scope (str): Scope of the masked ids.
            values (list[str]): List of masked ids to decode.
            prefix (str, optional): Prefix to remove from the masked ids.

        Returns:
            list[Maskable | None]: List of decoded values, None for any invalid id.
        """
        return list(map(lambda value: self.try_decode(scope, value, prefix), values))

    def scope(self, scope: str, prefix: str = "") -> "Scope":
        """
        Returns a handle bound to one scope and prefix.

        Args:
            scope (str): Scope to bind.
            prefix (str, optional): Prefix to bind.

        Returns:
            Scope: A handle whose encode/decode methods use the bound scope and prefix.
        """
        return Scope(self, scope, prefix)


class Scope:
    """
    A ScopeMask handle bound to one scope and prefix.

    It exposes the same encode and decode methods as ScopeMask, but the scope
    and prefix are fixed when the handle is created instead of passed each call.
    """

    def __init__(self, mask: ScopeMask, scope: str, prefix: str = ""):
        self._mask = mask
        self._scope = scope
        self._prefix = prefix

    def encode(self, value: Maskable | None) -> str | None:
        """
        Encodes a value to masked string.

        Args:
            value (Maskable | None): Value to encode.

        Returns:
            str | None: Masked id.
        """
        return self._mask.encode(self._scope, value, self._prefix)

    def encode_many(self, values: list[Maskable | None]) -> list[str | None]:
        """
        Encodes a list of values to masked strings.

        Args:
            values (list[Maskable | None]): List of values to encode.

        Returns:
            list[str | None]: List of masked ids.
        """
        return self._mask.encode_many(self._scope, values, self._prefix)

    def decode(self, value: str) -> Maskable:
        """
        Decodes a masked string to its original value.

        Args:
            value (str): Masked id to decode.

        Returns:
            Maskable: Decoded value.

        Raises:
            InvalidId: If the masked id is invalid.
        """
        return self._mask.decode(self._scope, value, self._prefix)

    def decode_many(self, values: list[str]) -> list[Maskable]:
        """
        Decodes a list of masked strings to their original values.

        Args:
            values (list[str]): List of masked ids to decode.

        Returns:
            list[Maskable]: List of decoded values.
        """
        return self._mask.decode_many(self._scope, values, self._prefix)

    def try_decode(self, value: str) -> Maskable | None:
        """
        Attempts to decode a masked string to its original value.

        Args:
            value (str): Masked id to decode.

        Returns:
            Maskable | None: Decoded value if successful, None otherwise.
        """
        return self._mask.try_decode(self._scope, value, self._prefix)

    def try_decode_many(self, values: list[str]) -> list[Maskable | None]:
        """
        Attempts to decode a list of masked strings to their original values.

        Args:
            values (list[str]): List of masked ids to decode.

        Returns:
            list[Maskable | None]: List of decoded values, None for any invalid id.
        """
        return self._mask.try_decode_many(self._scope, values, self._prefix)
