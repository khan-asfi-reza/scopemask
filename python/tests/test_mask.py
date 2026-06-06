import json
import os
import uuid

import pytest

from scopemask import ScopeMask, InvalidId, BASE_ALPHABET
from scopemask.mask import (
    MAC_LEN,
    TAG_INT,
    TAG_UUID,
    VERSION,
    compute_checksum,
    from_payload,
    nums_to_payload,
    payload_to_nums,
)

SECRET = "test-secret"

VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "fixtures", "parity_vectors.json"
)


def build_value(typ, value):
    if typ == "int":
        return int(value)
    if typ == "str":
        return value
    if typ == "bytes":
        return bytes.fromhex(value)
    if typ == "uuid":
        return uuid.UUID(value)
    raise ValueError(f"unknown type {typ}")


@pytest.mark.parametrize(
    "value",
    (
        1,
        2,
        923828828288828828882888288671235,
        "user@example.com",
        bytes([1, 2, 3, 4]),
        0,
        42,
        2**63,
        2**128 + 7,
        "",
        "hello",
        "üñîçødé 🐍",
        b"",
        b"\x00\x01\xff",
        uuid.UUID("12345678-1234-5678-1234-567812345678"),
    ),
)
@pytest.mark.parametrize("min_length", (16, 24, 32, 64))
@pytest.mark.parametrize("alphabets", (BASE_ALPHABET, "abcdefg1234#$"))
@pytest.mark.parametrize("scope", ("", "user", "entity", "profile", "accounts", "webhook"))
@pytest.mark.parametrize("prefix", ("", "id_", "test_", "sk",))
def test_encode_decode(value, min_length, alphabets, scope, prefix):
    scope_mask = ScopeMask(SECRET, min_length=min_length, base_alphabet=alphabets)
    assert scope_mask.secret == SECRET.encode()
    assert scope_mask._min_length == min_length
    assert scope_mask.base_alphabet == alphabets

    encoded = scope_mask.encode(scope=scope, value=value, prefix=prefix)
    assert len(encoded) >= scope_mask._min_length
    assert encoded.startswith(prefix)

    decoded = scope_mask.decode(scope=scope, value=encoded, prefix=prefix)
    assert decoded == value
    assert isinstance(decoded, type(value))



def test_cross_language_parity():
    with open(VECTORS_PATH, encoding="utf-8") as f:
        vectors = json.load(f)
    for v in vectors:
        scope_mask = ScopeMask(v["secret"])
        value = build_value(v["type"], v["value"])
        assert scope_mask.encode(v["scope"], value, v["prefix"]) == v["id"]
        decoded = scope_mask.decode(v["scope"], v["id"], v["prefix"])
        assert decoded == value
        assert isinstance(decoded, type(value))


def test_unsupported_type_rejected():
    with pytest.raises(ValueError):
        ScopeMask(SECRET).encode("user", 1.5)
    with pytest.raises(ValueError):
        ScopeMask(SECRET).encode("user", True)



def test_scope_isolation():
    scope_mask = ScopeMask(SECRET)
    assert scope_mask.encode("user", 1) != scope_mask.encode("order", 1)


def test_none_encode():
    assert ScopeMask(SECRET).encode("user", None) is None


def test_negative_rejected():
    with pytest.raises(ValueError):
        ScopeMask(SECRET).encode("user", -1)


def test_invalid_id_rejected():
    scope_mask = ScopeMask(SECRET)
    with pytest.raises(InvalidId):
        scope_mask.decode("user", "")
    with pytest.raises(InvalidId):
        scope_mask.decode("user", "whs_x", prefix="whs_")


def test_empty_secret_rejected():
    with pytest.raises(ValueError):
        ScopeMask("")


def test_derive_alphabet_deterministic():
    scope_mask = ScopeMask(b"s")
    a = scope_mask.alphabet_for("user")
    b = scope_mask.alphabet_for("user")
    c = scope_mask.alphabet_for("order")
    assert a == b
    assert a != c
    assert sorted(a) == sorted(scope_mask.alphabet_for("x"))


def test_integrity_rejects_wrong_scope():
    scope_mask = ScopeMask(SECRET)
    enc = scope_mask.encode("user", 42)
    with pytest.raises(InvalidId):
        scope_mask.decode("order", enc)


def test_integrity_rejects_tamper():
    scope_mask = ScopeMask(SECRET)
    enc = scope_mask.encode("user", 42)
    tampered = enc[:-1] + ("A" if enc[-1] != "A" else "B")
    with pytest.raises(InvalidId):
        scope_mask.decode("user", tampered)


def test_try_decode():
    scope_mask = ScopeMask(SECRET)
    enc = scope_mask.encode("user", 7)
    assert scope_mask.try_decode("user", enc) == 7
    assert scope_mask.try_decode("user", "not-an-id") is None


def test_secret_rotation():
    old = ScopeMask("old-secret")
    enc = old.encode("user", 99)

    rotated = ScopeMask("new-secret", previous_secrets=("old-secret",))
    assert rotated.decode("user", enc) == 99
    assert ScopeMask("new-secret").try_decode("user", enc) is None
    assert rotated.encode("user", 99) != enc


def test_batch():
    scope_mask = ScopeMask(SECRET)
    values = [1, 2, 3, 2**40]
    ids = scope_mask.encode_many("user", values, prefix="id_")
    assert scope_mask.decode_many("user", ids, prefix="id_") == values


def test_try_decode_many():
    scope_mask = ScopeMask(SECRET)
    ids = scope_mask.encode_many("user", [1, 2, 3], prefix="id_")
    got = scope_mask.try_decode_many("user", [ids[0], "not-an-id", ids[2]], prefix="id_")
    assert got == [1, None, 3]




def test_from_payload_rejects_empty():
    with pytest.raises(InvalidId):
        from_payload(b"")


def test_from_payload_rejects_bad_uuid_length():
    with pytest.raises(InvalidId):
        from_payload(bytes([TAG_UUID, 1, 2, 3]))


def test_from_payload_rejects_unknown_tag():
    with pytest.raises(InvalidId):
        from_payload(bytes([9]))


def test_nums_to_payload_rejects_empty():
    with pytest.raises(InvalidId):
        nums_to_payload([])


def test_nums_to_payload_rejects_chunk_overflow():
    with pytest.raises(InvalidId):
        nums_to_payload([2, 0xFFFFFFFFFFFFFFFF])


def test_nums_to_payload_rejects_length_mismatch():
    with pytest.raises(InvalidId):
        nums_to_payload([5])


def test_decode_rejects_unknown_version():
    scope_mask = ScopeMask(SECRET)
    sqids = scope_mask.sqids_for(0, "user")
    payload = bytes([2, TAG_INT, 5]) + b"\x00" * MAC_LEN
    id_ = sqids.encode(payload_to_nums(payload))
    with pytest.raises(InvalidId):
        scope_mask.decode("user", id_)


def test_decode_rejects_short_payload():
    scope_mask = ScopeMask(SECRET)
    sqids = scope_mask.sqids_for(0, "user")
    id_ = sqids.encode(payload_to_nums(bytes([VERSION, TAG_INT])))
    with pytest.raises(InvalidId):
        scope_mask.decode("user", id_)


def test_decode_rejects_bad_checksum():
    scope_mask = ScopeMask(SECRET)
    sqids = scope_mask.sqids_for(0, "user")
    signed = bytes([VERSION, TAG_INT, 5])
    real = compute_checksum(SECRET.encode(), "user", signed)
    bad = bytes([real[0] ^ 0xFF]) + real[1:]
    id_ = sqids.encode(payload_to_nums(signed + bad))
    with pytest.raises(InvalidId):
        scope_mask.decode("user", id_)


def test_scope_handle():
    scope_mask = ScopeMask(SECRET)
    users = scope_mask.scope("user", prefix="id_")

    enc = users.encode(42)
    assert enc == scope_mask.encode("user", 42, "id_")
    assert users.decode(enc) == 42
    assert users.try_decode("not-a-real-id") is None

    ids = users.encode_many([1, 2, 3])
    assert users.decode_many(ids) == [1, 2, 3]
    assert users.try_decode_many([ids[0], "not-a-real-id", ids[2]]) == [1, None, 3]
