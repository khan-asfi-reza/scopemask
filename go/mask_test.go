package scopemask

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const SECRET = "test-secret"

func assertEncodeDecode[T interface {
	Maskable
	comparable
}](t *testing.T, scopeMask *ScopeMask, scope, prefix string, value T, minLength uint8) {
	t.Helper()
	enc, err := Encode(scopeMask, scope, value, prefix)
	if err != nil {
		t.Fatalf("Encode(%v): %v", value, err)
	}
	if len(enc) < int(minLength) {
		t.Errorf("len(%q)=%d < minLength %d", enc, len(enc), minLength)
	}
	if !strings.HasPrefix(enc, prefix) {
		t.Errorf("%q missing prefix %q", enc, prefix)
	}
	got, err := Decode[T](scopeMask, scope, enc, prefix)
	if err != nil {
		t.Fatalf("Decode(%q): %v", enc, err)
	}
	if got != value {
		t.Errorf("decoded = %v, want %v", got, value)
	}
}

func assertEncodeDecodeBytes(t *testing.T, scopeMask *ScopeMask, scope, prefix string, value []byte, minLength uint8) {
	t.Helper()
	enc, err := Encode(scopeMask, scope, value, prefix)
	if err != nil {
		t.Fatalf("Encode(%v): %v", value, err)
	}
	if len(enc) < int(minLength) {
		t.Errorf("len(%q)=%d < minLength %d", enc, len(enc), minLength)
	}
	if !strings.HasPrefix(enc, prefix) {
		t.Errorf("%q missing prefix %q", enc, prefix)
	}
	got, err := Decode[[]byte](scopeMask, scope, enc, prefix)
	if err != nil {
		t.Fatalf("Decode(%q): %v", enc, err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("decoded = %v, want %v", got, value)
	}
}

func TestEncodeDecode(t *testing.T) {
	uintValues := []uint64{1, 2, 0, 42, 1 << 63, ^uint64(0)}
	stringValues := []string{"user@example.com", "", "hello", "üñîçødé 🐍"}
	bytesValues := [][]byte{{1, 2, 3, 4}, {}, {0, 1, 255}}
	uuidValue, _ := ParseUUID("12345678-1234-5678-1234-567812345678")

	for _, minLength := range []uint8{16, 24, 32, 64} {
		for _, alphabet := range []string{BaseAlphabet, "abcdefg1234#$"} {
			for _, scope := range []string{"user", "entity", "profile", "accounts", "webhook"} {
				for _, prefix := range []string{"", "id_", "test_", "sk"} {
					scopeMask, err := New(SECRET, WithMinLength(minLength), WithBaseAlphabet(alphabet))
					if err != nil {
						t.Fatalf("New: %v", err)
					}
					if string(scopeMask.secrets[0]) != SECRET {
						t.Errorf("secret = %q, want %q", scopeMask.secrets[0], SECRET)
					}
					if scopeMask.minLength != minLength {
						t.Errorf("minLength = %d, want %d", scopeMask.minLength, minLength)
					}
					if scopeMask.baseAlphabet != alphabet {
						t.Errorf("baseAlphabet = %q, want %q", scopeMask.baseAlphabet, alphabet)
					}
					for _, v := range uintValues {
						assertEncodeDecode(t, scopeMask, scope, prefix, v, minLength)
					}
					for _, v := range stringValues {
						assertEncodeDecode(t, scopeMask, scope, prefix, v, minLength)
					}
					for _, v := range bytesValues {
						assertEncodeDecodeBytes(t, scopeMask, scope, prefix, v, minLength)
					}
					assertEncodeDecode(t, scopeMask, scope, prefix, uuidValue, minLength)
				}
			}
		}
	}
}

type parityVector struct {
	Secret string `json:"secret"`
	Scope  string `json:"scope"`
	Prefix string `json:"prefix"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	ID     string `json:"id"`
}

func TestCrossLanguageParity(t *testing.T) {
	data, err := os.ReadFile("../fixtures/parity_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors []parityVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	for _, v := range vectors {
		scopeMask, _ := New(v.Secret)
		switch v.Type {
		case "int":
			n, _ := strconv.ParseUint(v.Value, 10, 64)
			if id, err := Encode(scopeMask, v.Scope, n, v.Prefix); err != nil || id != v.ID {
				t.Errorf("encode int %s = %q, %v; want %q", v.Value, id, err, v.ID)
			}
			if got, err := Decode[uint64](scopeMask, v.Scope, v.ID, v.Prefix); err != nil || got != n {
				t.Errorf("decode %q = %d, %v; want %d", v.ID, got, err, n)
			}
		case "str":
			if id, err := Encode(scopeMask, v.Scope, v.Value, v.Prefix); err != nil || id != v.ID {
				t.Errorf("encode str %q = %q, %v; want %q", v.Value, id, err, v.ID)
			}
			if got, err := Decode[string](scopeMask, v.Scope, v.ID, v.Prefix); err != nil || got != v.Value {
				t.Errorf("decode %q = %q, %v; want %q", v.ID, got, err, v.Value)
			}
		case "bytes":
			b, _ := hex.DecodeString(v.Value)
			if id, err := Encode(scopeMask, v.Scope, b, v.Prefix); err != nil || id != v.ID {
				t.Errorf("encode bytes %s = %q, %v; want %q", v.Value, id, err, v.ID)
			}
			if got, err := Decode[[]byte](scopeMask, v.Scope, v.ID, v.Prefix); err != nil || !bytes.Equal(got, b) {
				t.Errorf("decode %q = %x, %v; want %s", v.ID, got, err, v.Value)
			}
		case "uuid":
			u, _ := ParseUUID(v.Value)
			if id, err := Encode(scopeMask, v.Scope, u, v.Prefix); err != nil || id != v.ID {
				t.Errorf("encode uuid %s = %q, %v; want %q", v.Value, id, err, v.ID)
			}
			if got, err := Decode[UUID](scopeMask, v.Scope, v.ID, v.Prefix); err != nil || got != u {
				t.Errorf("decode %q = %v, %v; want %s", v.ID, got, err, v.Value)
			}
		default:
			t.Errorf("unknown type %q", v.Type)
		}
	}
}

func TestScopeIsolation(t *testing.T) {
	scopeMask, _ := New(SECRET)
	a, _ := Encode(scopeMask, "user", uint64(1), "")
	b, _ := Encode(scopeMask, "order", uint64(1), "")
	if a == b {
		t.Errorf("scopes produced identical ids: %q", a)
	}
}

func TestNegativeRejected(t *testing.T) {
	scopeMask, _ := New(SECRET)
	if _, err := Encode(scopeMask, "user", -1, ""); err == nil {
		t.Error("negative int = nil err, want error")
	}
}

func TestInvalidIDRejected(t *testing.T) {
	scopeMask, _ := New(SECRET)
	if _, err := Decode[uint64](scopeMask, "user", "", ""); !errors.Is(err, ErrInvalidID) {
		t.Errorf("empty err = %v, want ErrInvalidID", err)
	}
	if _, err := Decode[uint64](scopeMask, "user", "whs_x", "whs_"); !errors.Is(err, ErrInvalidID) {
		t.Errorf("bad-prefix err = %v, want ErrInvalidID", err)
	}
}

func TestEmptySecretRejected(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("New(\"\") = nil err, want error")
	}
}

func TestDeriveAlphabetDeterministic(t *testing.T) {
	a := DeriveAlphabet([]byte("s"), "user", BaseAlphabet)
	b := DeriveAlphabet([]byte("s"), "user", BaseAlphabet)
	c := DeriveAlphabet([]byte("s"), "order", BaseAlphabet)
	if a != b {
		t.Error("not deterministic")
	}
	if a == c {
		t.Error("scope did not change alphabet")
	}
	if sortString(a) != sortString(BaseAlphabet) {
		t.Error("not a permutation of base alphabet")
	}
}

func sortString(s string) string {
	r := []rune(s)
	sort.Slice(r, func(i, j int) bool { return r[i] < r[j] })
	return string(r)
}

func TestIntegrityRejectsWrongScope(t *testing.T) {
	scopeMask, _ := New(SECRET)
	enc, _ := Encode(scopeMask, "user", uint64(42), "")
	if _, err := Decode[uint64](scopeMask, "order", enc, ""); !errors.Is(err, ErrInvalidID) {
		t.Errorf("wrong-scope decode err = %v, want ErrInvalidID", err)
	}
}

func TestIntegrityRejectsTamper(t *testing.T) {
	scopeMask, _ := New(SECRET)
	enc, _ := Encode(scopeMask, "user", uint64(42), "")
	tampered := enc[:len(enc)-1] + string(rune(enc[len(enc)-1])+1)
	if _, err := Decode[uint64](scopeMask, "user", tampered, ""); err == nil {
		t.Error("tampered id decoded without error")
	}
}

func TestTryDecode(t *testing.T) {
	scopeMask, _ := New(SECRET)
	enc, _ := Encode(scopeMask, "user", uint64(7), "")
	if v, ok := TryDecode[uint64](scopeMask, "user", enc, ""); !ok || v != 7 {
		t.Errorf("TryDecode = %v, %v; want 7, true", v, ok)
	}
	if _, ok := TryDecode[uint64](scopeMask, "user", "not-an-id", ""); ok {
		t.Error("TryDecode of garbage = ok, want false")
	}
}

func TestSecretRotation(t *testing.T) {
	old, _ := New("old-secret")
	enc, _ := Encode(old, "user", uint64(99), "")

	rotated, _ := New("new-secret", WithPreviousSecrets("old-secret"))
	got, err := Decode[uint64](rotated, "user", enc, "")
	if err != nil || got != 99 {
		t.Errorf("rotated decode = %v, %v; want 99", got, err)
	}
	fresh, _ := New("new-secret")
	if _, ok := TryDecode[uint64](fresh, "user", enc, ""); ok {
		t.Error("id decoded under unrelated secret")
	}
	reenc, _ := Encode(rotated, "user", uint64(99), "")
	if reenc == enc {
		t.Error("rotated encode reused old secret's id")
	}
}

func TestBatch(t *testing.T) {
	scopeMask, _ := New(SECRET)
	want := []uint64{1, 2, 3, 1 << 40}
	ids, err := EncodeMany(scopeMask, "user", want, "id_")
	if err != nil {
		t.Fatalf("EncodeMany: %v", err)
	}
	got, err := DecodeMany[uint64](scopeMask, "user", ids, "id_")
	if err != nil {
		t.Fatalf("DecodeMany: %v", err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("batch[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestTryDecodeMany(t *testing.T) {
	scopeMask, _ := New(SECRET)
	ids, _ := EncodeMany(scopeMask, "user", []uint64{1, 2, 3}, "id_")
	vals, oks := TryDecodeMany[uint64](scopeMask, "user", []string{ids[0], "not-an-id", ids[2]}, "id_")
	want := []uint64{1, 0, 3}
	wantOk := []bool{true, false, true}
	for i := range want {
		if vals[i] != want[i] || oks[i] != wantOk[i] {
			t.Errorf("idx %d = %d, %v; want %d, %v", i, vals[i], oks[i], want[i], wantOk[i])
		}
	}
}

func TestIntegerWidthsRoundTrip(t *testing.T) {
	scopeMask, _ := New(SECRET)

	e8, _ := Encode(scopeMask, "user", int8(5), "")
	if g, err := Decode[int8](scopeMask, "user", e8, ""); err != nil || g != 5 {
		t.Errorf("int8 = %v, %v", g, err)
	}
	e16, _ := Encode(scopeMask, "user", int16(5), "")
	if g, err := Decode[int16](scopeMask, "user", e16, ""); err != nil || g != 5 {
		t.Errorf("int16 = %v, %v", g, err)
	}
	e32, _ := Encode(scopeMask, "user", int32(5), "")
	if g, err := Decode[int32](scopeMask, "user", e32, ""); err != nil || g != 5 {
		t.Errorf("int32 = %v, %v", g, err)
	}
	e64, _ := Encode(scopeMask, "user", int64(5), "")
	if g, err := Decode[int64](scopeMask, "user", e64, ""); err != nil || g != 5 {
		t.Errorf("int64 = %v, %v", g, err)
	}
	ei, _ := Encode(scopeMask, "user", int(5), "")
	if g, err := Decode[int](scopeMask, "user", ei, ""); err != nil || g != 5 {
		t.Errorf("int = %v, %v", g, err)
	}
	eu, _ := Encode(scopeMask, "user", uint(5), "")
	if g, err := Decode[uint](scopeMask, "user", eu, ""); err != nil || g != 5 {
		t.Errorf("uint = %v, %v", g, err)
	}
	eu8, _ := Encode(scopeMask, "user", uint8(5), "")
	if g, err := Decode[uint8](scopeMask, "user", eu8, ""); err != nil || g != 5 {
		t.Errorf("uint8 = %v, %v", g, err)
	}
	eu16, _ := Encode(scopeMask, "user", uint16(5), "")
	if g, err := Decode[uint16](scopeMask, "user", eu16, ""); err != nil || g != 5 {
		t.Errorf("uint16 = %v, %v", g, err)
	}
	eu32, _ := Encode(scopeMask, "user", uint32(5), "")
	if g, err := Decode[uint32](scopeMask, "user", eu32, ""); err != nil || g != 5 {
		t.Errorf("uint32 = %v, %v", g, err)
	}
}

func TestNegativeIntegerWidthsRejected(t *testing.T) {
	scopeMask, _ := New(SECRET)
	if _, err := Encode(scopeMask, "user", int8(-1), ""); err == nil {
		t.Error("int8")
	}
	if _, err := Encode(scopeMask, "user", int16(-1), ""); err == nil {
		t.Error("int16")
	}
	if _, err := Encode(scopeMask, "user", int32(-1), ""); err == nil {
		t.Error("int32")
	}
	if _, err := Encode(scopeMask, "user", int64(-1), ""); err == nil {
		t.Error("int64")
	}
}

func TestDecodeWrongType(t *testing.T) {
	scopeMask, _ := New(SECRET)
	encStr, _ := Encode(scopeMask, "user", "hello", "")
	if _, err := Decode[uint64](scopeMask, "user", encStr, ""); !errors.Is(err, ErrInvalidID) {
		t.Error("string decoded as uint64")
	}
	u, _ := ParseUUID("12345678-1234-5678-1234-567812345678")
	encUUID, _ := Encode(scopeMask, "user", u, "")
	if _, err := Decode[string](scopeMask, "user", encUUID, ""); !errors.Is(err, ErrInvalidID) {
		t.Error("uuid decoded as string")
	}
	encBytes, _ := Encode(scopeMask, "user", []byte{1, 2}, "")
	if _, err := Decode[uint64](scopeMask, "user", encBytes, ""); !errors.Is(err, ErrInvalidID) {
		t.Error("bytes decoded as uint64")
	}
}

func TestUUIDStringAndParse(t *testing.T) {
	const canonical = "12345678-1234-5678-1234-567812345678"
	u, err := ParseUUID(canonical)
	if err != nil || u.String() != canonical {
		t.Errorf("ParseUUID/String = %q, %v", u.String(), err)
	}
	if _, err := ParseUUID("too-short"); err == nil {
		t.Error("short UUID accepted")
	}
	if _, err := ParseUUID("zz345678-1234-5678-1234-567812345678"); err == nil {
		t.Error("non-hex UUID accepted")
	}
}

func TestAlphabetFor(t *testing.T) {
	scopeMask, _ := New(SECRET)
	if scopeMask.AlphabetFor("user") != DeriveAlphabet([]byte(SECRET), "user", BaseAlphabet) {
		t.Error("AlphabetFor does not match DeriveAlphabet")
	}
}

func TestEncodeManyRejectsBadValue(t *testing.T) {
	scopeMask, _ := New(SECRET)
	if _, err := EncodeMany(scopeMask, "user", []int{1, -1, 3}, ""); err == nil {
		t.Error("EncodeMany accepted a negative int")
	}
}

func TestDecodeManyRejectsInvalid(t *testing.T) {
	scopeMask, _ := New(SECRET)
	if _, err := DecodeMany[uint64](scopeMask, "user", []string{"not-an-id"}, ""); err == nil {
		t.Error("DecodeMany accepted an invalid id")
	}
}

func TestToPayloadRejectsUnsupportedType(t *testing.T) {
	if _, err := toPayload(3.14); err == nil {
		t.Error("float64 accepted")
	}
}

func TestFromPayloadRejectsBadInput(t *testing.T) {
	if _, err := fromPayload(nil); err == nil {
		t.Error("empty payload accepted")
	}
	if _, err := fromPayload([]byte{tagUUID, 1, 2, 3}); err == nil {
		t.Error("short UUID body accepted")
	}
	if _, err := fromPayload([]byte{9}); err == nil {
		t.Error("unknown tag accepted")
	}
}

func TestNumsToPayloadRejectsBadInput(t *testing.T) {
	if _, err := numsToPayload(nil); err == nil {
		t.Error("empty nums accepted")
	}
	if _, err := numsToPayload([]uint64{2, 0xFFFFFFFFFFFFFFFF}); err == nil {
		t.Error("chunk overflow accepted")
	}
	if _, err := numsToPayload([]uint64{5}); err == nil {
		t.Error("length mismatch accepted")
	}
}

func TestDecodeRejectsUnknownVersion(t *testing.T) {
	scopeMask, _ := New(SECRET)
	s, _ := scopeMask.sqidsForIdx(0, "user")
	payload := []byte{2, tagInt, 5, 0, 0, 0, 0}
	id, _ := s.Encode(payloadToNums(payload))
	if _, err := Decode[uint64](scopeMask, "user", id, ""); !errors.Is(err, ErrInvalidID) {
		t.Error("unknown version accepted")
	}
}

func TestScope(t *testing.T) {
	scopeMask, _ := New(SECRET)
	users := scopeMask.Scope("user", "id_")

	enc, _ := EncodeIn(users, uint64(42))
	direct, _ := Encode(scopeMask, "user", uint64(42), "id_")
	if enc != direct {
		t.Errorf("EncodeIn = %q, want %q", enc, direct)
	}
	if v, _ := DecodeIn[uint64](users, enc); v != 42 {
		t.Errorf("DecodeIn = %d, want 42", v)
	}
	if _, ok := TryDecodeIn[uint64](users, "not-a-real-id"); ok {
		t.Error("TryDecodeIn of garbage = ok, want false")
	}
	ids, _ := EncodeManyIn(users, []uint64{1, 2, 3})
	vals, _ := DecodeManyIn[uint64](users, ids)
	for i, w := range []uint64{1, 2, 3} {
		if vals[i] != w {
			t.Errorf("DecodeManyIn[%d] = %d, want %d", i, vals[i], w)
		}
	}
}
