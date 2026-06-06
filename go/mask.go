package scopemask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	sqids "github.com/sqids/sqids-go"
)

const MinLength = 16
const BaseAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

const version = 1
const macLen = 4

var ErrInvalidID = errors.New("scopemask: invalid id")

const (
	tagInt   = 0
	tagStr   = 1
	tagBytes = 2
	tagUUID  = 3
)

const chunk = 6

type Integer interface {
	int | int8 | int16 | int32 | int64 |
		uint | uint8 | uint16 | uint32 | uint64
}

type Maskable interface {
	Integer | string | []byte | UUID
}

type UUID [16]byte

func ParseUUID(s string) (UUID, error) {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return UUID{}, fmt.Errorf("scopemask: invalid UUID %q", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return UUID{}, fmt.Errorf("scopemask: invalid UUID %q: %w", s, err)
	}
	var u UUID
	copy(u[:], b)
	return u, nil
}

func (u UUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

func toPayload(value any) ([]byte, error) {
	var u uint64
	switch v := value.(type) {
	case int:
		if v < 0 {
			return nil, fmt.Errorf("int must be non-negative, got %d", v)
		}
		u = uint64(v)
	case int8:
		if v < 0 {
			return nil, fmt.Errorf("int must be non-negative, got %d", v)
		}
		u = uint64(v)
	case int16:
		if v < 0 {
			return nil, fmt.Errorf("int must be non-negative, got %d", v)
		}
		u = uint64(v)
	case int32:
		if v < 0 {
			return nil, fmt.Errorf("int must be non-negative, got %d", v)
		}
		u = uint64(v)
	case int64:
		if v < 0 {
			return nil, fmt.Errorf("int must be non-negative, got %d", v)
		}
		u = uint64(v)
	case uint:
		u = uint64(v)
	case uint8:
		u = uint64(v)
	case uint16:
		u = uint64(v)
	case uint32:
		u = uint64(v)
	case uint64:
		u = v
	case string:
		return append([]byte{tagStr}, v...), nil
	case []byte:
		return append([]byte{tagBytes}, v...), nil
	case UUID:
		return append([]byte{tagUUID}, v[:]...), nil
	default:
		return nil, fmt.Errorf("unsupported type for Encode: %T", value)
	}
	return append([]byte{tagInt}, minimalBE(u)...), nil
}

func fromPayload(p []byte) (any, error) {
	if len(p) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidID)
	}
	tag, body := p[0], p[1:]
	switch tag {
	case tagInt:
		var n uint64
		for _, b := range body {
			n = n<<8 | uint64(b)
		}
		return n, nil
	case tagStr:
		return string(body), nil
	case tagBytes:
		return body, nil
	case tagUUID:
		if len(body) != 16 {
			return nil, fmt.Errorf("%w: bad UUID length %d", ErrInvalidID, len(body))
		}
		var u UUID
		copy(u[:], body)
		return u, nil
	default:
		return nil, fmt.Errorf("%w: unknown type tag %d", ErrInvalidID, tag)
	}
}

func minimalBE(v uint64) []byte {
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v & 0xff)}, b...)
		v >>= 8
	}
	return b
}

func wrapPayload(secret []byte, scope string, inner []byte) []byte {
	signed := append([]byte{version}, inner...)
	return append(signed, computeChecksum(secret, scope, signed)...)
}

func computeChecksum(secret []byte, scope string, signed []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write(signed)
	return h.Sum(nil)[:macLen]
}

func payloadToNums(p []byte) []uint64 {
	nums := []uint64{uint64(len(p))}
	for i := 0; i < len(p); i += chunk {
		end := i + chunk
		if end > len(p) {
			end = len(p)
		}
		var n uint64
		for _, b := range p[i:end] {
			n = n<<8 | uint64(b)
		}
		nums = append(nums, n)
	}
	return nums
}

func numsToPayload(nums []uint64) ([]byte, error) {
	if len(nums) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidID)
	}
	length := int(nums[0])
	out := make([]byte, 0, length)
	remaining := length
	for _, n := range nums[1:] {
		k := chunk
		if remaining < k {
			k = remaining
		}
		if k < 8 && n>>(8*k) != 0 {
			return nil, fmt.Errorf("%w: chunk overflow", ErrInvalidID)
		}
		for i := k - 1; i >= 0; i-- {
			out = append(out, byte(n>>(8*i)))
		}
		remaining -= k
	}
	if remaining != 0 || len(out) != length {
		return nil, fmt.Errorf("%w: length mismatch", ErrInvalidID)
	}
	return out, nil
}

func castTo[T Maskable](zero T, raw any, scope, value string) (T, error) {
	mismatch := func() (T, error) {
		return zero, fmt.Errorf("%w for scope %q: %q is not the requested type", ErrInvalidID, scope, value)
	}
	switch any(zero).(type) {
	case string:
		s, ok := raw.(string)
		if !ok {
			return mismatch()
		}
		return any(s).(T), nil
	case []byte:
		b, ok := raw.([]byte)
		if !ok {
			return mismatch()
		}
		return any(b).(T), nil
	case UUID:
		u, ok := raw.(UUID)
		if !ok {
			return mismatch()
		}
		return any(u).(T), nil
	}
	n, ok := raw.(uint64)
	if !ok {
		return mismatch()
	}
	var out any
	switch any(zero).(type) {
	case int:
		out = int(n)
	case int8:
		out = int8(n)
	case int16:
		out = int16(n)
	case int32:
		out = int32(n)
	case int64:
		out = int64(n)
	case uint:
		out = uint(n)
	case uint8:
		out = uint8(n)
	case uint16:
		out = uint16(n)
	case uint32:
		out = uint32(n)
	case uint64:
		out = n
	default:
		return mismatch()
	}
	return out.(T), nil
}

func DeriveAlphabet(secret []byte, scope, base string) string {
	chars := []rune(base)
	var pool []byte
	pos, counter := 0, 0
	for i := len(chars) - 1; i > 0; i-- {
		if pos >= len(pool) {
			mac := hmac.New(sha256.New, secret)
			mac.Write([]byte(fmt.Sprintf("%s:%d", scope, counter)))
			pool = mac.Sum(nil)
			counter++
			pos = 0
		}
		j := int(pool[pos]) % (i + 1)
		pos++
		chars[i], chars[j] = chars[j], chars[i]
	}
	return string(chars)
}

type Option func(*ScopeMask)

func WithMinLength(n uint8) Option { return func(m *ScopeMask) { m.minLength = n } }
func WithBaseAlphabet(a string) Option {
	return func(m *ScopeMask) { m.baseAlphabet = a }
}

func WithPreviousSecrets(secrets ...string) Option {
	return func(m *ScopeMask) {
		for _, s := range secrets {
			if s != "" {
				m.secrets = append(m.secrets, []byte(s))
			}
		}
	}
}

// ScopeMask provides a way to mask integers, strings, and UUIDs
//
// It uses a combination of sqids and hmac to generate opaque ids that are
// scope-bound and secret-bound.
type ScopeMask struct {
	secrets      [][]byte
	minLength    uint8
	baseAlphabet string

	mu    sync.Mutex
	cache map[string]*sqids.Sqids
}

func New(secret string, opts ...Option) (*ScopeMask, error) {
	if secret == "" {
		return nil, errors.New("scopemask: secret must be non-empty")
	}
	m := &ScopeMask{
		secrets:      [][]byte{[]byte(secret)},
		minLength:    MinLength,
		baseAlphabet: BaseAlphabet,
		cache:        make(map[string]*sqids.Sqids),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

func (m *ScopeMask) AlphabetFor(scope string) string {
	return DeriveAlphabet(m.secrets[0], scope, m.baseAlphabet)
}

func (m *ScopeMask) sqidsForIdx(idx int, scope string) (*sqids.Sqids, error) {
	key := fmt.Sprintf("%d\x00%s", idx, scope)
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.cache[key]; ok {
		return s, nil
	}
	s, err := sqids.New(sqids.Options{
		Alphabet:  DeriveAlphabet(m.secrets[idx], scope, m.baseAlphabet),
		MinLength: m.minLength,
		Blocklist: []string{},
	})
	if err != nil {
		return nil, err
	}
	m.cache[key] = s
	return s, nil
}

// Encode encodes a value to masked string.
func Encode[T Maskable](m *ScopeMask, scope string, value T, prefix string) (string, error) {
	inner, err := toPayload(any(value))
	if err != nil {
		return "", err
	}
	s, err := m.sqidsForIdx(0, scope)
	if err != nil {
		return "", err
	}
	id, err := s.Encode(payloadToNums(wrapPayload(m.secrets[0], scope, inner)))
	if err != nil {
		return "", err
	}
	return prefix + id, nil
}

// EncodeMany encodes a list of values to masked strings.
func EncodeMany[T Maskable](m *ScopeMask, scope string, values []T, prefix string) ([]string, error) {
	out := make([]string, len(values))
	for i, v := range values {
		id, err := Encode(m, scope, v, prefix)
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		out[i] = id
	}
	return out, nil
}

// Decode decodes a masked string to its original value.
func Decode[T Maskable](m *ScopeMask, scope, value, prefix string) (T, error) {
	return decode[T](m, scope, value, prefix)
}

// TryDecode attempts to decode a masked string to its original value.
func TryDecode[T Maskable](m *ScopeMask, scope, value, prefix string) (val T, ok bool) {
	v, err := decode[T](m, scope, value, prefix)
	return v, err == nil
}

// DecodeMany decodes a list of masked strings to their original values.
func DecodeMany[T Maskable](m *ScopeMask, scope string, values []string, prefix string) ([]T, error) {
	out := make([]T, len(values))
	for i, value := range values {
		v, err := Decode[T](m, scope, value, prefix)
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		out[i] = v
	}
	return out, nil
}

// TryDecodeMany attempts to decode a list of masked strings to their original values.
func TryDecodeMany[T Maskable](m *ScopeMask, scope string, values []string, prefix string) ([]T, []bool) {
	out := make([]T, len(values))
	oks := make([]bool, len(values))
	for i, value := range values {
		out[i], oks[i] = TryDecode[T](m, scope, value, prefix)
	}
	return out, oks
}

// Scope is a ScopeMask handle bound to one scope and prefix. Pass it to the
// *In functions instead of repeating the scope and prefix on every call.
type Scope struct {
	mask   *ScopeMask
	scope  string
	prefix string
}

// Scope returns a handle bound to one scope and prefix.
func (m *ScopeMask) Scope(scope, prefix string) Scope {
	return Scope{mask: m, scope: scope, prefix: prefix}
}

// EncodeIn encodes a value to masked string within a bound scope.
func EncodeIn[T Maskable](s Scope, value T) (string, error) {
	return Encode(s.mask, s.scope, value, s.prefix)
}

// EncodeManyIn encodes a list of values to masked strings within a bound scope.
func EncodeManyIn[T Maskable](s Scope, values []T) ([]string, error) {
	return EncodeMany(s.mask, s.scope, values, s.prefix)
}

// DecodeIn decodes a masked string to its original value within a bound scope.
func DecodeIn[T Maskable](s Scope, value string) (T, error) {
	return Decode[T](s.mask, s.scope, value, s.prefix)
}

// DecodeManyIn decodes a list of masked strings to their original values within a bound scope.
func DecodeManyIn[T Maskable](s Scope, values []string) ([]T, error) {
	return DecodeMany[T](s.mask, s.scope, values, s.prefix)
}

// TryDecodeIn attempts to decode a masked string to its original value within a bound scope.
func TryDecodeIn[T Maskable](s Scope, value string) (T, bool) {
	return TryDecode[T](s.mask, s.scope, value, s.prefix)
}

// TryDecodeManyIn attempts to decode a list of masked strings to their original values within a bound scope.
func TryDecodeManyIn[T Maskable](s Scope, values []string) ([]T, []bool) {
	return TryDecodeMany[T](s.mask, s.scope, values, s.prefix)
}

func decode[T Maskable](m *ScopeMask, scope, value, prefix string) (T, error) {
	var zero T
	if value == "" {
		return zero, fmt.Errorf("%w: empty id", ErrInvalidID)
	}
	if prefix != "" {
		if len(value) < len(prefix) || value[:len(prefix)] != prefix {
			return zero, fmt.Errorf("%w for scope %q: expected prefix %q", ErrInvalidID, scope, prefix)
		}
		value = value[len(prefix):]
	}
	for i, secret := range m.secrets {
		s, err := m.sqidsForIdx(i, scope)
		if err != nil {
			return zero, err
		}
		nums := s.Decode(value)
		if len(nums) == 0 {
			continue
		}
		reencoded, err := s.Encode(nums)
		if err != nil || reencoded != value {
			continue
		}
		payload, err := numsToPayload(nums)
		if err != nil || len(payload) < 2+macLen {
			continue
		}
		signed, tag := payload[:len(payload)-macLen], payload[len(payload)-macLen:]
		if signed[0] != version || !hmac.Equal(tag, computeChecksum(secret, scope, signed)) {
			continue
		}
		raw, err := fromPayload(signed[1:])
		if err != nil {
			continue
		}
		return castTo[T](zero, raw, scope, value)
	}
	return zero, fmt.Errorf("%w for scope %q", ErrInvalidID, scope)
}
