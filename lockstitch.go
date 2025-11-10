// Package lockstitch provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic
// operations (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex
// protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin transcripts, and Xoodyak's
// Cyclist mode, Lockstitch uses [cSHAKE128], [GMAC], and [AES-128] to provide 10+ Gb/sec performance on modern
// processors at a 128-bit security level.
//
// [cSHAKE128]: https://csrc.nist.gov/pubs/sp/800/185/final
// [GMAC]: https://csrc.nist.gov/pubs/sp/800/38/d/final
// [AES-128]: https://doi.org/10.6028/NIST.FIPS.197-upd1
package lockstitch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha3"
	"crypto/subtle"
	"errors"

	"github.com/codahale/lockstitch-go/internal/mem"
	"github.com/codahale/lockstitch-go/internal/tuplehash"
)

// TagLen is the number of bytes added to the plaintext by the Seal operation.
const TagLen = aes.BlockSize

var (
	// ErrInvalidCiphertext is returned when the ciphertext is invalid or has been decrypted with the
	// wrong key.
	ErrInvalidCiphertext = errors.New("lockstitch: invalid ciphertext")

	// ErrInvalidState is returned when BinaryUnmarshal fails, either due to malformed data or an incorrect protocol
	// domain.
	ErrInvalidState = errors.New("lockstitch: invalid protocol state")
)

// A Protocol is a stateful object providing fine-grained symmetric-key cryptographic services like hashing, message
// authentication codes, pseudo-random functions, authenticated encryption, and more.
type Protocol struct {
	transcript sha3.SHAKE
}

// NewProtocol creates a new Protocol with the given domain separation string.
func NewProtocol(domain string) Protocol {
	// Initialize a cSHAKE128 instance with a customization string of `lockstitch:{domain}`.
	return Protocol{
		transcript: *sha3.NewCSHAKE128(nil, append([]byte("lockstitch:"), []byte(domain)...)),
	}
}

// Mix ratchets the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	// Append the operation metadata and input to the transcript in a recoverable encoding.
	p.combine(make([]byte, 0, 9), opMix, []byte(label), input)
}

// Derive generates pseudorandom output from the Protocol's current state, the label, and the output length, then
// ratchets the Protocol's state with the label and output length. It appends the output to dst and returns the
// resulting slice.
func (p *Protocol) Derive(label string, dst []byte, n int) []byte {
	if n < 0 {
		panic("invalid argument to Derive: n cannot be negative")
	}

	// Allocate a slice for keys and encoded lengths.
	buf := make([]byte, 9+32)

	// Append the operation metadata to the transcript in a recoverable encoding.
	p.combine(buf[:0], opDerive, []byte(label), tuplehash.LeftEncode(buf[9:9], uint64(n)*8))

	// Expand n bytes of PRF output from the transcript.
	prf := p.expand(dst, buf[:0], "prf output", n)

	// Ratchet the transcript.
	p.ratchet(buf[9:9], buf[:0])

	return prf
}

// Encrypt encrypts the plaintext using the protocol's current state as the key, then ratchets the protocol's state
// using the label and input. It appends the ciphertext to dst and returns the resulting slice.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Encrypt(label string, dst, plaintext []byte) []byte {
	// Allocate a slice for the ciphertext and one for keys and encoded lengths.
	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext))
	buf := make([]byte, 9+16+16)

	// Append the operation metadata to the transcript.
	p.combine(buf[:0], opCrypt, []byte(label), tuplehash.LeftEncode(buf[9:9], uint64(len(plaintext))*8))

	// Expand a data key from the transcript.
	dk := p.expand(buf[9:9], buf[:0], "data key", 16)

	// Calculate a GMAC of the plaintext.
	block, _ := aes.NewCipher(dk)
	auth := gmac(block, dk[:0], plaintext)

	// Append the operation data (i.e., the GMAC authenticator) to the transcript.
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(auth))*8))
	_, _ = p.transcript.Write(auth)

	// Encrypt the plaintext using AES-128-CTR with an all-zero IV.
	ctr(block, zeroBlock[:], ciphertext, plaintext)

	// Ratchet the transcript.
	p.ratchet(buf[9:9], buf[:0])

	return ret
}

// Decrypt decrypts the given ciphertext using the protocol's current state as the key, then ratchets the protocol's
// state using the label and input. It appends the plaintext to dst and returns the resulting slice. To reuse
// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity of dst
// must not overlap ciphertext.
func (p *Protocol) Decrypt(label string, dst, ciphertext []byte) []byte {
	// Allocate a slice for the plaintext and one for keys and encoded lengths.
	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))
	buf := make([]byte, 9+16+16)

	// Append the operation metadata to the transcript.
	p.combine(buf[:0], opCrypt, []byte(label), tuplehash.LeftEncode(buf[9:9], uint64(len(ciphertext))*8))

	// Expand a data key from the transcript.
	dk := p.expand(buf[9:9], buf[:0], "data key", 16)

	// Decrypt the ciphertext using AES-128-CTR with an all-zero IV.
	block, _ := aes.NewCipher(dk)
	ctr(block, zeroBlock[:], plaintext, ciphertext)

	// Calculate a GMAC authenticator of the plaintext.
	auth := gmac(block, dk[:0], plaintext)

	// Append the operation data (i.e., the GMAC authenticator) to the transcript.
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(auth))*8))
	_, _ = p.transcript.Write(auth)

	// Ratchet the transcript.
	p.ratchet(buf[9:9], buf[:0])

	return ret
}

// Seal encrypts the given plaintext using the protocol's current state as the key, appending an authentication tag of
// TagLen bytes, then ratchets the protocol's state using the label and input. It appends the ciphertext and
// authentication tag to dst and returns the resulting slice.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	// Allocate a slice for the ciphertext split it between ciphertext and tag. Also allocate a slice for keys and
	// encoded lengths.
	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext)+TagLen)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]
	buf := make([]byte, 9+16+16)

	// Append the operation metadata to the transcript.
	p.combine(buf[:0], opAuthCrypt, []byte(label), tuplehash.LeftEncode(buf[9:9], uint64(len(plaintext))*8))

	// Expand a data key from the transcript.
	dk := p.expand(buf[9:9], buf[:0], "data key", 16)

	// Calculate a GMAC authenticator of the plaintext.
	block, _ := aes.NewCipher(dk)
	auth := gmac(block, dk[:0], plaintext)

	// Append the operation data (i.e., the GMAC authenticator) to the transcript.
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(auth))*8))
	_, _ = p.transcript.Write(auth)

	// Expand an authentication tag.
	tag = p.expand(tag[:0], buf[:0], "authentication tag", TagLen)

	// Encrypt the plaintext using AES-128-CTR with the tag as the IV.
	ctr(block, tag, ciphertext, plaintext)

	// Ratchet the transcript.
	p.ratchet(buf[9:9], buf[:0])

	return ret
}

// Open decrypts the given slice in place using the protocol's current state as the key, verifying the final TagLen
// bytes as an authentication tag. If the ciphertext is authentic, it appends the plaintext to dst and returns the
// resulting slice; otherwise, ErrInvalidCiphertext is returned.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
func (p *Protocol) Open(label string, dst, ciphertext []byte) ([]byte, error) {
	// Allocate a slice for the plaintext and split the ciphertext between ciphertext and tag. Also allocate a slice for
	// keys and encoded lengths.
	ciphertext, tag := ciphertext[:len(ciphertext)-TagLen], ciphertext[len(ciphertext)-TagLen:]
	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))
	buf := make([]byte, 9+16+16)

	// Append the operation metadata to the transcript.
	p.combine(buf[:0], opAuthCrypt, []byte(label), tuplehash.LeftEncode(buf[9:9], uint64(len(ciphertext))*8))

	// Expand a data key from the transcript.
	dk := p.expand(buf[9:9], buf[:0], "data key", 16)

	// Decrypt the plaintext using AES-128-CTR with the tag as the IV.
	block, _ := aes.NewCipher(dk)
	ctr(block, tag, plaintext, ciphertext)

	// Calculate a GMAC authenticator of the plaintext.
	auth := gmac(block, dk[:0], plaintext)

	// Append the operation data (i.e., the GMAC authenticator) to the transcript.
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(auth))*8))
	_, _ = p.transcript.Write(auth)

	// Expand a counterfactual authentication tag.
	tagP := p.expand(dk[:0], buf[:0], "authentication tag", TagLen)
	valid := subtle.ConstantTimeCompare(tag, tagP) == 0

	// Ratchet the transcript.
	p.ratchet(buf[9:9], buf[:0])

	// Compare the tag and the counterfactual tag in constant time.
	if valid {
		return nil, ErrInvalidCiphertext
	}
	return ret, nil
}

// AppendBinary appends the binary representation of itself to the end of b (allocating a larger slice if necessary) and
// returns the updated slice.
//
// Implementations must not retain b, nor mutate any bytes within b[:len(b)].
func (p *Protocol) AppendBinary(b []byte) ([]byte, error) {
	return p.transcript.AppendBinary(b)
}

// MarshalBinary encodes the receiver into a binary form and returns the result.
func (p *Protocol) MarshalBinary() (data []byte, err error) {
	return p.AppendBinary(make([]byte, 0, 256))
}

// UnmarshalBinary decodes the binary form into the receiver and returns an error, if any.
func (p *Protocol) UnmarshalBinary(data []byte) error {
	if err := p.transcript.UnmarshalBinary(data); err != nil {
		return ErrInvalidState
	}
	return nil
}

// Clone returns an exact clone of the receiver Protocol.
func (p *Protocol) Clone() Protocol {
	return *p
}

// ratchet replaces the protocol's transcript with a ratchet operation code and a ratchet key derived from the previous
// protocol transcript.
func (p *Protocol) ratchet(dst, buf []byte) {
	rak := p.expand(dst, buf, "ratchet key", 32)
	p.transcript.Reset()
	p.combine(buf, opRatchet, rak)
}

// combine appends an operation code and a sequence of bit string inputs to the protocol transcript using a recoverable
// encoding.
func (p *Protocol) combine(buf []byte, op byte, inputs ...[]byte) {
	_, _ = p.transcript.Write(append(buf, op))
	for _, input := range inputs {
		_, _ = p.transcript.Write(tuplehash.LeftEncode(buf, uint64(len(input))*8))
		_, _ = p.transcript.Write(input)
	}
}

// expand clones the protocol's transcript, appends an expand operation code, the label length, the label, and the
// requested output length, and fills the out slice with derived data.
func (p *Protocol) expand(dst, buf []byte, label string, n int) []byte {
	ret, out := mem.SliceForAppend(dst, n)
	h := p.transcript // make a copy
	_, _ = h.Write([]byte{opExpand})
	_, _ = h.Write(tuplehash.LeftEncode(buf, uint64(len(label))*8))
	_, _ = h.Write([]byte(label))
	_, _ = h.Write(tuplehash.RightEncode(buf, uint64(len(out))*8))
	_, _ = h.Read(out)
	return ret
}

// gmac calculates a GMAC authenticator using the keyed block cipher for the given message. The authenticator is
// appended to dst and returned.
func gmac(block cipher.Block, dst, message []byte) []byte {
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(dst, zeroBlock[:gcm.NonceSize()], nil, message)
}

// ctr XORs each byte in the given slice with a byte from the cipher's CTR mode key stream. Dst and src must overlap
// entirely or not at all.
func ctr(block cipher.Block, iv, dst, src []byte) {
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, src)
}

const (
	opMix       = 0x01
	opDerive    = 0x02
	opCrypt     = 0x03
	opAuthCrypt = 0x04
	opExpand    = 0x05
	opRatchet   = 0x06
)

//nolint:gochecknoglobals // this is fine
var zeroBlock = [aes.BlockSize]byte{}
