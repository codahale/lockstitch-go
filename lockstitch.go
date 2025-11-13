// Package lockstitch provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic
// operations (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex
// protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin transcripts, and Xoodyak's
// Cyclist mode, Lockstitch uses [KT128] and [AES-128] to provide 10+ Gb/sec performance on modern processors at a
// 128-bit security level.
//
// [KT128]: https://www.rfc-editor.org/rfc/rfc9861.html
// [AES-128]: https://doi.org/10.6028/NIST.FIPS.197-upd1
package lockstitch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/cloudflare/circl/xof/k12"
	"github.com/codahale/lockstitch-go/internal/mem"
	"github.com/codahale/lockstitch-go/internal/tuplehash"
)

// TagLen is the number of bytes added to the plaintext by the Seal operation.
const TagLen = aes.BlockSize

var (
	// ErrInvalidCiphertext is returned when the ciphertext is invalid or has been decrypted with the
	// wrong key.
	ErrInvalidCiphertext = errors.New("lockstitch: invalid ciphertext")
)

// A Protocol is a stateful object providing fine-grained symmetric-key cryptographic services like hashing, message
// authentication codes, pseudo-random functions, authenticated encryption, and more.
type Protocol struct {
	transcript k12.State
}

// NewProtocol creates a new Protocol with the given domain separation string.
func NewProtocol(domain string) Protocol {
	// Initialize a KT128 instance with a customization string of `lockstitch:{domain}`.
	return Protocol{
		transcript: k12.NewDraft10(append([]byte("lockstitch:"), []byte(domain)...)),
	}
}

// Mix ratchets the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	// Append the operation metadata and data to the transcript.
	buf := make([]byte, 9)
	_, _ = p.transcript.Write(append(buf[:0], opMix))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(label))*8))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(input))*8))
	_, _ = p.transcript.Write(input)
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

	// Append the operation metadata to the transcript.
	_, _ = p.transcript.Write(append(buf[:0], opDerive))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(label))*8))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(n)*8))

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
	_, _ = p.transcript.Write(append(buf[:0], opCrypt))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(label))*8))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(plaintext))*8))

	// Expand a data encryption key and an IV from the transcript.
	dk := p.expand(buf[9:9], buf[:0], "data encryption key", 32)

	// Append the operation data (i.e., the plaintext) to the transcript.
	_, _ = p.transcript.Write(plaintext)

	// Encrypt the plaintext using AES-128-CTR.
	aes128CTR(dk[:16], dk[16:], ciphertext, plaintext)

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
	_, _ = p.transcript.Write(append(buf[:0], opCrypt))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(label))*8))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(plaintext))*8))

	// Expand a data encryption key and an IV from the transcript.
	dk := p.expand(buf[9:9], buf[:0], "data encryption key", 32)

	// Decrypt the ciphertext using AES-128-CTR.
	aes128CTR(dk[:16], dk[16:], plaintext, ciphertext)

	// Append the operation data (i.e., the plaintext) to the transcript.
	_, _ = p.transcript.Write(plaintext)

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
	_, _ = p.transcript.Write(append(buf[:0], opAuthCrypt))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(label))*8))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(plaintext))*8))

	// Expand a data encryption key from the transcript.
	dk := p.expand(buf[9:9], buf[:0], "data encryption key", 16)

	// Append the operation data (i.e., the plaintext) to the transcript.
	_, _ = p.transcript.Write(plaintext)

	// Expand an authentication tag.
	tag = p.expand(tag[:0], buf[:0], "authentication tag", TagLen)

	// Encrypt the plaintext using AES-128-CTR with the tag as the IV.
	aes128CTR(dk, tag, ciphertext, plaintext)

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
	_, _ = p.transcript.Write(append(buf[:0], opAuthCrypt))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(label))*8))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(plaintext))*8))

	// Expand a data encryption key from the transcript.
	dk := p.expand(buf[9:9], buf[:0], "data encryption key", 16)

	// Encrypt the plaintext using AES-128-CTR with the tag as the IV.
	aes128CTR(dk, tag, plaintext, ciphertext)

	// Append the operation data (i.e., the plaintext) to the transcript.
	_, _ = p.transcript.Write(plaintext)

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

// Clone returns an exact clone of the receiver Protocol.
func (p *Protocol) Clone() Protocol {
	return Protocol{transcript: p.transcript.Clone()}
}

// ratchet replaces the protocol's transcript with a ratchet operation code and a ratchet key derived from the previous
// protocol transcript.
func (p *Protocol) ratchet(dst, buf []byte) {
	// Expand a ratchet key.
	rak := p.expand(dst, buf, "ratchet key", 32)

	// Clear the transcript.
	p.transcript.Reset()

	// Append the operation data to the transcript.
	_, _ = p.transcript.Write(append(buf[:0], opRatchet))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(buf[:0], uint64(len(rak))*8))
	_, _ = p.transcript.Write(rak)
}

// expand clones the protocol's transcript, appends an expand operation code, the label length, the label, and the
// requested output length, and fills the out slice with derived data.
func (p *Protocol) expand(dst, buf []byte, label string, n int) []byte {
	ret, out := mem.SliceForAppend(dst, n)
	h := p.transcript.Clone()
	_, _ = h.Write([]byte{opExpand})
	_, _ = h.Write(tuplehash.LeftEncode(buf, uint64(len(label))*8))
	_, _ = h.Write([]byte(label))
	_, _ = h.Write(tuplehash.RightEncode(buf, uint64(len(out))*8))
	_, _ = h.Read(out)
	return ret
}

func aes128CTR(key, iv, dst, src []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(dst, src)
}

const (
	opMix       = 0x01
	opDerive    = 0x02
	opCrypt     = 0x03
	opAuthCrypt = 0x04
	opExpand    = 0x05
	opRatchet   = 0x06
)
