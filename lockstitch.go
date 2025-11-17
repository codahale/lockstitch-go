// Package lockstitch provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic
// operations (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex
// protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin transcripts, and Xoodyak's
// Cyclist mode, Lockstitch uses [KT128], [POLYVAL], and [AES-128] to provide 10+ Gb/sec performance on modern
// processors at a 128-bit security level.
//
// [KT128]: https://www.rfc-editor.org/rfc/rfc9861.html
// [POLYVAL]: https://www.rfc-editor.org/rfc/rfc8452.html
// [AES-128]: https://doi.org/10.6028/NIST.FIPS.197-upd1
package lockstitch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	kt128 "github.com/cloudflare/circl/xof/k12"
	"github.com/codahale/lockstitch-go/internal/polyval"
	"github.com/codahale/lockstitch-go/internal/tuplehash"
	mem "github.com/ericlagergren/subtle"
)

// TagLen is the number of bytes added to the plaintext by the Seal operation.
const TagLen = 16

var (
	// ErrInvalidCiphertext is returned when the ciphertext is invalid or has been decrypted with the
	// wrong key.
	ErrInvalidCiphertext = errors.New("lockstitch: invalid ciphertext")
)

// A Protocol is a stateful object providing fine-grained symmetric-key cryptographic services like hashing, message
// authentication codes, pseudo-random functions, authenticated encryption, and more.
type Protocol struct {
	transcript kt128.State
}

// NewProtocol creates a new Protocol with the given domain separation string.
func NewProtocol(domain string) Protocol {
	// Initialize a KT128 instance with a customization string of `lockstitch:{domain}`.
	return Protocol{
		transcript: kt128.NewDraft10(append([]byte("lockstitch:"), []byte(domain)...)),
	}
}

// Mix ratchets the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	// Append the operation metadata and data to the transcript.
	_, _ = p.transcript.Write([]byte{opMix})
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(input)) * bitsPerByte))
	_, _ = p.transcript.Write(input)
}

// Derive generates pseudorandom output from the Protocol's current state, the label, and the output length, then
// ratchets the Protocol's state with the label and output length. It appends the output to dst and returns the
// resulting slice.
func (p *Protocol) Derive(label string, dst []byte, n int) []byte {
	if n < 0 {
		panic("invalid argument to Derive: n cannot be negative")
	}

	// Append the operation metadata to the transcript.
	_, _ = p.transcript.Write([]byte{opDerive})
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(n) * bitsPerByte))

	// Expand n bytes of PRF output from the transcript.
	ret, prf := mem.SliceForAppend(dst, n)
	p.expand("prf output", prf)

	// Ratchet the transcript.
	p.ratchet()

	return ret
}

// Encrypt encrypts the plaintext using the protocol's current state as the key, then ratchets the protocol's state
// using the label and input. It appends the ciphertext to dst and returns the resulting slice.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Encrypt(label string, dst, plaintext []byte) []byte {
	// Allocate slices for the ciphertext and the keys.
	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext))
	dek := make([]byte, aes128KeyLen+aes.BlockSize)
	dak := make([]byte, polyval.KeyLen)

	// Append the operation metadata to the transcript.
	_, _ = p.transcript.Write([]byte{opCrypt})
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(plaintext)) * bitsPerByte))

	// Expand a data encryption key, an IV, and a data authentication key from the transcript.
	p.expand("data encryption key", dek)
	p.expand("data authentication key", dak)

	// Calculate a POLYVAL authentication of the plaintext.
	auth := polyval.Authenticator(dak, plaintext)

	// Append the authenticator to the transcript.
	_, _ = p.transcript.Write(auth[:])

	// Encrypt the plaintext using AES-128-CTR.
	aes128CTR(dek[:aes128KeyLen], dek[aes128KeyLen:], ciphertext, plaintext)

	// Ratchet the transcript.
	p.ratchet()

	return ret
}

// Decrypt decrypts the given ciphertext using the protocol's current state as the key, then ratchets the protocol's
// state using the label and input. It appends the plaintext to dst and returns the resulting slice. To reuse
// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity of dst
// must not overlap ciphertext.
func (p *Protocol) Decrypt(label string, dst, ciphertext []byte) []byte {
	// Allocate slice for the plaintext and keys.
	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))
	dek := make([]byte, aes128KeyLen+aes.BlockSize)
	dak := make([]byte, polyval.KeyLen)

	// Append the operation metadata to the transcript.
	_, _ = p.transcript.Write([]byte{opCrypt})
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(plaintext)) * bitsPerByte))

	// Expand a data encryption key, an IV, and a data authentication key from the transcript.
	p.expand("data encryption key", dek)
	p.expand("data authentication key", dak)

	// Decrypt the ciphertext using AES-128-CTR.
	aes128CTR(dek[:aes128KeyLen], dek[aes128KeyLen:], plaintext, ciphertext)

	// Calculate a POLYVAL authentication of the plaintext.
	auth := polyval.Authenticator(dak, plaintext)

	// Append the authenticator to the transcript.
	_, _ = p.transcript.Write(auth[:])

	// Ratchet the transcript.
	p.ratchet()

	return ret
}

// Seal encrypts the given plaintext using the protocol's current state as the key, appending an authentication tag of
// TagLen bytes, then ratchets the protocol's state using the label and input. It appends the ciphertext and
// authentication tag to dst and returns the resulting slice.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	// Allocate a slice for the ciphertext and split it between ciphertext and tag. Also allocate slices for keys.
	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext)+TagLen)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]
	dek := make([]byte, aes128KeyLen)
	dak := make([]byte, polyval.KeyLen)

	// Append the operation metadata to the transcript.
	_, _ = p.transcript.Write([]byte{opAuthCrypt})
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(plaintext)) * bitsPerByte))

	// Expand a data encryption key and a data authentication key from the transcript.
	p.expand("data encryption key", dek)
	p.expand("data authentication key", dak)

	// Calculate a POLYVAL authentication of the plaintext.
	auth := polyval.Authenticator(dak, plaintext)

	// Append the authenticator to the transcript.
	_, _ = p.transcript.Write(auth[:])

	// Expand an authentication tag.
	p.expand("authentication tag", tag)

	// Encrypt the plaintext using AES-128-CTR with the tag as the IV.
	aes128CTR(dek, tag, ciphertext, plaintext)

	// Ratchet the transcript.
	p.ratchet()

	return ret
}

// Open decrypts the given slice in place using the protocol's current state as the key, verifying the final TagLen
// bytes as an authentication tag. If the ciphertext is authentic, it appends the plaintext to dst and returns the
// resulting slice; otherwise, ErrInvalidCiphertext is returned.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
func (p *Protocol) Open(label string, dst, ciphertext []byte) ([]byte, error) {
	// Split the ciphertext between ciphertext and tag. Allocate slices for plaintext, keys, and tag.
	ciphertext, tag := ciphertext[:len(ciphertext)-TagLen], ciphertext[len(ciphertext)-TagLen:]
	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))
	dek := make([]byte, aes128KeyLen)
	dak := make([]byte, polyval.KeyLen)
	tagP := make([]byte, TagLen)

	// Append the operation metadata to the transcript.
	_, _ = p.transcript.Write([]byte{opAuthCrypt})
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	_, _ = p.transcript.Write([]byte(label))
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(plaintext)) * bitsPerByte))

	// Expand a data encryption key and a data authentication key from the transcript.
	p.expand("data encryption key", dek)
	p.expand("data authentication key", dak)

	// Decrypt the ciphertext using AES-128-CTR with the tag as the IV.
	aes128CTR(dek, tag, plaintext, ciphertext)

	// Calculate a POLYVAL authentication of the plaintext.
	auth := polyval.Authenticator(dak, plaintext)

	// Append the authenticator to the transcript.
	_, _ = p.transcript.Write(auth[:])

	// Expand a counterfactual authentication tag.
	p.expand("authentication tag", tagP)

	// Ratchet the transcript.
	p.ratchet()

	// Compare the tag and the counterfactual tag in constant time.
	if subtle.ConstantTimeCompare(tag, tagP) == 0 {
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
func (p *Protocol) ratchet() {
	// Expand a ratchet key.
	rak := make([]byte, ratchetKeyLen)
	p.expand("ratchet key", rak)

	// Clear the transcript.
	p.transcript.Reset()

	// Append the operation data to the transcript.
	_, _ = p.transcript.Write([]byte{opRatchet})
	_, _ = p.transcript.Write(tuplehash.LeftEncode(uint64(len(rak)) * bitsPerByte))
	_, _ = p.transcript.Write(rak)
}

// expand clones the protocol's transcript, appends an expand operation code, the label length, the label, and the
// requested output length, and fills the out slice with derived data.
func (p *Protocol) expand(label string, out []byte) {
	h := p.transcript.Clone()
	_, _ = h.Write([]byte{opExpand})
	_, _ = h.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	_, _ = h.Write([]byte(label))
	_, _ = h.Write(tuplehash.RightEncode(uint64(len(out)) * bitsPerByte))
	_, _ = h.Read(out)
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

	ratchetKeyLen = 32
	aes128KeyLen  = 16
	bitsPerByte   = 8
)
