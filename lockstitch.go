// Package lockstitch provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic
// operations (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex
// protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin transcripts, and Xoodyak's
// Cyclist mode, Lockstitch uses cSHAKE128 (https://csrc.nist.gov/pubs/sp/800/185/final), Poly1305 (RFC 8439), and
// AES-128 (https://doi.org/10.6028/NIST.FIPS.197-upd1) to provide 10+ Gb/sec performance on modern processors at a
// 128-bit security level.
package lockstitch

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"

	"golang.org/x/crypto/poly1305" //nolint:staticcheck // we're not using Poly1305 incorrectly, ignore deprecation warning
)

// TagLen is the number of bytes added to the plaintext by the Seal operation.
const TagLen = aes.BlockSize

// ErrInvalidCiphertext is returned when the ciphertext is invalid or has been decrypted with the
// wrong key.
var ErrInvalidCiphertext = errors.New("lockstitch: invalid ciphertext")

// A Protocol is a stateful object providing fine-grained symmetric-key cryptographic services like hashing, message
// authentication codes, pseudo-random functions, authenticated encryption, and more.
type Protocol struct {
	transcript *sha3.SHAKE
	s          []byte
}

// NewProtocol creates a new Protocol with the given domain separation string.
func NewProtocol(domain string) Protocol {
	// Initialize a cSHAKE128 instance with a customization string of `lockstitch:{domain}`.
	s := append([]byte("lockstitch:"), []byte(domain)...)
	return Protocol{
		transcript: sha3.NewCSHAKE128(nil, s),
		s:          s,
	}
}

// Mix ratchets the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	// Append the operation metadata and input to the transcript in a recoverable encoding.
	p.combine(opMix, []byte(label), input)
}

// Derive generates pseudorandom output from the Protocol's current state, the label, and the output length, then
// ratchets the Protocol's state with the label and output length. It appends the output to dst and returns the
// resulting slice.
func (p *Protocol) Derive(label string, dst []byte, n int) []byte {
	if n < 0 {
		panic("invalid argument to Derive: n cannot be negative")
	}

	// Append the operation metadata to the transcript in a recoverable encoding.
	p.combine(opDerive, []byte(label), leftEncode(uint64(n)*8))

	// Expand a ratchet key and n bytes of PRF output from the transcript.
	rak := make([]byte, 32)
	p.expand(rak, "ratchet key")
	ret, prf := sliceForAppend(dst, n)
	p.expand(prf, "prf output")

	// Ratchet the transcript with the ratchet key.
	p.ratchet(rak)

	return ret
}

// Encrypt encrypts the plaintext using the protocol's current state as the key, then ratchets the protocol's state
// using the label and input. It appends the ciphertext to dst and returns the resulting slice.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Encrypt(label string, dst, plaintext []byte) []byte {
	// Append the operation metadata to the transcript.
	p.combine(opCrypt, []byte(label), leftEncode(uint64(len(plaintext))*8))

	// Expand a ratchet key, a data encryption key, and a data authentication key from the transcript.
	var (
		rak [32]byte
		dek [16]byte
		dak [32]byte
	)
	p.expand(rak[:], "ratchet key")
	p.expand(dek[:], "data encryption key")
	p.expand(dak[:], "data authentication key")

	// Calculate a Poly1305 authenticator of the plaintext.
	m := poly1305.New(&dak)
	_, _ = m.Write(plaintext)
	auth := m.Sum(dak[:0])

	// Ratchet the transcript with the ratchet key and the authenticator.
	p.ratchet(append(rak[:], auth...))

	// Encrypt the plaintext using AES-128-CTR with an all-zero IV.
	ret, ciphertext := sliceForAppend(dst, len(plaintext))
	block, _ := aes.NewCipher(dek[:])
	ctr := cipher.NewCTR(block, zeroIV[:])
	ctr.XORKeyStream(ciphertext, plaintext)

	return ret
}

// Decrypt decrypts the given ciphertext using the protocol's current state as the key, then ratchets the protocol's
// state using the label and input. It appends the plaintext to dst and returns the resulting slice. To reuse
// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity of dst
// must not overlap ciphertext.
func (p *Protocol) Decrypt(label string, dst, ciphertext []byte) []byte {
	// Append the operation metadata to the transcript.
	p.combine(opCrypt, []byte(label), leftEncode(uint64(len(ciphertext))*8))

	// Expand a ratchet key, a data encryption key, and a data authentication key from the transcript.
	var (
		rak [32]byte
		dek [16]byte
		dak [32]byte
	)
	p.expand(rak[:], "ratchet key")
	p.expand(dek[:], "data encryption key")
	p.expand(dak[:], "data authentication key")

	// Decrypt the ciphertext using AES-128-CTR with an all-zero IV.
	ret, plaintext := sliceForAppend(dst, len(ciphertext))
	block, _ := aes.NewCipher(dek[:])
	ctr := cipher.NewCTR(block, zeroIV[:])
	ctr.XORKeyStream(plaintext, ciphertext)

	// Calculate a Poly1305 authenticator of the plaintext.
	m := poly1305.New(&dak)
	_, _ = m.Write(plaintext)
	auth := m.Sum(dak[:0])

	// Ratchet the transcript with the ratchet key and the authenticator.
	p.ratchet(append(rak[:], auth...))

	return ret
}

// Seal encrypts the given plaintext using the protocol's current state as the key, appending an authentication tag of
// TagLen bytes, then ratchets the protocol's state using the label and input. It appends the ciphertext and
// authentication tag to dst and returns the resulting slice.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+TagLen)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]

	// Append the operation metadata to the transcript.
	p.combine(opAuthCrypt, []byte(label), leftEncode(uint64(len(plaintext))*8))

	// Expand a ratchet key, a data encryption key, and a data authentication key from the transcript.
	var (
		rak [32]byte
		dek [16]byte
		dak [32]byte
	)
	p.expand(rak[:], "ratchet key")
	p.expand(dek[:], "data encryption key")
	p.expand(dak[:], "data authentication key")

	// Calculate a Poly1305 authenticator of the plaintext.
	m := poly1305.New(&dak)
	_, _ = m.Write(plaintext)
	auth := m.Sum(dak[:0])

	// Ratchet the transcript with the ratchet key and the authenticator.
	p.ratchet(append(rak[:], auth...))

	// Expand a ratchet key and an authentication tag.
	p.expand(rak[:], "ratchet key")
	p.expand(tag, "authentication tag")

	// Encrypt the plaintext using AES-128-CTR with the tag as the IV.
	block, _ := aes.NewCipher(dek[:])
	ctr := cipher.NewCTR(block, tag)
	ctr.XORKeyStream(ciphertext, plaintext)

	// Ratchet the transcript with the ratchet key.
	p.ratchet(rak[:])

	return ret
}

// Open decrypts the given slice in place using the protocol's current state as the key, verifying the final TagLen
// bytes as an authentication tag. If the ciphertext is authentic, it appends the plaintext to dst and returns the
// resulting slice; otherwise, ErrInvalidCiphertext is returned.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
func (p *Protocol) Open(label string, dst, ciphertext []byte) ([]byte, error) {
	ciphertext, tag := ciphertext[:len(ciphertext)-TagLen], ciphertext[len(ciphertext)-TagLen:]
	ret, plaintext := sliceForAppend(dst, len(ciphertext))

	// Append the operation metadata to the transcript.
	p.combine(opAuthCrypt, []byte(label), leftEncode(uint64(len(ciphertext))*8))

	// Expand a ratchet key, a data encryption key, and a data authentication key from the transcript.
	var (
		rak [32]byte
		dek [16]byte
		dak [32]byte
	)
	p.expand(rak[:], "ratchet key")
	p.expand(dek[:], "data encryption key")
	p.expand(dak[:], "data authentication key")

	// Decrypt the plaintext using AES-128-CTR and using the tag as the IV.
	block, _ := aes.NewCipher(dek[:])
	ctr := cipher.NewCTR(block, tag)
	ctr.XORKeyStream(plaintext, ciphertext)

	// Calculate a Poly1305 authenticator of the plaintext.
	m := poly1305.New(&dak)
	_, _ = m.Write(plaintext)
	auth := m.Sum(dak[:0])

	// Ratchet the transcript with the ratchet key and the authenticator.
	p.ratchet(append(rak[:], auth...))

	// Expand a ratchet key and a counterfactual authentication tag.
	var tagP [16]byte
	p.expand(rak[:], "ratchet key")
	p.expand(tagP[:], "authentication tag")

	// Compare the tag and the counterfactual tag in constant time.
	if subtle.ConstantTimeCompare(tag, tagP[:]) == 0 {
		return nil, ErrInvalidCiphertext
	}

	// Ratchet the transcript with the ratchet key.
	p.ratchet(rak[:])

	return ret, nil
}

func (p *Protocol) AppendBinary(b []byte) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, uint16(len(p.s)))
	b = append(b, p.s...)
	return p.transcript.AppendBinary(b)
}

func (p *Protocol) MarshalBinary() (data []byte, err error) {
	return p.AppendBinary(make([]byte, 0, 256))
}

func (p *Protocol) UnmarshalBinary(data []byte) error {
	sLen := binary.BigEndian.Uint16(data)
	S := bytes.Clone(data[2 : 2+int(sLen)])
	p.transcript = sha3.NewCSHAKE128(nil, S)
	if err := p.transcript.UnmarshalBinary(data[2+int(sLen):]); err != nil {
		return err
	}
	return nil
}

// Clone returns an exact clone of the receiver Protocol.
func (p *Protocol) Clone() Protocol {
	state, err := p.MarshalBinary()
	if err != nil {
		panic(err)
	}

	var clone Protocol
	if err := clone.UnmarshalBinary(state); err != nil {
		panic(err)
	}
	return clone
}

func (p *Protocol) ratchet(rak []byte) {
	p.transcript.Reset()
	p.combine(opRatchet, rak)
}

// Combine appends an operation code and a sequence of bit string inputs to the protocol transcript using a recoverable
// encoding.
func (p *Protocol) combine(op byte, inputs ...[]byte) {
	_, _ = p.transcript.Write([]byte{op})
	for _, input := range inputs {
		_, _ = p.transcript.Write(leftEncode(uint64(len(input)) * 8))
		_, _ = p.transcript.Write(input)
	}
}

// expand clones the protocol's transcript, appends an
func (p *Protocol) expand(out []byte, label string) {
	h := *p.transcript // make a copy
	_, _ = p.transcript.Write([]byte{opExpand})
	_, _ = h.Write(leftEncode(uint64(len(label)) * 8))
	_, _ = h.Write([]byte(label))
	_, _ = h.Write(rightEncode(uint64(len(out)) * 8))
	_, _ = h.Read(out)
}

var zeroIV [aes.BlockSize]byte

const (
	opMix       = 0x01
	opDerive    = 0x02
	opCrypt     = 0x03
	opAuthCrypt = 0x04
	opExpand    = 0x05
	opRatchet   = 0x06
)

// leftEncode encodes an integer value using NIST SP 800-185's left_encode.
//
// https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
func leftEncode(value uint64) []byte {
	var buf [9]byte
	binary.BigEndian.PutUint64(buf[1:], value)
	n := max(len(buf)-1-(bits.LeadingZeros64(value)/8), 1)
	buf[len(buf)-n-1] = byte(n)
	return buf[len(buf)-n-1:]
}

// rightEncode encodes an integer value using NIST SP 800-185's right_encode.
//
// https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
func rightEncode(value uint64) []byte {
	var buf [9]byte
	binary.BigEndian.PutUint64(buf[:8], value)
	n := max(len(buf)-1-(bits.LeadingZeros64(value)/8), 1)
	buf[len(buf)-1] = byte(n)
	return buf[len(buf)-n-1:]
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a slice with the contents of the given slice
// followed by that many bytes and a second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity, then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
