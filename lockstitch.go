// Package lockstitch provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic
// operations (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex
// protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin transcripts, and Xoodyak's
// Cyclist mode, Lockstitch uses cSHAKE128 (https://csrc.nist.gov/pubs/sp/800/185/final), POLYVAL (RFC 8452), and
// AES-128 (https://doi.org/10.6028/NIST.FIPS.197-upd1) to provide 10+ Gb/sec performance on modern processors at a
// 128-bit security level.
package lockstitch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/ericlagergren/polyval"
)

// TagLen is the number of bytes added to the plaintext by the Seal operation.
const TagLen = aes.BlockSize

var (
	// ErrInvalidCiphertext is returned when the ciphertext is invalid or has been decrypted with the
	// wrong key.
	ErrInvalidCiphertext = errors.New("lockstitch: invalid ciphertext")

	// ErrInvalidState is returned when a protocol's state cannot be unmarshalled, either due to malformed
	// data or an incorrect protocol domain.
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

	// Expand n bytes of PRF output from the transcript.
	prf := p.expand(dst, "prf output", n)

	// Ratchet the transcript.
	p.ratchet()

	return prf
}

// Encrypt encrypts the plaintext using the protocol's current state as the key, then ratchets the protocol's state
// using the label and input. It appends the ciphertext to dst and returns the resulting slice.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Encrypt(label string, dst, plaintext []byte) []byte {
	// Append the operation metadata to the transcript.
	p.combine(opCrypt, []byte(label), leftEncode(uint64(len(plaintext))*8))

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand(nil, "data encryption key", 16)
	dak := p.expand(nil, "data authentication key", 16)

	// Calculate a POLYVAL authenticator of the plaintext.
	auth := polyvalAuth(dak[:0], dak, plaintext)

	// Append the operation data (i.e., the POLYVAL authenticator) to the transcript.
	_, _ = p.transcript.Write(leftEncode(uint64(len(auth)) * 8))
	_, _ = p.transcript.Write(auth)

	// Ratchet the transcript.
	p.ratchet()

	// Encrypt the plaintext using AES-128-CTR with an all-zero IV.
	ret, ciphertext := sliceForAppend(dst, len(plaintext))
	block, _ := aes.NewCipher(dek)
	ctr := cipher.NewCTR(block, make([]byte, aes.BlockSize))
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

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand(nil, "data encryption key", 16)
	dak := p.expand(nil, "data authentication key", 16)

	// Decrypt the ciphertext using AES-128-CTR with an all-zero IV.
	ret, plaintext := sliceForAppend(dst, len(ciphertext))
	block, _ := aes.NewCipher(dek)
	ctr := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	ctr.XORKeyStream(plaintext, ciphertext)

	// Calculate a POLYVAL authenticator of the plaintext.
	auth := polyvalAuth(dak[:0], dak, plaintext)

	// Append the operation data (i.e., the POLYVAL authenticator) to the transcript.
	_, _ = p.transcript.Write(leftEncode(uint64(len(auth)) * 8))
	_, _ = p.transcript.Write(auth)

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
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+TagLen)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]

	// Append the operation metadata to the transcript.
	p.combine(opAuthCrypt, []byte(label), leftEncode(uint64(len(plaintext))*8))

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand(nil, "data encryption key", 16)
	dak := p.expand(nil, "data authentication key", 16)

	// Calculate a POLYVAL authenticator of the plaintext.
	auth := polyvalAuth(dak[:0], dak, plaintext)

	// Append the operation data (i.e., the POLYVAL authenticator) to the transcript.
	_, _ = p.transcript.Write(leftEncode(uint64(len(auth)) * 8))
	_, _ = p.transcript.Write(auth)

	// Expand an authentication tag.
	tag = p.expand(tag[:0], "authentication tag", TagLen)

	// Encrypt the plaintext using AES-128-CTR with the tag as the IV.
	block, _ := aes.NewCipher(dek)
	ctr := cipher.NewCTR(block, tag)
	ctr.XORKeyStream(ciphertext, plaintext)

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
	ciphertext, tag := ciphertext[:len(ciphertext)-TagLen], ciphertext[len(ciphertext)-TagLen:]
	ret, plaintext := sliceForAppend(dst, len(ciphertext))

	// Append the operation metadata to the transcript.
	p.combine(opAuthCrypt, []byte(label), leftEncode(uint64(len(ciphertext))*8))

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand(nil, "data encryption key", 16)
	dak := p.expand(nil, "data authentication key", 16)

	// Decrypt the plaintext using AES-128-CTR with the tag as the IV.
	block, _ := aes.NewCipher(dek)
	ctr := cipher.NewCTR(block, tag)
	ctr.XORKeyStream(plaintext, ciphertext)

	// Calculate a POLYVAL authenticator of the unauthenticated plaintext.
	auth := polyvalAuth(dak[:0], dak, plaintext)

	// Append the operation data (i.e., the POLYVAL authenticator) to the transcript.
	_, _ = p.transcript.Write(leftEncode(uint64(len(auth)) * 8))
	_, _ = p.transcript.Write(auth)

	// Expand a counterfactual authentication tag.
	tagP := p.expand(dak[:0], "authentication tag", TagLen)

	// Ratchet the transcript.
	p.ratchet()

	// Compare the tag and the counterfactual tag in constant time.
	if subtle.ConstantTimeCompare(tag, tagP) == 0 {
		return nil, ErrInvalidCiphertext
	}

	return ret, nil
}

func (p *Protocol) AppendBinary(b []byte) ([]byte, error) {
	return p.transcript.AppendBinary(b)
}

func (p *Protocol) MarshalBinary() (data []byte, err error) {
	return p.AppendBinary(make([]byte, 0, 256))
}

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
func (p *Protocol) ratchet() {
	rak := p.expand(nil, "ratchet key", 32)
	p.transcript.Reset()
	p.combine(opRatchet, rak)
}

// combine appends an operation code and a sequence of bit string inputs to the protocol transcript using a recoverable
// encoding.
func (p *Protocol) combine(op byte, inputs ...[]byte) {
	_, _ = p.transcript.Write([]byte{op})
	for _, input := range inputs {
		_, _ = p.transcript.Write(leftEncode(uint64(len(input)) * 8))
		_, _ = p.transcript.Write(input)
	}
}

// expand clones the protocol's transcript, appends an expand operation code, the label length, the label, and the
// requested output length, and fills the out slice with derived data.
func (p *Protocol) expand(dst []byte, label string, n int) []byte {
	ret, out := sliceForAppend(dst, n)
	h := p.transcript // make a copy
	_, _ = h.Write([]byte{opExpand})
	_, _ = h.Write(leftEncode(uint64(len(label)) * 8))
	_, _ = h.Write([]byte(label))
	_, _ = h.Write(rightEncode(uint64(len(out)) * 8))
	_, _ = h.Read(out)
	return ret
}

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

// polyvalAuth pads the given message using the same scheme as AES-GCM-SIV and calculates a POLYVAL authenticator of it.
func polyvalAuth(dst, key, message []byte) []byte {
	n := len(message)
	block := make([]byte, 16)

	p, _ := polyval.New(key)

	// Hash all full blocks.
	if len(message) >= 16 {
		m := len(message) &^ (16 - 1)
		p.Update(message[:m])
		message = message[m:]
	}

	// Pad final message block with zeros.
	if len(message) > 0 {
		copy(block, message)
		p.Update(block)
	}

	// Hash a final block with the message length. The first eight bytes are zero because, unlike AES-GCM-SIV, there is
	// no authenticated data.
	binary.LittleEndian.PutUint64(block[:8], 0)
	binary.LittleEndian.PutUint64(block[8:], uint64(n)*8)
	p.Update(block)

	return p.Sum(dst[:0])
}
