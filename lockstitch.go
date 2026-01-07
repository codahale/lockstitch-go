// Package lockstitch provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic
// operations (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex
// protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin transcripts, and Xoodyak's
// Cyclist mode, Lockstitch uses [SHA-256], [AES-128], and [GMAC] to provide 10+ Gb/sec performance on modern
// processors at a 128-bit security level.
//
// [SHA-256]: https://doi.org/10.6028/NIST.FIPS.180-4
// [AES-128]: https://doi.org/10.6028/NIST.FIPS.197-upd1
// [GMAC]: https://doi.org/10.6028/NIST.SP.800-38D
package lockstitch

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"errors"
	"hash"

	"github.com/codahale/lockstitch-go/internal/aes"
	"github.com/codahale/lockstitch-go/internal/tuplehash"
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
	transcript hash.Hash
}

// NewProtocol creates a new Protocol with the given domain separation string.
func NewProtocol(domain string) Protocol {
	// Initialize an empty transcript.
	transcript := sha256.New()

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(domain))
	metadata[0] = opInit
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(domain))*bitsPerByte)
	metadata = append(metadata, domain...)
	transcript.Write(metadata)

	return Protocol{transcript}
}

// Mix ratchets the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	// Append the operation metadata and data to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opMix
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(input))*bitsPerByte)
	p.transcript.Write(metadata)
	p.transcript.Write(input)
}

// Derive generates pseudorandom output from the Protocol's current state, the label, and the output length, then
// ratchets the Protocol's state with the label and output length. It appends the output to dst and returns the
// resulting slice.
func (p *Protocol) Derive(label string, dst []byte, n int) []byte {
	if n < 0 {
		panic("invalid argument to Derive: n cannot be negative")
	} else if uint64(n) > 64*1024*1024*1024 {
		panic("invalid argument to Derive: n must be <= 64GiB")
	}

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opDerive
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(n)*bitsPerByte)
	p.transcript.Write(metadata)

	// Expand a PRF key.
	prfKey := p.expand("prf key")

	// Expand n bytes of AES-128-CTR keystream for PRF output.
	ret, prf := sliceForAppend(dst, n)
	for i := range prf {
		prf[i] = 0 // There's no way to get just the keystream from stdlib's CTR mode, so we ensure the input is zeroed.
	}
	aes.CTR(prfKey, make([]byte, aes.BlockSize), prf, prf)

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
	// Allocate a slice for the ciphertext.
	ret, ciphertext := sliceForAppend(dst, len(plaintext))

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(plaintext))*bitsPerByte)
	p.transcript.Write(metadata)

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand("data encryption key")
	dak := p.expand("data authentication key")

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes.GMAC(dak, make([]byte, gcmNonceLen), dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Encrypt the plaintext using AES-128-CTR.
	aes.CTR(dek, make([]byte, aes.BlockSize), ciphertext, plaintext)

	// Ratchet the transcript.
	p.ratchet()

	return ret
}

// Decrypt decrypts the given ciphertext using the protocol's current state as the key, then ratchets the protocol's
// state using the label and input. It appends the plaintext to dst and returns the resulting slice. To reuse
// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity of dst
// must not overlap ciphertext.
func (p *Protocol) Decrypt(label string, dst, ciphertext []byte) []byte {
	// Allocate a slice for the plaintext.
	ret, plaintext := sliceForAppend(dst, len(ciphertext))

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(plaintext))*bitsPerByte)
	p.transcript.Write(metadata)

	// Expand a data encryption key, an IV, and a data authentication key from the transcript.
	dek := p.expand("data encryption key")
	dak := p.expand("data authentication key")

	// Decrypt the ciphertext using AES-128-CTR.
	aes.CTR(dek, make([]byte, aes.BlockSize), plaintext, ciphertext)

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes.GMAC(dak, make([]byte, gcmNonceLen), dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

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
	// Allocate a slice for the ciphertext and split it between ciphertext and tag.
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+TagLen)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opAuthCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(plaintext))*bitsPerByte)
	p.transcript.Write(metadata)

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand("data encryption key")
	dak := p.expand("data authentication key")

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes.GMAC(dak, make([]byte, gcmNonceLen), dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Expand an authentication tag.
	copy(tag, p.expand("authentication tag"))

	// Encrypt the plaintext using AES-128-CTR with the tag as the IV.
	aes.CTR(dek, tag, ciphertext, plaintext)

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
	// Split the ciphertext between ciphertext and tag. Allocate slice for plaintext.
	ciphertext, tag := ciphertext[:len(ciphertext)-TagLen], ciphertext[len(ciphertext)-TagLen:]
	ret, plaintext := sliceForAppend(dst, len(ciphertext))

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opAuthCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(plaintext))*bitsPerByte)
	p.transcript.Write(metadata)

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand("data encryption key")
	dak := p.expand("data authentication key")

	// Decrypt the ciphertext using AES-128-CTR with the tag as the IV.
	aes.CTR(dek, tag, plaintext, ciphertext)

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes.GMAC(dak, make([]byte, gcmNonceLen), dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Expand a counterfactual authentication tag.
	tagP := p.expand("authentication tag")

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
	transcript, err := p.transcript.(hash.Cloner).Clone() //nolint:errcheck // cannot panic
	if err != nil {
		panic(err)
	}

	return Protocol{transcript}
}

func (p *Protocol) AppendBinary(b []byte) ([]byte, error) {
	return p.transcript.(encoding.BinaryAppender).AppendBinary(b) //nolint:errcheck // cannot panic
}

func (p *Protocol) UnmarshalBinary(data []byte) error {
	return p.transcript.(encoding.BinaryUnmarshaler).UnmarshalBinary(data) //nolint:errcheck // cannot panic
}

func (p *Protocol) MarshalBinary() (data []byte, err error) {
	return p.transcript.(encoding.BinaryMarshaler).MarshalBinary() //nolint:errcheck // cannot panic
}

// ratchet replaces the protocol's transcript with a ratchet operation code and a ratchet key derived from the previous
// protocol transcript.
func (p *Protocol) ratchet() {
	// Expand a ratchet key in place, since the transcript is immediately reset following this.
	rak := expand(p.transcript, "ratchet key")

	// Clear the transcript.
	p.transcript.Reset()

	// Append the operation metadata and data to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen)
	metadata[0] = opRatchet
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(rak))*bitsPerByte)
	p.transcript.Write(metadata)
	p.transcript.Write(rak)
}

// expand clones the protocol's transcript, appends an expand operation code, the label length, the label, and the
// requested output length, and returns 16 bytes of derived output.
func (p *Protocol) expand(label string) []byte {
	// Create a copy of the transcript.
	h, err := p.transcript.(hash.Cloner).Clone() //nolint:errcheck // cannot panic
	if err != nil {
		panic(err)
	}

	return expand(h, label)
}

// expand appends an expand operation code, the label length, the label, and the requested output length, and returns 16
// bytes of derived output.
func expand(transcript hash.Hash, label string) []byte {
	// Append the operation metadata and data to the transcript copy.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opExpand
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendRightEncode(metadata, maxExpandLen*bitsPerByte)
	transcript.Write(metadata)

	// Generate 16 bytes of output.
	return transcript.Sum(nil)[:maxExpandLen]
}

var (
	_ encoding.BinaryMarshaler   = (*Protocol)(nil)
	_ encoding.BinaryUnmarshaler = (*Protocol)(nil)
	_ encoding.BinaryAppender    = (*Protocol)(nil)
)

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
	return head, tail
}

const (
	opInit      = 0x01 // Initializes a protocol with a domain separation string.
	opMix       = 0x02 // Mixes a labeled input value into the protocol's state.
	opDerive    = 0x03 // Derives pseudorandom data from the protocol's transcript.
	opCrypt     = 0x04 // Encrypts or decrypts a plaintext value.
	opAuthCrypt = 0x05 // Opens or seals a plaintext value.
	opExpand    = 0x06 // Internal only. Derives up to 128 bits of PRF data from the protocol's transcript.
	opRatchet   = 0x07 // Internal only. Replaces the protocol's transcript with 128 bits of derived data.
)

const (
	maxExpandLen = 16 // The length, in bytes, of the maximum data expandable from a transcript.
	gcmNonceLen  = 12 // The length, in bytes, of an AES-GCM nonce.
	bitsPerByte  = 8  // The number of bits in one byte.
)
