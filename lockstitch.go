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
	"math/bits"
	"slices"
	"strconv"

	"github.com/codahale/lockstitch-go/internal/aes"
	"github.com/codahale/lockstitch-go/internal/tuplehash"
)

const (
	// TagSize is the number of bytes added to the plaintext by the Seal operation.
	TagSize = 16
	// MaxDeriveSize is the maximum number of bytes which can be produced by a single Protocol.Derive operation.
	MaxDeriveSize = 64 * 1024 * 1024 * 1024 // 64 GiB
)

// ErrInvalidCiphertext is returned when the ciphertext is invalid or has been decrypted with the
// wrong key.
var ErrInvalidCiphertext = errors.New("lockstitch: invalid ciphertext")

// A Protocol is a stateful object providing fine-grained symmetric-key cryptographic services like hashing, message
// authentication codes, pseudo-random functions, authenticated encryption, and more.
//
// Protocol instances are not concurrent-safe.
type Protocol struct {
	_           noCopy
	transcript  hash.Hash
	metadataBuf []byte
}

// NewProtocol creates a new Protocol with the given domain separation string.
//
// The domain separation string should be unique to the application and specific protocol. It should not contain dynamic
// data like timestamps or user IDs. A good format is "application-name.protocol-name".
func NewProtocol(domain string) *Protocol {
	// Initialize an empty transcript.
	p := &Protocol{ //nolint:exhaustruct // noCopy can't be initialized, metadataBuf doesn't need to be
		transcript: sha256.New(),
	}

	// Append the operation metadata to the transcript.
	metadata := p.metadataBuffer(max(1+tuplehash.MaxSize+len(domain), initialBufSize))
	metadata[0] = opInit
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(domain))*bitsPerByte)
	metadata = append(metadata, domain...)
	p.transcript.Write(metadata)
	clear(metadata)

	return p
}

// Mix ratchets the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	// Append the operation metadata and data to the transcript.
	metadata := p.metadataBuffer(1 + tuplehash.MaxSize + len(label) + tuplehash.MaxSize)
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
//
// Derive panics if n is negative or greater than MaxDeriveSize to strictly avoid birthday-bound attacks.
func (p *Protocol) Derive(label string, dst []byte, n int) []byte {
	if n < 0 {
		panic("invalid argument to Derive: n cannot be negative")
	} else if uint64(n) > MaxDeriveSize {
		panic("invalid argument to Derive: n must be <= 64GiB")
	}

	// Append the operation metadata to the transcript.
	metadata := p.metadataBuffer(1 + tuplehash.MaxSize + len(label) + tuplehash.MaxSize)
	metadata[0] = opDerive
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(n)*bitsPerByte)
	p.transcript.Write(metadata)
	clear(metadata)

	// Expand a PRF key.
	expandBuf := make([]byte, expandBufSize)
	prfKey := p.expand(p.cloneTranscript(), "prf key", expandBuf[:0])

	// Expand n bytes of AES-128-CTR keystream for PRF output.
	ret, prf := sliceForAppend(dst, n)
	clear(prf) // There's no way to get just the keystream from stdlib's CTR mode, so we ensure the input is zeroed.
	aes.CTR(prfKey, zeroIV[:], prf, prf)

	// Ratchet the transcript.
	p.ratchet(expandBuf[:0])

	return ret
}

// Encrypt encrypts the plaintext using the protocol's current state as the key, then ratchets the protocol's state
// using the label and input. It appends the ciphertext to dst and returns the resulting slice.
//
// Encrypt provides confidentiality but not authenticity. If you need to ensure the ciphertext hasn't been modified, use
// Seal instead.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Encrypt(label string, dst, plaintext []byte) []byte {
	// Allocate a slice for the ciphertext.
	ret, ciphertext := sliceForAppend(dst, len(plaintext))

	// Append the operation metadata to the transcript.
	metadata := p.metadataBuffer(1 + tuplehash.MaxSize + len(label) + tuplehash.MaxSize)
	metadata[0] = opCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(plaintext))*bitsPerByte)
	p.transcript.Write(metadata)
	clear(metadata)

	// Expand a data encryption key and a data authentication key from the transcript.
	expandBuf := make([]byte, expandBufSize*2)
	dek := p.expand(p.cloneTranscript(), "data encryption key", expandBuf[:0])
	dak := p.expand(p.cloneTranscript(), "data authentication key", expandBuf[expandBufSize:expandBufSize])

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes.GMAC(dak, dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Encrypt the plaintext using AES-128-CTR.
	aes.CTR(dek, zeroIV[:], ciphertext, plaintext)

	// Ratchet the transcript.
	p.ratchet(expandBuf[:0])

	return ret
}

// Decrypt decrypts the given ciphertext using the protocol's current state as the key, then ratchets the protocol's
// state using the label and input. It appends the plaintext to dst and returns the resulting slice.
//
// Decrypt provides confidentiality but not authenticity. If you need to ensure the ciphertext hasn't been modified, use
// Open instead.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
func (p *Protocol) Decrypt(label string, dst, ciphertext []byte) []byte {
	// Allocate a slice for the plaintext.
	ret, plaintext := sliceForAppend(dst, len(ciphertext))

	// Append the operation metadata to the transcript.
	metadata := p.metadataBuffer(1 + tuplehash.MaxSize + len(label) + tuplehash.MaxSize)
	metadata[0] = opCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(plaintext))*bitsPerByte)
	p.transcript.Write(metadata)
	clear(metadata)

	// Expand a data encryption key, an IV, and a data authentication key from the transcript.
	expandBuf := make([]byte, expandBufSize*2)
	dek := p.expand(p.cloneTranscript(), "data encryption key", expandBuf[:0])
	dak := p.expand(p.cloneTranscript(), "data authentication key", expandBuf[expandBufSize:expandBufSize])

	// Decrypt the ciphertext using AES-128-CTR.
	aes.CTR(dek, zeroIV[:], plaintext, ciphertext)

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes.GMAC(dak, dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Ratchet the transcript.
	p.ratchet(expandBuf[:0])

	return ret
}

// Seal encrypts the given plaintext using the protocol's current state as the key, appending an authentication tag of
// TagSize bytes, then ratchets the protocol's state using the label and input. It appends the ciphertext and
// authentication tag to dst and returns the resulting slice.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity of
// dst must not overlap plaintext.
func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	// Allocate a slice for the ciphertext and split it between ciphertext and tag.
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+TagSize)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]

	// Append the operation metadata to the transcript.
	metadata := p.metadataBuffer(1 + tuplehash.MaxSize + len(label) + tuplehash.MaxSize)
	metadata[0] = opAuthCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(plaintext))*bitsPerByte)
	p.transcript.Write(metadata)
	clear(metadata)

	// Expand a data encryption key and a data authentication key from the transcript.
	expandBuf := make([]byte, expandBufSize*2)
	dek := p.expand(p.cloneTranscript(), "data encryption key", expandBuf[:0])
	dak := p.expand(p.cloneTranscript(), "data authentication key", expandBuf[expandBufSize:expandBufSize])

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes.GMAC(dak, dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Expand an authentication tag.
	copy(tag, p.expand(p.cloneTranscript(), "authentication tag", auth[:0]))

	// Encrypt the plaintext using AES-128-CTR with the tag as the IV.
	aes.CTR(dek, tag, ciphertext, plaintext)

	// Ratchet the transcript.
	p.ratchet(expandBuf[:0])

	return ret
}

// Open decrypts the given slice in place using the protocol's current state as the key, verifying the final TagSize
// bytes as an authentication tag. If the ciphertext is authentic, it appends the plaintext to dst and returns the
// resulting slice; otherwise, ErrInvalidCiphertext is returned.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
func (p *Protocol) Open(label string, dst, ciphertext []byte) ([]byte, error) {
	// Split the ciphertext between ciphertext and tag. Allocate slice for plaintext.
	ciphertext, tag := ciphertext[:len(ciphertext)-TagSize], ciphertext[len(ciphertext)-TagSize:]
	ret, plaintext := sliceForAppend(dst, len(ciphertext))

	// Append the operation metadata to the transcript.
	metadata := p.metadataBuffer(1 + tuplehash.MaxSize + len(label) + tuplehash.MaxSize)
	metadata[0] = opAuthCrypt
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(plaintext))*bitsPerByte)
	p.transcript.Write(metadata)
	clear(metadata)

	// Expand a data encryption key and a data authentication key from the transcript.
	expandBuf := make([]byte, expandBufSize*2)
	dek := p.expand(p.cloneTranscript(), "data encryption key", expandBuf[:0])
	dak := p.expand(p.cloneTranscript(), "data authentication key", expandBuf[expandBufSize:expandBufSize])

	// Decrypt the ciphertext using AES-128-CTR with the tag as the IV.
	aes.CTR(dek, tag, plaintext, ciphertext)

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes.GMAC(dak, dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Expand a counterfactual authentication tag.
	tagP := p.expand(p.cloneTranscript(), "authentication tag", auth[:0])

	// Ratchet the transcript.
	p.ratchet(expandBuf[:0])

	// Compare the tag and the counterfactual tag in constant time.
	if subtle.ConstantTimeCompare(tag, tagP) == 0 {
		clear(plaintext)
		return nil, ErrInvalidCiphertext
	}
	return ret, nil
}

// Clone returns an exact, deep copy of the receiver Protocol. The cloned protocol shares no state with the original.
func (p *Protocol) Clone() *Protocol {
	transcript, err := p.transcript.(hash.Cloner).Clone() //nolint:errcheck // cannot panic
	if err != nil {
		panic(err)
	}

	return &Protocol{ //nolint:exhaustruct // noCopy cannot be initialized
		transcript:  transcript,
		metadataBuf: make([]byte, len(p.metadataBuf)),
	}
}

func (p *Protocol) AppendBinary(b []byte) ([]byte, error) {
	if p.transcript == nil {
		return nil, errors.New("lockstitch: uninitialized protocol")
	}
	return p.transcript.(encoding.BinaryAppender).AppendBinary(b) //nolint:errcheck // cannot panic
}

func (p *Protocol) UnmarshalBinary(data []byte) error {
	if p.transcript != nil {
		return errors.New("lockstitch: initialized protocol")
	}

	p.transcript = sha256.New()
	p.metadataBuf = make([]byte, initialBufSize)
	return p.transcript.(encoding.BinaryUnmarshaler).UnmarshalBinary(data) //nolint:errcheck // cannot panic
}

func (p *Protocol) MarshalBinary() (data []byte, err error) {
	if p.transcript == nil {
		return nil, errors.New("lockstitch: uninitialized protocol")
	}
	return p.transcript.(encoding.BinaryMarshaler).MarshalBinary() //nolint:errcheck // cannot panic
}

// ratchet replaces the protocol's transcript with a ratchet operation code and a ratchet key derived from the previous
// protocol transcript.
func (p *Protocol) ratchet(expandBuf []byte) {
	// Expand a ratchet key in place, since the transcript is immediately reset following this.
	rak := p.expand(p.transcript, "ratchet key", expandBuf)

	// Clear the transcript.
	p.transcript.Reset()

	// Append the operation metadata and data to the transcript.
	metadata := p.metadataBuffer(1 + tuplehash.MaxSize)
	metadata[0] = opRatchet
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(rak))*bitsPerByte)
	p.transcript.Write(metadata)
	clear(metadata)
	p.transcript.Write(rak)
}

// expand appends an expand operation code, the label length, the label, and the requested output length, and returns 16
// bytes of derived output.
func (p *Protocol) expand(transcript hash.Hash, label string, buf []byte) []byte {
	// Append the operation metadata and data to the transcript copy.
	metadata := p.metadataBuffer(1 + tuplehash.MaxSize + len(label) + tuplehash.MaxSize)
	metadata[0] = opExpand
	metadata = tuplehash.AppendLeftEncode(metadata, uint64(len(label))*bitsPerByte)
	metadata = append(metadata, label...)
	metadata = tuplehash.AppendRightEncode(metadata, maxExpandSize*bitsPerByte)
	transcript.Write(metadata)
	clear(metadata)

	// Generate 16 bytes of output.
	return transcript.Sum(buf)[:maxExpandSize]
}

// cloneTranscript returns a clone of the protocol's transcript.
func (p *Protocol) cloneTranscript() hash.Hash {
	clone, _ := p.transcript.(hash.Cloner).Clone() //nolint:errcheck // type assertion cannot fail, neither can Clone
	return clone
}

// metadataBuffer returns a 1-length, n-capacity slice, reusing the protocol's existing metadataBuf if possible.
func (p *Protocol) metadataBuffer(n int) []byte {
	if len(p.metadataBuf) < n {
		// If the buffer is undersized, round up to the nearest power of two for the new one.
		p.metadataBuf = make([]byte, 1<<(strconv.IntSize-bits.LeadingZeros(uint(n-1)))) //nolint:gosec // n is always >= initialBufSize
	}

	return p.metadataBuf[:1]
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
	head = slices.Grow(in, n)
	head = head[:len(in)+n]
	tail = head[len(in):]
	return head, tail
}

//nolint:gochecknoglobals // the whole point of this is that it's global
var zeroIV [aes.BlockSize]byte

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
	maxExpandSize  = 16 // The length, in bytes, of the maximum data expandable from a transcript.
	bitsPerByte    = 8  // The number of bits in one byte.
	initialBufSize = 64 // The length, in bytes, of the initial metadata buffer.
	expandBufSize  = 32 // The length, in bytes, required of an expand buffer.
)

// noCopy is a fake lock used by -copylocks checker from `go vet`.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
