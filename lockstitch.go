// Package lockstitch provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic
// operations (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex
// protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin transcripts, and Xoodyak's
// Cyclist mode, Lockstitch uses [SHA-512/256], [AES-256], and [GMAC] to provide 10+ Gb/sec performance on modern
// processors at a 128-bit security level.
//
// [SHA-512/256]: https://doi.org/10.6028/NIST.FIPS.180-4
// [GMAC]: https://doi.org/10.6028/NIST.SP.800-38D
// [AES-256]: https://doi.org/10.6028/NIST.FIPS.197-upd1
package lockstitch

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"crypto/subtle"
	"encoding"
	"errors"
	"hash"

	"github.com/codahale/lockstitch-go/internal/mem"
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
	transcript := sha512.New512_256()

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(domain))
	metadata[0] = opInit
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(domain))*bitsPerByte)...)
	metadata = append(metadata, []byte(domain)...)
	transcript.Write(metadata)

	return Protocol{transcript}
}

// Mix ratchets the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	// Append the operation metadata and data to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opMix
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(label))*bitsPerByte)...)
	metadata = append(metadata, []byte(label)...)
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(input))*bitsPerByte)...)
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
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(label))*bitsPerByte)...)
	metadata = append(metadata, []byte(label)...)
	metadata = append(metadata, tuplehash.LeftEncode(uint64(n)*bitsPerByte)...)
	p.transcript.Write(metadata)

	// Expand a PRF key.
	prfKey := p.expand("prf key", aes256KeyLen)

	// Expand n bytes of AES-256-CTR keystream for PRF output.
	ret, prf := mem.SliceForAppend(dst, n)
	for i := range prf {
		prf[i] = 0 // There's no way to get just the keystream from stdlib's CTR mode, so we ensure the input is zeroed.
	}
	aesCTR(prfKey, zeroIV[:], prf, prf)

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
	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext))

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opCrypt
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(label))*bitsPerByte)...)
	metadata = append(metadata, []byte(label)...)
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(plaintext))*bitsPerByte)...)
	p.transcript.Write(metadata)

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand("data encryption key", aes256KeyLen)
	dak := p.expand("data authentication key", aes256KeyLen)

	// Calculate an AES-256-GMAC authenticator of the plaintext.
	auth := aesGMAC(dak, dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Encrypt the plaintext using AES-256-CTR.
	aesCTR(dek, zeroIV[:], ciphertext, plaintext)

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
	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opCrypt
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(label))*bitsPerByte)...)
	metadata = append(metadata, []byte(label)...)
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(plaintext))*bitsPerByte)...)
	p.transcript.Write(metadata)

	// Expand a data encryption key, an IV, and a data authentication key from the transcript.
	dek := p.expand("data encryption key", aes256KeyLen)
	dak := p.expand("data authentication key", aes256KeyLen)

	// Decrypt the ciphertext using AES-256-CTR.
	aesCTR(dek, zeroIV[:], plaintext, ciphertext)

	// Calculate an AES-256-GMAC authenticator of the plaintext.
	auth := aesGMAC(dak, dak[:0], plaintext)

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
	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext)+TagLen)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opAuthCrypt
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(label))*bitsPerByte)...)
	metadata = append(metadata, []byte(label)...)
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(plaintext))*bitsPerByte)...)
	p.transcript.Write(metadata)

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand("data encryption key", aes256KeyLen)
	dak := p.expand("data authentication key", aes256KeyLen)

	// Calculate an AES-256-GMAC authenticator of the plaintext.
	auth := aesGMAC(dak, dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Expand an authentication tag.
	copy(tag, p.expand("authentication tag", TagLen))

	// Encrypt the plaintext using AES-256-CTR with the tag as the IV.
	aesCTR(dek, tag, ciphertext, plaintext)

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
	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))

	// Append the operation metadata to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opAuthCrypt
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(label))*bitsPerByte)...)
	metadata = append(metadata, []byte(label)...)
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(plaintext))*bitsPerByte)...)
	p.transcript.Write(metadata)

	// Expand a data encryption key and a data authentication key from the transcript.
	dek := p.expand("data encryption key", aes256KeyLen)
	dak := p.expand("data authentication key", aes256KeyLen)

	// Decrypt the ciphertext using AES-256-CTR with the tag as the IV.
	aesCTR(dek, tag, plaintext, ciphertext)

	// Calculate an AES-256-GMAC authenticator of the plaintext.
	auth := aesGMAC(dak[:aes256KeyLen], dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

	// Expand a counterfactual authentication tag.
	tagP := p.expand("authentication tag", TagLen)

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
	// Expand a ratchet key.
	rak := p.expand("ratchet key", p.transcript.Size())

	// Clear the transcript.
	p.transcript.Reset()

	// Append the operation metadata and data to the transcript.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen)
	metadata[0] = opRatchet
	metadata = append(metadata, tuplehash.LeftEncode(uint64(p.transcript.Size())*bitsPerByte)...) //nolint:gosec // n << 2^64
	p.transcript.Write(metadata)
	p.transcript.Write(rak)
}

// expand clones the protocol's transcript, appends an expand operation code, the label length, the label, and the
// requested output length, and returns n (<=32) bytes of derived output.
func (p *Protocol) expand(label string, n int) []byte {
	// Create a copy of the transcript.
	h, err := p.transcript.(hash.Cloner).Clone() //nolint:errcheck // cannot panic
	if err != nil {
		panic(err)
	}

	if n > h.Size() {
		panic("invalid expand length")
	}

	// Append the operation metadata and data to the transcript copy.
	metadata := make([]byte, 1, 1+tuplehash.MaxLen+len(label)+tuplehash.MaxLen)
	metadata[0] = opExpand
	metadata = append(metadata, tuplehash.LeftEncode(uint64(len(label))*bitsPerByte)...)
	metadata = append(metadata, []byte(label)...)
	metadata = append(metadata, tuplehash.RightEncode(uint64(n)*bitsPerByte)...) //nolint:gosec // n <= 32
	_, _ = h.Write(metadata)

	// Generate up to 32 bytes of output.
	return h.Sum(nil)[:n]
}

var (
	_ encoding.BinaryMarshaler   = (*Protocol)(nil)
	_ encoding.BinaryUnmarshaler = (*Protocol)(nil)
	_ encoding.BinaryAppender    = (*Protocol)(nil)
)

func aesCTR(key, iv, dst, src []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// For small messages, it's faster to avoid the full AES-CTR vector pipeline.
	if len(src) <= aes.BlockSize*4 {
		ctr := bytes.Clone(iv)
		tmp := make([]byte, aes.BlockSize)
		for {
			block.Encrypt(tmp, ctr)
			subtle.XORBytes(dst, src, tmp)

			remain := min(len(dst), aes.BlockSize)
			dst = dst[remain:]
			src = src[remain:]

			if len(dst) == 0 {
				return
			}

			// Increment counter
			for i := len(ctr) - 1; i >= 0; i-- {
				ctr[i]++
				if ctr[i] != 0 {
					break
				}
			}
		}
	}

	// For long messages, the throughput gains of stdlib's AES-CTR implementation are unbeatable.
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
}

type fakeBlock struct {
	block cipher.Block
}

func (f *fakeBlock) BlockSize() int {
	return f.block.BlockSize()
}

func (f *fakeBlock) Encrypt(dst, src []byte) {
	f.block.Encrypt(dst, src)
}

func (f *fakeBlock) Decrypt(dst, src []byte) {
	f.block.Decrypt(dst, src)
}

var _ cipher.Block = (*fakeBlock)(nil)

func aesGMAC(key, dst, src []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	return gcm.Seal(dst, zeroIV[:gcm.NonceSize()], nil, src)
}

var zeroIV [aes.BlockSize]byte //nolint:gochecknoglobals // it's just zeros, man

const (
	opInit      = 0x01
	opMix       = 0x02
	opDerive    = 0x03
	opCrypt     = 0x04
	opAuthCrypt = 0x05
	opExpand    = 0x06
	opRatchet   = 0x07

	aes256KeyLen = 32
	bitsPerByte  = 8
)
