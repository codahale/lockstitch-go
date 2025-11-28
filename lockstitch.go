// Package lockstitch provides an incremental, stateful cryptographic primitive for symmetric-key cryptographic
// operations (e.g., hashing, encryption, message authentication codes, and authenticated encryption) in complex
// protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin transcripts, and Xoodyak's
// Cyclist mode, Lockstitch uses [SHA-512/256], [AES-128], and [GMAC] to provide 10+ Gb/sec performance on modern
// processors at a 128-bit security level.
//
// [SHA-512/256]: https://doi.org/10.6028/NIST.FIPS.180-4
// [GMAC]: https://doi.org/10.6028/NIST.SP.800-38D
// [AES-128]: https://doi.org/10.6028/NIST.FIPS.197-upd1
package lockstitch

import (
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
	// Append the operation metadata to the transcript.
	transcript := sha512.New512_256()
	transcript.Write([]byte{opInit})
	transcript.Write(tuplehash.LeftEncode(uint64(len(domain)) * bitsPerByte))
	transcript.Write([]byte(domain))

	return Protocol{transcript}
}

// Mix ratchets the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	// Append the operation metadata and data to the transcript.
	p.transcript.Write([]byte{opMix})
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	p.transcript.Write([]byte(label))
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(input)) * bitsPerByte))
	p.transcript.Write(input)
}

// Derive generates pseudorandom output from the Protocol's current state, the label, and the output length, then
// ratchets the Protocol's state with the label and output length. It appends the output to dst and returns the
// resulting slice.
func (p *Protocol) Derive(label string, dst []byte, n int) []byte {
	if n < 0 {
		panic("invalid argument to Derive: n cannot be negative")
	}

	// Append the operation metadata to the transcript.
	p.transcript.Write([]byte{opDerive})
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	p.transcript.Write([]byte(label))
	p.transcript.Write(tuplehash.LeftEncode(uint64(n) * bitsPerByte))

	// Expand a PRF key and IV.
	keyAndIV := make([]byte, aes128KeyLen+aes.BlockSize)
	p.expand("prf key", keyAndIV)

	// Expand n bytes of AES-128-CTR keystream for PRF output.
	ret, prf := mem.SliceForAppend(dst, n)
	for i := range prf {
		prf[i] = 0 // There's no way to get just the keystream from stdlib's CTR mode, so we ensure the input is zeroed.
	}
	aes128CTR(keyAndIV[:aes128KeyLen], keyAndIV[aes128KeyLen:], prf, prf)

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
	dek, dak := make([]byte, aes128KeyLen+aes.BlockSize), make([]byte, aes128KeyLen+gcmNonceLen)

	// Append the operation metadata to the transcript.
	p.transcript.Write([]byte{opCrypt})
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	p.transcript.Write([]byte(label))
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(plaintext)) * bitsPerByte))

	// Expand a data encryption key, an IV, and a data authentication key from the transcript.
	p.expand("data encryption key", dek)
	p.expand("data authentication key", dak)

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes12GMAC(dak[:aes128KeyLen], dak[aes128KeyLen:aes128KeyLen+gcmNonceLen], dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

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
	dek, dak := make([]byte, aes128KeyLen+aes.BlockSize), make([]byte, aes128KeyLen+gcmNonceLen)

	// Append the operation metadata to the transcript.
	p.transcript.Write([]byte{opCrypt})
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	p.transcript.Write([]byte(label))
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(plaintext)) * bitsPerByte))

	// Expand a data encryption key, an IV, and a data authentication key from the transcript.
	p.expand("data encryption key", dek)
	p.expand("data authentication key", dak)

	// Decrypt the ciphertext using AES-128-CTR.
	aes128CTR(dek[:aes128KeyLen], dek[aes128KeyLen:], plaintext, ciphertext)

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes12GMAC(dak[:aes128KeyLen], dak[aes128KeyLen:aes128KeyLen+gcmNonceLen], dak[:0], plaintext)

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
	// Allocate a slice for the ciphertext and split it between ciphertext and tag. Also allocate slices for keys.
	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext)+TagLen)
	ciphertext, tag := ciphertext[:len(plaintext)], ciphertext[len(plaintext):]
	dek, dak := make([]byte, aes128KeyLen), make([]byte, aes128KeyLen+gcmNonceLen)

	// Append the operation metadata to the transcript.
	p.transcript.Write([]byte{opAuthCrypt})
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	p.transcript.Write([]byte(label))
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(plaintext)) * bitsPerByte))

	// Expand a data encryption key and a data authentication key from the transcript.
	p.expand("data encryption key", dek)
	p.expand("data authentication key", dak)

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes12GMAC(dak[:aes128KeyLen], dak[aes128KeyLen:aes128KeyLen+gcmNonceLen], dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

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
	dek, dak, tagP := make([]byte, aes128KeyLen), make([]byte, aes128KeyLen+gcmNonceLen), make([]byte, TagLen)

	// Append the operation metadata to the transcript.
	p.transcript.Write([]byte{opAuthCrypt})
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	p.transcript.Write([]byte(label))
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(plaintext)) * bitsPerByte))

	// Expand a data encryption key and a data authentication key from the transcript.
	p.expand("data encryption key", dek)
	p.expand("data authentication key", dak)

	// Decrypt the ciphertext using AES-128-CTR with the tag as the IV.
	aes128CTR(dek, tag, plaintext, ciphertext)

	// Calculate an AES-128-GMAC authenticator of the plaintext.
	auth := aes12GMAC(dak[:aes128KeyLen], dak[aes128KeyLen:aes128KeyLen+gcmNonceLen], dak[:0], plaintext)

	// Append the authenticator to the transcript.
	p.transcript.Write(auth)

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
	state, err := p.transcript.(encoding.BinaryMarshaler).MarshalBinary() //nolint:errcheck // cannot panic
	if err != nil {
		panic(err)
	}

	transcript := sha512.New512_256()
	if err := transcript.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil { //nolint:errcheck // cannot panic
		panic(err)
	}
	return Protocol{transcript}
}

// ratchet replaces the protocol's transcript with a ratchet operation code and a ratchet key derived from the previous
// protocol transcript.
func (p *Protocol) ratchet() {
	// Expand a ratchet key.
	rak := make([]byte, ratchetKeyLen)
	p.expand("ratchet key", rak)

	// Clear the transcript.
	p.transcript.Reset()

	// Append the operation metadata and data to the transcript.
	p.transcript.Write([]byte{opRatchet})
	p.transcript.Write(tuplehash.LeftEncode(uint64(len(rak)) * bitsPerByte))
	p.transcript.Write(rak)
}

// expand clones the protocol's transcript, appends an expand operation code, the label length, the label, and the
// requested output length, and fills the out slice with derived data.
func (p *Protocol) expand(label string, out []byte) {
	// Create a copy of the transcript.
	h := p.Clone().transcript

	// Append the operation metadata and data to the transcript copy.
	h.Write([]byte{opExpand})
	h.Write(tuplehash.LeftEncode(uint64(len(label)) * bitsPerByte))
	h.Write([]byte(label))
	h.Write(tuplehash.RightEncode(uint64(len(out)) * bitsPerByte))

	// Generate up to 32 bytes of output.
	switch {
	case len(out) == h.Size():
		h.Sum(out[:0])
	case len(out) < h.Size():
		copy(out, h.Sum(nil)[:len(out)])
	default:
		panic("invalid expand length")
	}
}

func aes128CTR(key, iv, dst, src []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
}

func aes12GMAC(key, nonce, dst, src []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	return gcm.Seal(dst, nonce, nil, src)
}

const (
	opInit      = 0x01
	opMix       = 0x02
	opDerive    = 0x03
	opCrypt     = 0x04
	opAuthCrypt = 0x05
	opExpand    = 0x06
	opRatchet   = 0x07

	ratchetKeyLen = 32
	aes128KeyLen  = 16
	gcmNonceLen   = 12
	bitsPerByte   = 8
)
