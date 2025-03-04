// Package lockstitch provides an incremental, stateful cryptographic primitive for symmetric-key
// cryptographic operations (e.g. hashing, encryption, message authentication codes, and
// authenticated encryption) in complex protocols. Inspired by TupleHash, STROBE, Noise Protocol's
// stateful objects, Merlin transcripts, and Xoodyak's Cyclist mode, Lockstitch uses SHA-256
// (https://doi.org/10.6028/NIST.FIPS.180-4) and AES-128
// (https://doi.org/10.6028/NIST.FIPS.197-upd1) to provide 10+ Gb/sec performance on modern
// processors at a 128-bit security level.
package lockstitch

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/bits"
)

// TagLen is the number of bytes added to the plaintext by the Seal operation.
const TagLen = 16

// ErrInvalidCiphertext is returned when the ciphertext is invalid or has been decrypted with the
// wrong key.
var ErrInvalidCiphertext = errors.New("lockstitch: invalid ciphertext")

// A Protocol is a stateful object providing fine-grained symmetric-key cryptographic services like
// hashing, message authentication codes, pseudo-random functions, authenticated encryption, and
// more.
type Protocol struct {
	state []byte
}

// NewProtocol creates a new Protocol with the given domain separation string.
func NewProtocol(domain string) Protocol {
	h := hmac.New(sha256.New, []byte{
		// HMAC("", "lockstitch")
		220, 87, 54, 63, 227, 165, 27, 245, 65, 144, 247, 188, 40, 15, 101, 174, 80, 197, 19, 248,
		7, 216, 209, 168, 247, 171, 219, 147, 63, 135, 63, 1,
	})
	_, _ = h.Write([]byte(domain))

	return Protocol{
		state: h.Sum(nil),
	}
}

// Mix ratchets the protocol's state using the given label and input.
func (p *Protocol) Mix(label string, input []byte) {
	_, _ = p.MixReader(label, bytes.NewReader(input))
}

// MixReader ratchets the protocol's state using the given label and input. It returns the number of
// bytes copied and the first error encountered while copying, if any.
func (p *Protocol) MixReader(label string, r io.Reader) (int64, error) {
	// Extract an operation key from the protocol's state, the operation code, the label, and the
	// input, using an unambiguous encoding to prevent collisions:
	//
	//     opk = HMAC(state, 0x01 || left_encode(|label|) || label || input)
	h := p.startOp(opMix, label)
	n, err := io.Copy(h, r)
	if err != nil {
		return n, err
	}
	opk := h.Sum(nil)

	// Extract a new state value from the protocol's old state and the operation key:
	//
	//     state' = HMAC(state, opk)
	//
	// This preserves the invariant that the protocol state is the HMAC output of two uniform
	// random keys.
	h.Reset()
	_, _ = h.Write(opk)
	p.state = h.Sum(p.state[:0])

	return n, nil
}

// MixWriter initiates a Mix operation with the given label and returns a WriteCloser wrapping the
// given Writer. All data written to the WriteCloser will be used in the Mix operation as well as
// written to the underlying writer. When Close() is called on the WriteCloser, the Mix operation is
// completed and the Protocol's state is updated.
func (p *Protocol) MixWriter(label string, w io.Writer) io.WriteCloser {
	// Extract an operation key from the protocol's state, the operation code, the label, and the
	// input, using an unambiguous encoding to prevent collisions:
	//
	//     opk = HMAC(state, 0x01 || left_encode(|label|) || label || input)
	h := p.startOp(opMix, label)
	return &mixWriter{p, h, w}
}

type mixWriter struct {
	p *Protocol
	h hash.Hash
	w io.Writer
}

func (w *mixWriter) Write(p []byte) (int, error) {
	w.h.Write(p)
	return w.w.Write(p)
}

func (w *mixWriter) Close() error {
	opk := w.h.Sum(nil)

	// Extract a new state value from the protocol's old state and the operation key:
	//
	//     state' = HMAC(state, opk)
	//
	// This preserves the invariant that the protocol state is the HMAC output of two uniform
	// random keys.
	w.h.Reset()
	_, _ = w.h.Write(opk)
	w.p.state = w.h.Sum(w.p.state[:0])

	return nil
}

// Derive generates pseudorandom output from the Protocol's current state, the label, and the output
// length, then ratchets the Protocol's state with the label and output length. The output is
// appended to dst and the resulting slice is returned.
func (p *Protocol) Derive(label string, dst []byte, n int) []byte {
	// Extract an operation key from the protocol's state, the operation code, the label, and the
	// output length, using an unambiguous encoding to prevent collisions:
	//
	//     opk = HMAC(state, 0x02 || left_encode(|label|) || label || left_encode(|out|))
	h := p.startOp(opDerive, label)
	_, _ = h.Write(leftEncode(uint64(n) * 8)) //nolint:gosec
	opk := h.Sum(nil)

	// Use the PRK to encrypt all zeroes with AES:
	//
	//     prf = AES-CTR(opk[:16], opk[16:], [0x00; N])
	ret, out := sliceForAppend(dst, n)
	for i := range out {
		out[i] = 0
	}
	block, _ := aes.NewCipher(opk[:16])
	c := cipher.NewCTR(block, opk[16:])
	c.XORKeyStream(out, out)

	// Extract a new state value from the protocol's old state and the operation key:
	//
	//     state' = HMAC(state, opk)
	//
	// This preserves the invariant that the protocol state is the HMAC output of two uniform
	// random keys.
	h.Reset()
	_, _ = h.Write(opk)
	p.state = h.Sum(p.state[:0])

	return ret
}

// Encrypt encrypts the given slice in place using the protocol's current state as the key, then
// ratchets the protocol's state using the label and input.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the
// remaining capacity of dst must not overlap plaintext.
func (p *Protocol) Encrypt(label string, dst, plaintext []byte) []byte {
	ret, ciphertext := sliceForAppend(dst, len(plaintext))

	// Extract a data encryption key and data authentication key from the protocol's state, the
	// operation code, the label, and the output length, using an unambiguous encoding to
	// prevent collisions:
	//
	//     dek || dak = HMAC(state, 0x03 || left_encode(|label|) || label || left_encode(|plaintext|))
	h := p.startOp(opCrypt, label)
	_, _ = h.Write(leftEncode(uint64(len(plaintext)) * 8))
	opk := h.Sum(nil)
	dek, dak := opk[:16], opk[16:]

	// Use the DAK to extract a PRK from the plaintext with HMAC-SHA-256:
	//
	//     prk = HMAC(dak, plaintext)
	h2 := hmac.New(sha256.New, dak)
	_, _ = h2.Write(plaintext)
	prk := h2.Sum(nil)

	// Use the DEK to encrypt the plaintext with AES-128-CTR:
	//
	//     ciphertext = AES-CTR(dek, [0x00; 16], plaintext)
	block, _ := aes.NewCipher(dek)
	c := cipher.NewCTR(block, make([]byte, 16))
	c.XORKeyStream(ciphertext, plaintext)

	// Extract a new state value from the protocol's old state and the PRK:
	//
	//     state' = HMAC(state, prk)
	//
	// This preserves the invariant that the protocol state is the HMAC output of two uniform
	// random keys.
	h.Reset()
	_, _ = h.Write(prk)
	p.state = h.Sum(p.state[:0])

	return ret
}

// Decrypt decrypts the given slice in place using the protocol's current state as the key, then
// ratchets the protocol's state using the label and input.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the
// remaining capacity of dst must not overlap ciphertext.
func (p *Protocol) Decrypt(label string, dst, ciphertext []byte) []byte {
	ret, plaintext := sliceForAppend(dst, len(ciphertext))

	// Extract a data encryption key and data authentication key from the protocol's state, the
	// operation code, the label, and the output length, using an unambiguous encoding to
	// prevent collisions:
	//
	//     dek || dak = HMAC(state, 0x03 || left_encode(|label|) || label || left_encode(|plaintext|))
	h := p.startOp(opCrypt, label)
	_, _ = h.Write(leftEncode(uint64(len(ciphertext)) * 8))
	opk := h.Sum(nil)
	dek, dak := opk[:16], opk[16:]

	// Use the DEK to decrypt the ciphertext with AES-128-CTR:
	//
	//     plaintext = AES-CTR(dek, [0x00; 16], ciphertext)
	block, _ := aes.NewCipher(dek)
	c := cipher.NewCTR(block, make([]byte, 16))
	c.XORKeyStream(plaintext, ciphertext)

	// Use the DAK to extract a PRK from the plaintext with HMAC-SHA-256:
	//
	//     prk = HMAC(dak, plaintext)
	h2 := hmac.New(sha256.New, dak)
	_, _ = h2.Write(plaintext)
	prk := h2.Sum(nil)

	// Extract a new state value from the protocol's old state and the PRK:
	//
	//     state′ = HMAC(state, prk)
	//
	// This preserves the invariant that the protocol state is the HMAC output of two uniform
	// random keys.
	h.Reset()
	_, _ = h.Write(prk)
	p.state = h.Sum(p.state[:0])

	return ret
}

// Encrypts the given slice in place using the protocol's current state as the key, appending an
// authentication tag of TagLen bytes, then ratchets the protocol's state using the label and
// input.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the
// remaining capacity of dst must not overlap plaintext.
func (p *Protocol) Seal(label string, dst, plaintext []byte) []byte {
	ret, out := sliceForAppend(dst, len(plaintext)+TagLen)
	ciphertext, tag := out[:len(plaintext)], out[len(plaintext):]

	// Extract a data encryption key and data authentication key from the protocol's state, the
	// operation code, the label, and the output length, using an unambiguous encoding to
	// prevent collisions:
	//
	//     dek || dak = HMAC(state, 0x04 || left_encode(|label|) || label || left_encode(|plaintext|))
	h := p.startOp(opAuthCrypt, label)
	_, _ = h.Write(leftEncode(uint64(len(plaintext)) * 8))
	opk := h.Sum(nil)
	dek, dak := opk[:16], opk[16:]

	// Use the DAK to extract a PRK from the plaintext with HMAC-SHA-256:
	//
	//     prk_0 || prk_1 = HMAC(dak, plaintext)
	h2 := hmac.New(sha256.New, dak)
	_, _ = h2.Write(plaintext)
	prk := h2.Sum(nil)
	copy(tag, prk[:TagLen])

	// Use the DEK and tag to encrypt the plaintext with AES-128, using the first 16 bytes of
	// the PRK as the nonce:
	//
	//     ciphertext = AES-CTR(dek, prk_0, plaintext)
	block, _ := aes.NewCipher(dek)
	c := cipher.NewCTR(block, tag)
	c.XORKeyStream(ciphertext, plaintext)

	// Use the PRK to extract a new protocol state:
	//
	//     state' = HMAC(state, prk_0 || prk_1)
	//
	// This preserves the invariant that the protocol state is the HMAC output of two uniform
	// random keys.
	h.Reset()
	_, _ = h.Write(prk)
	p.state = h.Sum(p.state[:0])

	return ret
}

// Open decrypts the given slice in place using the protocol's current state as the key, verifying
// the final TagLen bytes as an authentication tag, then ratchets the protocol's state using the
// label and input.
//
// If the ciphertext is authentic, the plaintext is appended to dst and returned; otherwise,
// ErrInvalidCiphertext is returned.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the
// remaining capacity of dst must not overlap ciphertext.
func (p *Protocol) Open(label string, dst, ciphertext []byte) ([]byte, error) {
	ret, plaintext := sliceForAppend(dst, len(ciphertext)-TagLen)
	ciphertext, tag := ciphertext[:len(ciphertext)-TagLen], ciphertext[len(ciphertext)-TagLen:]

	// Extract a data encryption key and data authentication key from the protocol's state, the
	// operation code, the label, and the output length, using an unambiguous encoding to
	// prevent collisions:
	//
	//     dek || dak = HMAC(state, 0x04 || left_encode(|label|) || label || left_encode(|plaintext|))
	h := p.startOp(opAuthCrypt, label)
	_, _ = h.Write(leftEncode(uint64(len(plaintext)) * 8))
	opk := h.Sum(nil)
	dek, dak := opk[:16], opk[16:]

	// Use the DEK and the tag to decrypt the plaintext with AES-128:
	//
	//     plaintext = AES-CTR(dek, tag, ciphertext)
	block, _ := aes.NewCipher(dek)
	c := cipher.NewCTR(block, tag)
	c.XORKeyStream(plaintext, ciphertext)

	// Use the DAK to extract a PRK from the plaintext with HMAC-SHA-256:
	//
	//     prk_0 || prk_1 = HMAC(dak, plaintext)
	h2 := hmac.New(sha256.New, dak)
	_, _ = h2.Write(plaintext)
	prk := h2.Sum(opk[:0])

	// Use the PRK to extract a new protocol state:
	//
	//     state' = HMAC(state, prk_0 || prk_1)
	//
	// This preserves the invariant that the protocol state is the HMAC output of two uniform
	// random keys.
	h.Reset()
	_, _ = h.Write(prk)
	p.state = h.Sum(p.state[:0])

	// Verify the authentication tag:
	//
	//     tag = prk_0
	if hmac.Equal(tag, prk[:TagLen]) {
		return ret, nil
	}

	// If unauthenticated, zero out the output buffer to prevent accidental disclosure.
	for i := range plaintext {
		plaintext[i] = 0
	}
	return nil, ErrInvalidCiphertext
}

// Clone returns an exact clone of the receiver Protocol.
func (p *Protocol) Clone() Protocol {
	return Protocol{state: p.state}
}

func (p *Protocol) startOp(op byte, label string) hash.Hash {
	h := hmac.New(sha256.New, p.state)
	_, _ = h.Write([]byte{op})
	_, _ = h.Write(leftEncode(uint64(len(label)) * 8))
	_, _ = h.Write([]byte(label))
	return h
}

const (
	opMix       = 0x01
	opDerive    = 0x02
	opCrypt     = 0x03
	opAuthCrypt = 0x04
)

// leftEncode encodes an integer value using NIST SP 800-185's left_encode.
//
// https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
func leftEncode(value uint64) []byte {
	buf := [9]byte{}
	binary.BigEndian.PutUint64(buf[1:], value)
	n := max(len(buf)-1-(bits.LeadingZeros64(value)/8), 1)
	buf[len(buf)-n-1] = byte(n)
	return buf[len(buf)-n-1:]
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
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
