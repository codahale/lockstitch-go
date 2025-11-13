// Package polyval implements the [POLYVAL] MAC algorithm using the AES-GCM-SIV padding scheme: pad the final message
// block with zeros, then hash a final block composed of a 64-bit little endian counter of authenticated data bits (in
// this context, hard-coded to zero) and a 64-bit little endian counter of message bits.
//
// N.B.: Keys cannot be used for multiple messages without invalidating all security claims.
//
// [POLYVAL]: https://tools.ietf.org/html/rfc8452
package polyval

import (
	"encoding/binary"

	"github.com/ericlagergren/polyval"
)

// Authenticator calculates a POLYVAL authenticator of the given message with the given key. The 16-byte authenticator
// is appended to dst.
func Authenticator(dst, key, message []byte) []byte {
	p, err := polyval.New(key)
	if err != nil {
		panic(err)
	}

	// Hash all full blocks.
	n := len(message)
	if len(message) >= 16 {
		m := len(message) &^ (16 - 1)
		p.Update(message[:m])
		message = message[m:]
	}

	// Pad final message block with zeros.
	block := make([]byte, 16)
	if len(message) > 0 {
		copy(block, message)
		p.Update(block)
	}

	// Hash a final block with the message length. The first eight bytes are zero because, unlike AES-GCM-SIV, there is
	// no authenticated data.
	binary.LittleEndian.PutUint64(block[:8], 0)
	binary.LittleEndian.PutUint64(block[8:], uint64(n)*8)
	p.Update(block)

	return p.Sum(dst)
}
