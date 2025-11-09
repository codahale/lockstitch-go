// Package tuplehash implements various routines from [NIST SP 800-185].
//
// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
package tuplehash

import (
	"encoding/binary"
	"math/bits"

	"github.com/codahale/lockstitch-go/internal/mem"
)

// LeftEncode encodes an integer value using NIST SP 800-185's left_encode and appends it to dst.
func LeftEncode(dst []byte, value uint64) []byte {
	n := 8 - (bits.LeadingZeros64(value|1) / 8)
	ret, buf := mem.SliceForAppend(dst, 9)
	binary.BigEndian.PutUint64(buf[1:], value<<((8-n)*8))
	buf[0] = byte(n)
	return ret[:len(ret)-(8-n)]
}

// RightEncode encodes an integer value using NIST SP 800-185's right_encode and appends is to dst.
func RightEncode(dst []byte, value uint64) []byte {
	n := 8 - (bits.LeadingZeros64(value|1) / 8)
	ret, buf := mem.SliceForAppend(dst, 9)
	binary.BigEndian.PutUint64(buf, value<<((8-n)*8))
	buf[n] = byte(n)
	return ret[:len(ret)-(8-n)]
}
