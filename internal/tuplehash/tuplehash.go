// Package tuplehash implements various routines from [NIST SP 800-185].
//
// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
package tuplehash

import (
	"encoding/binary"
	"math/bits"

	"github.com/ericlagergren/subtle"
)

// LeftEncode encodes an integer value using NIST SP 800-185's left_encode.
func LeftEncode(dst []byte, value uint64) []byte {
	n := 8 - (bits.LeadingZeros64(value|1) / 8)
	ret, buf := subtle.SliceForAppend(dst, 9)
	binary.BigEndian.PutUint64(buf[1:], value<<((8-n)*8))
	buf[0] = byte(n)
	return ret[:len(ret)-(8-n)]
}

// RightEncode encodes an integer value using NIST SP 800-185's right_encode.
func RightEncode(dst []byte, value uint64) []byte {
	n := 8 - (bits.LeadingZeros64(value|1) / 8)
	ret, buf := subtle.SliceForAppend(dst, 9)
	binary.BigEndian.PutUint64(buf, value<<((8-n)*8))
	buf[n] = byte(n)
	return ret[:len(ret)-(8-n)]
}
