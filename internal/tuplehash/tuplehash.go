package tuplehash

import (
	"encoding/binary"
	"math/bits"
)

// LeftEncode encodes an integer value using NIST SP 800-185's left_encode.
//
// https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
func LeftEncode(value uint64) []byte {
	var buf [9]byte
	binary.BigEndian.PutUint64(buf[1:], value)
	n := max(len(buf)-1-(bits.LeadingZeros64(value)/8), 1)
	buf[len(buf)-n-1] = byte(n)
	return buf[len(buf)-n-1:]
}

// RightEncode encodes an integer value using NIST SP 800-185's right_encode.
//
// https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
func RightEncode(value uint64) []byte {
	var buf [9]byte
	binary.BigEndian.PutUint64(buf[:8], value)
	n := max(len(buf)-1-(bits.LeadingZeros64(value)/8), 1)
	buf[len(buf)-1] = byte(n)
	return buf[len(buf)-n-1:]
}
