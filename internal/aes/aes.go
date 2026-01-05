// Package aes provides concise implementations of AES-CTR for confidentiality and AES-GMAC for authenticity.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
)

// BlockSize is the block size of the AES cipher.
const BlockSize = aes.BlockSize

// CTR implements AES-CTR with a specialized implementation for inputs shorter than 64 bytes. The standard library
// implementation of AES-CTR uses SIMD instructions for high throughput, which comes with a latency penalty for small
// inputs.
func CTR(key, iv, dst, src []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// For small messages (i.e., under 8 blocks), it's faster to avoid the full AES-CTR vector pipeline.
	if len(src) < BlockSize*8 {
		ctrSmall(block, iv, dst, src)
		return
	}

	// For long messages, the throughput gains of stdlib's AES-CTR implementation are unbeatable.
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
}

func ctrSmall(block cipher.Block, iv, dst, src []byte) {
	var ctrBuf, tmpBuf [BlockSize]byte
	ctr, tmp := ctrBuf[:], tmpBuf[:]
	copy(ctr, iv)
	for {
		// Encrypt the counter to produce a block of keystream, then XOR it with the input.
		block.Encrypt(tmp, ctr)
		subtle.XORBytes(dst, src, tmp)

		// Advance the inputs by either a block or the remaining bytes.
		remain := min(len(dst), BlockSize)
		dst = dst[remain:]
		src = src[remain:]

		// If the input is fully processed, return.
		if len(dst) == 0 {
			return
		}

		// Increment counter, if necessary.
		for i := len(ctr) - 1; i >= 0; i-- {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
	}
}

// GMAC implements AES-GMAC, which is the same thing as AES-GCM, but passing the message as the authenticated data and
// an empty string as the plaintext.
func GMAC(key, nonce, dst, src []byte) []byte {
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
