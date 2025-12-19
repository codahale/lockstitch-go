package aes_test

import (
	"bytes"
	stdlibaes "crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/codahale/lockstitch-go/internal/aes"
)

func FuzzCTR(f *testing.F) {
	f.Add([]byte("ayellowsubmarine"), []byte("ayellowsubmarine"), make([]byte, 15))
	f.Add([]byte("ayellowsubmarine"), []byte("ayellowsubmarine"), make([]byte, 31))
	f.Add([]byte("ayellowsubmarine"), []byte("ayellowsubmarine"), make([]byte, 47))
	f.Add([]byte("ayellowsubmarine"), []byte("ayellowsubmarine"), make([]byte, 63))
	f.Fuzz(func(t *testing.T, key, iv, plaintext []byte) {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			t.SkipNow()
		}

		if len(iv) != aes.BlockSize {
			t.SkipNow()
		}

		got := make([]byte, len(plaintext))
		aes.CTR(key, iv, got, plaintext)

		block, err := stdlibaes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		want := make([]byte, len(plaintext))
		ctr := cipher.NewCTR(block, iv)
		ctr.XORKeyStream(want, plaintext)

		if !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
	})
}
