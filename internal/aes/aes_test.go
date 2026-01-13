package aes_test

import (
	"bytes"
	stdlibaes "crypto/aes"
	"crypto/cipher"
	"crypto/sha3"
	"testing"

	"github.com/codahale/lockstitch-go/internal/aes"
)

func TestGMAC(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	data := []byte("hello world")

	tag := aes.GMAC(key, nil, data)

	block, err := stdlibaes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	got, err := gcm.Open(nil, nonce, tag, data)
	if err != nil {
		t.Fatal(err)
	}

	if want := []byte{}; !bytes.Equal(got, want) {
		t.Errorf("GCM(GMAC()) = %x, want %x", tag, got)
	}
}

func TestCTR_InvalidKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("CTR(15 byte key) should have failed")
		}
	}()

	key := make([]byte, 15) // Invalid key size
	aes.CTR(key, make([]byte, 16), nil, nil)
}

func TestGMAC_InvalidKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("GMAC(15 byte key) should have failed")
		}
	}()

	key := make([]byte, 15) // Invalid key size
	aes.GMAC(key, nil, nil)
}

func FuzzCTR(f *testing.F) {
	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("lockstitch ctr implementation"))

	for _, length := range lengths {
		key := make([]byte, 16)
		iv := make([]byte, aes.BlockSize)
		plaintext := make([]byte, length.n)
		_, _ = drbg.Read(key)
		_, _ = drbg.Read(iv)
		_, _ = drbg.Read(plaintext)
		f.Add(key, iv, plaintext)
	}

	f.Fuzz(func(t *testing.T, key, iv, plaintext []byte) {
		if len(key) != 16 || len(iv) != aes.BlockSize {
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

func BenchmarkCTR(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			msg := make([]byte, length.n)
			b.SetBytes(int64(length.n))
			b.ReportAllocs()
			for b.Loop() {
				aes.CTR(key, iv, msg, msg)
			}
		})
	}
}

//nolint:gochecknoglobals // this is fine
var lengths = []struct {
	name string
	n    int
}{
	{"16B", 16},
	{"32B", 32},
	{"64B", 64},
	{"128B", 128},
	{"256B", 256},
	{"512B", 512},
	{"1KiB", 1024},
	{"2KiB", 2048},
}
