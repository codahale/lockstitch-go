package lockstitch

import (
	"bytes"
	"testing"
)

func FuzzStream(f *testing.F) {
	encrypt := func(key []byte, nonce []byte, message []byte) []byte {
		protocol := NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Encrypt("message", message[:0], message)
	}

	decrypt := func(key []byte, nonce []byte, message []byte) []byte {
		protocol := NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Decrypt("message", message[:0], message)
	}

	f.Add([]byte("yellow submarine"), []byte("12345678"), []byte("hello world"))
	f.Fuzz(func(t *testing.T, key []byte, nonce []byte, message []byte) {
		ciphertext := encrypt(key, nonce, message)
		if got, want := decrypt(key, nonce, ciphertext), message; !bytes.Equal(got, want) {
			t.Errorf("decrypt(key, nonce, ciphertext) = %v, want = %v", got, want)
		}
	})
}

func FuzzAEAD(f *testing.F) {
	encrypt := func(key []byte, nonce []byte, message []byte) []byte {
		protocol := NewProtocol("aead")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Seal("message", nil, message)
	}

	decrypt := func(key []byte, nonce []byte, message []byte) ([]byte, error) {
		protocol := NewProtocol("aead")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Open("message", nil, message)
	}

	f.Add([]byte("yellow submarine"), []byte("12345678"), []byte("hello world"), uint(2), byte(100))
	f.Fuzz(func(t *testing.T, key []byte, nonce []byte, plaintext []byte, idx uint, mask byte) {
		if mask == 0 {
			t.Skip()
		}

		c := encrypt(key, nonce, plaintext)

		// check for decryption of authentic ciphertext
		p2, err := decrypt(key, nonce, c)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := p2, plaintext; !bytes.Equal(got, want) {
			t.Errorf("decrypt(key, nonce, c) = %v, want = %v", got, want)
		}

		// check for non-decryption of inauthentic ciphertext
		c[int(idx)%len(c)] ^= mask

		if got, err := decrypt(key, nonce, c); err == nil {
			t.Errorf("decrypt(key, nonce, c) = %v, want = nil", got)
		}
	})
}
