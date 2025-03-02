package lockstitch

import (
	"bytes"
	"slices"
	"testing"
)

func FuzzStream(f *testing.F) {
	encrypt := func(key []byte, nonce []byte, message []byte) {
		protocol := NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		protocol.Encrypt("message", message)
	}

	decrypt := func(key []byte, nonce []byte, message []byte) {
		protocol := NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		protocol.Decrypt("message", message)
	}

	f.Add([]byte("yellow submarine"), []byte("12345678"), []byte("hello world"))
	f.Fuzz(func(t *testing.T, key []byte, nonce []byte, message []byte) {
		expected := slices.Clone(message)
		encrypt(key, nonce, message)
		decrypt(key, nonce, message)
		if !bytes.Equal(expected, message) {
			t.Errorf("failed decryption. expected %v, got %v", expected, message)
		}
	})
}

func FuzzAEAD(f *testing.F) {
	encrypt := func(key []byte, nonce []byte, message []byte) []byte {
		protocol := NewProtocol("aead")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		out := make([]byte, len(message)+TAG_LEN)
		copy(out, message)
		protocol.Seal("message", out)
		return out
	}

	decrypt := func(key []byte, nonce []byte, message []byte) ([]byte, error) {
		protocol := NewProtocol("aead")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Open("message", message)
	}

	f.Add([]byte("yellow submarine"), []byte("12345678"), []byte("hello world"))
	f.Fuzz(func(t *testing.T, key []byte, nonce []byte, plaintext []byte) {
		c := encrypt(key, nonce, plaintext)
		p2, err := decrypt(key, nonce, c)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plaintext, p2) {
			t.Errorf("failed decryption. expected %v, got %v", plaintext, p2)
		}
	})
}
