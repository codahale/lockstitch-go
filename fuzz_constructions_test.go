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
		actual := decrypt(key, nonce, ciphertext)
		if !bytes.Equal(message, actual) {
			t.Errorf("failed decryption. expected %v, got %v", message, actual)
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
