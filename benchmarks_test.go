package lockstitch

import (
	"io"
	"testing"
)

func BenchmarkHash(b *testing.B) {
	hash := func(message []byte) []byte {
		protocol := NewProtocol("hash")
		protocol.Mix("message", message)
		return protocol.DeriveSlice("digest", 32)
	}

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			input := make([]byte, length.n)
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				hash(input)
			}
		})
	}
}

func BenchmarkHashWriter(b *testing.B) {
	hash := func(message []byte) []byte {
		protocol := NewProtocol("hash")
		w := protocol.MixWriter("message", io.Discard)
		_, _ = w.Write(message)
		_ = w.Close()
		return protocol.DeriveSlice("digest", 32)
	}

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			input := make([]byte, length.n)
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				hash(input)
			}
		})
	}
}

func BenchmarkPRF(b *testing.B) {
	key := make([]byte, 32)
	prf := func(output []byte) {
		protocol := NewProtocol("prf")
		protocol.Mix("key", key)
		protocol.Derive("output", output)
	}

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			output := make([]byte, length.n)
			b.SetBytes(int64(len(output)))
			for b.Loop() {
				prf(output)
			}
		})
	}
}

func BenchmarkStream(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	stream := func(message []byte) {
		protocol := NewProtocol("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		protocol.Encrypt("message", message)
	}

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			output := make([]byte, length.n)
			b.SetBytes(int64(len(output)))
			for b.Loop() {
				stream(output)
			}
		})
	}
}

func BenchmarkAEAD(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	ad := make([]byte, 32)
	aead := func(message []byte) {
		protocol := NewProtocol("aead")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		protocol.Mix("ad", ad)
		protocol.Seal("message", message)
	}

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			output := make([]byte, length.n+TAG_LEN)
			b.SetBytes(int64(len(output)))
			for b.Loop() {
				aead(output)
			}
		})
	}
}

var lengths []struct {
	name string
	n    int
} = []struct {
	name string
	n    int
}{
	{"16B", 16},
	{"256B", 256},
	{"1KiB", 1024},
	{"16KiB", 16 * 1024},
	{"1MiB", 1024 * 1024},
}
