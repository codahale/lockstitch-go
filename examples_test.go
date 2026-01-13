package lockstitch_test

import (
	"fmt"

	"github.com/codahale/lockstitch-go"
)

func ExampleProtocol_mac() {
	// Initialize a protocol with a domain string.
	mac := lockstitch.NewProtocol("com.example.mac")

	// Mix the key into the protocol.
	key := []byte("my-secret-key")
	mac.Mix("key", key)

	// Mix the message into the protocol.
	message := []byte("hello world")
	mac.Mix("message", message)

	// Derive 16 bytes of output.
	// Note: The output length (128 bits) is encoded into the derivation, so
	// changing the length will change the output.
	tag := mac.Derive("tag", nil, 16)

	fmt.Printf("%x\n", tag)
	// Output: 8072172e62079021ab8cdb8834071584
}

func ExampleProtocol_stream() {
	var ciphertext, nonce []byte
	{
		// Initialize a protocol with a domain string.
		stream := lockstitch.NewProtocol("com.example.stream")

		// Mix the key into the protocol.
		key := []byte("my-secret-key")
		stream.Mix("key", key)

		// Mix a nonce into the protocol.
		nonce = []byte("actually random")
		stream.Mix("nonce", nonce)

		// Encrypt the plaintext.
		plaintext := []byte("hello world")
		ciphertext = stream.Encrypt("message", nil, plaintext)
		fmt.Printf("%x\n", ciphertext)
	}

	{
		// Initialize a protocol with a domain string.
		stream := lockstitch.NewProtocol("com.example.stream")

		// Mix the key into the protocol.
		key := []byte("my-secret-key")
		stream.Mix("key", key)

		// Mix a nonce into the protocol.
		nonce = []byte("actually random")
		stream.Mix("nonce", nonce)

		// Decrypt the ciphertext.
		plaintext := stream.Decrypt("message", nil, ciphertext)
		fmt.Printf("%s\n", plaintext)
	}

	// Output:
	// 342bcef28cbd46ac1b3cbc
	// hello world
}

func ExampleProtocol_aead() {
	var ciphertext []byte
	{
		// Initialize a protocol with a domain string.
		aead := lockstitch.NewProtocol("com.example.aead")

		// Mix the key into the protocol.
		key := []byte("my-secret-key")
		aead.Mix("key", key)

		// Mix the authenticated data into the protocol.
		ad := []byte("some authenticated data")
		aead.Mix("ad", ad)

		// Seal the plaintext.
		plaintext := []byte("hello world")
		ciphertext = aead.Seal("message", nil, plaintext)
		fmt.Printf("%x\n", ciphertext)
	}

	{
		// Initialize a protocol with a domain string.
		aead := lockstitch.NewProtocol("com.example.aead")

		// Mix the key into the protocol.
		key := []byte("my-secret-key")
		aead.Mix("key", key)

		// Mix the authenticated data into the protocol.
		ad := []byte("some authenticated data")
		aead.Mix("ad", ad)

		// Open the ciphertext.
		plaintext, err := aead.Open("message", nil, ciphertext)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", plaintext)
	}

	// Output:
	// fd58696cf39e4f44138a22a6ebaa374b6fe00fe0bce5f59e501d70
	// hello world
}
