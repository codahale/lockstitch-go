package lockstitch_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codahale/lockstitch-go"
)

func TestProtocol_Clone(t *testing.T) {
	t.Parallel()

	p1 := lockstitch.NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))
	p2 := p1.Clone()

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_MarshalBinary(t *testing.T) {
	p1 := lockstitch.NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))

	state, err := p1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	p2 := lockstitch.NewProtocol("counter-example")
	if err := p2.UnmarshalBinary(state); err != nil {
		t.Fatal(err)
	}

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_AppendBinary(t *testing.T) {
	p1 := lockstitch.NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))

	got, err := p1.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}

	want, err := p1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("AppendBinary = %x, want %x", got, want)
	}
}

func TestDeriveZeroOutputs(t *testing.T) {
	t.Parallel()

	zero := make([]byte, 10)
	nonZero := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

	p1 := lockstitch.NewProtocol("example")
	p2 := lockstitch.NewProtocol("example")

	if got, want := p1.Derive("test", nonZero[:0], 10), p2.Derive("test", zero[:0], 10); !bytes.Equal(got, want) {
		t.Errorf("Derive(nonZero) = %x, want = %x", got, want)
	}
}

func TestDeriveArgValidation(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	p := lockstitch.NewProtocol("example")
	p.Derive("test", nil, -200)
}

func TestDeriveKnownAnswers(t *testing.T) {
	t.Parallel()

	p := lockstitch.NewProtocol("example")

	if got, want := hex.EncodeToString(p.Derive("one", nil, 8)), "fad28d904759995e"; got != want {
		t.Errorf("Derive('one') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(p.Derive("two", nil, 15)), "cff3483ac9653bf6c0cc8bd4d80454"; got != want {
		t.Errorf("Derive('two') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(p.Derive("three", nil, 31)), "16c235e9161aa7e8710c6562f4775266c2d12a17ce1d2652ab5fdc2d621654"; got != want {
		t.Errorf("Derive('three') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(p.Derive("four", nil, 63)), "774f34cb5e907663c5bdd3f45c5d53087c31f28ca7d9346fcca61f562d1d8d80d5169b284fd7bea645905c81cf4a1b0afe28e05207c64cb8b7a25494c879cf"; got != want {
		t.Errorf("Derive('four') = %v, want = %v", got, want)
	}
}

func TestKnownAnswers(t *testing.T) {
	t.Parallel()

	protocol := lockstitch.NewProtocol("com.example.kat")
	protocol.Mix("first", []byte("one"))
	protocol.Mix("second", []byte("two"))

	if got, want := hex.EncodeToString(protocol.Derive("third", nil, 8)), "94817feeb041f907"; got != want {
		t.Errorf("Derive('third') = %v, want = %v", got, want)
	}

	plaintext := []byte("this is an example")
	ciphertext := protocol.Encrypt("fourth", nil, plaintext)
	if got, want := hex.EncodeToString(ciphertext), "cd7a6d51699ae237dc2ef5a91d3a39639b34"; got != want {
		t.Errorf("Encrypt('fourth') = %v, want = %v", got, want)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if got, want := hex.EncodeToString(ciphertext), "659ef429e2680fbaf02a0702928d9600f10efcb90a124c2e040ea52901c8f8650634"; got != want {
		t.Errorf("Seal('fifth') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(protocol.Derive("sixth", nil, 8)), "cb0ec90e45f6eeff"; got != want {
		t.Errorf("Derive('sixth') = %v, want = %v", got, want)
	}
}
