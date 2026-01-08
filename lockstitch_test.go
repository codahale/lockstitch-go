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

func TestKnownAnswers(t *testing.T) {
	t.Parallel()

	protocol := lockstitch.NewProtocol("com.example.kat")
	protocol.Mix("first", []byte("one"))
	protocol.Mix("second", []byte("two"))

	if got, want := hex.EncodeToString(protocol.Derive("third", nil, 8)), "1b1eb6c50b7a0efa"; got != want {
		t.Errorf("Derive('third') = %v, want = %v", got, want)
	}

	plaintext := []byte("this is an example")
	ciphertext := protocol.Encrypt("fourth", nil, plaintext)
	if got, want := hex.EncodeToString(ciphertext), "db1daa1bc9483166afc66e64e5ea755551a1"; got != want {
		t.Errorf("Encrypt('fourth') = %v, want = %v", got, want)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if got, want := hex.EncodeToString(
		ciphertext,
	), "d02f72467272779eedff51ffd875d6a4c45537b38d3d56868af3acdb81c22e2fcd24"; got != want {
		t.Errorf("Seal('fifth') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(protocol.Derive("sixth", nil, 8)), "04d8a4b236e5e7db"; got != want {
		t.Errorf("Derive('sixth') = %v, want = %v", got, want)
	}
}
