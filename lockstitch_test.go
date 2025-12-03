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

	if got, want := hex.EncodeToString(p.Derive("one", nil, 8)), "3b082931bc889539"; got != want {
		t.Errorf("Derive('one') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(p.Derive("two", nil, 15)), "1292c630bfd29155c6f85be8c24c22"; got != want {
		t.Errorf("Derive('two') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(p.Derive("three", nil, 31)), "87e7a2f746b87e3dcb8a4a78b41f74d2996a9e8d08132a04ef9224138f1051"; got != want {
		t.Errorf("Derive('three') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(p.Derive("four", nil, 63)), "140e01e3fe122a2a28e832d742b0091cf9d94c4463b173f07c028240f469984f6aa35310a9b4abfd2ab3b63daeaff7666bb1f87509b1bdf506bfd1f721a79d"; got != want {
		t.Errorf("Derive('four') = %v, want = %v", got, want)
	}
}

func TestKnownAnswers(t *testing.T) {
	t.Parallel()

	protocol := lockstitch.NewProtocol("com.example.kat")
	protocol.Mix("first", []byte("one"))
	protocol.Mix("second", []byte("two"))

	if got, want := hex.EncodeToString(protocol.Derive("third", nil, 8)), "49639b877ddea480"; got != want {
		t.Errorf("Derive('third') = %v, want = %v", got, want)
	}

	plaintext := []byte("this is an example")
	ciphertext := protocol.Encrypt("fourth", nil, plaintext)
	if got, want := hex.EncodeToString(ciphertext), "14a97bb7d4988161cdd0787d8524dc6734ab"; got != want {
		t.Errorf("Encrypt('fourth') = %v, want = %v", got, want)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if got, want := hex.EncodeToString(ciphertext), "99877f3c1272c42729718d8a78bd69562ba0be48c997d6c865319ad946072ae4ff74"; got != want {
		t.Errorf("Seal('fifth') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(protocol.Derive("sixth", nil, 8)), "972317ec8f477321"; got != want {
		t.Errorf("Derive('sixth') = %v, want = %v", got, want)
	}
}
