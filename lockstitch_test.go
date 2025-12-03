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

	if got, want := hex.EncodeToString(p.Derive("two", nil, 15)), "191574900fc0b154f23a5d4c23717a"; got != want {
		t.Errorf("Derive('two') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(p.Derive("three", nil, 31)), "5d6858f03d001b6f68784aece8b8fa5bb0f3444b26c1730ca4e87001f7a7b1"; got != want {
		t.Errorf("Derive('three') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(p.Derive("four", nil, 63)), "4b0fab3c6c25620a3ef86fb94ae6c22e4c9b5cef1deecf6df5a8aa95c4aa610adf9e75ddaac582e6eb1bceccbd8a4f1556edd10deff0cf48c81317e675b1e5"; got != want {
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
	if got, want := hex.EncodeToString(ciphertext), "34830931d97c14b4b4a5dd2093429347aeb6"; got != want {
		t.Errorf("Encrypt('fourth') = %v, want = %v", got, want)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if got, want := hex.EncodeToString(ciphertext), "76bef04c2d274072f84e52867c347783aa489041b8936ca27e0f30b5181f1def3879"; got != want {
		t.Errorf("Seal('fifth') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(protocol.Derive("sixth", nil, 8)), "d95ee73d86687616"; got != want {
		t.Errorf("Derive('sixth') = %v, want = %v", got, want)
	}
}
