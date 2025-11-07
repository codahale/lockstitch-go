package lockstitch

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestProtocol_Clone(t *testing.T) {
	t.Parallel()

	p1 := NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))
	p2 := p1.Clone()

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestProtocol_MarshalBinary(t *testing.T) {
	p1 := NewProtocol("example")
	p1.Mix("a thing", []byte("another thing"))

	state, err := p1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	p2 := NewProtocol("example")
	if err := p2.UnmarshalBinary(state); err != nil {
		t.Fatal(err)
	}

	if got, want := p2.Derive("third", nil, 8), p1.Derive("third", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('third') = %x, want = %x", got, want)
	}
}

func TestDeriveZeroOutputs(t *testing.T) {
	t.Parallel()

	zero := make([]byte, 10)
	nonZero := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

	p1 := NewProtocol("example")
	p2 := NewProtocol("example")

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

	p := NewProtocol("example")
	p.Derive("test", nil, -200)
}

func TestKnownAnswers(t *testing.T) {
	t.Parallel()

	protocol := NewProtocol("com.example.kat")
	protocol.Mix("first", []byte("one"))
	protocol.Mix("second", []byte("two"))

	if got, want := hex.EncodeToString(protocol.Derive("third", nil, 8)), "d86a504bc828ae8d"; got != want {
		t.Errorf("Derive('third') = %v, want = %v", got, want)
	}

	plaintext := []byte("this is an example")
	ciphertext := protocol.Encrypt("fourth", nil, plaintext)
	if got, want := hex.EncodeToString(ciphertext), "0016a9cb4c654a4320e38bc6b3a223e2e0ad"; got != want {
		t.Errorf("Encrypt('fourth') = %v, want = %v", got, want)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if got, want := hex.EncodeToString(ciphertext), "51adbe3def07d055007c93294be00660715eae236004f4c473716c3a64547029393b"; got != want {
		t.Errorf("Seal('fifth') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(protocol.Derive("sixth", nil, 8)), "ed30730274b01b0f"; got != want {
		t.Errorf("Derive('sixth') = %v, want = %v", got, want)
	}
}

func TestLeftEncode(t *testing.T) {
	t.Parallel()

	if got, want := leftEncode(0), []byte{1, 0}; !bytes.Equal(got, want) {
		t.Errorf("leftEncode(0) = %v, want = %v", got, want)
	}

	if got, want := leftEncode(128), []byte{1, 128}; !bytes.Equal(got, want) {
		t.Errorf("leftEncode(128) = %v, want = %v", got, want)
	}

	if got, want := leftEncode(65536), []byte{3, 1, 0, 0}; !bytes.Equal(got, want) {
		t.Errorf("leftEncode(65536) = %v, want = %v", got, want)
	}

	if got, want := leftEncode(4096), []byte{2, 16, 0}; !bytes.Equal(got, want) {
		t.Errorf("leftEncode(4096) = %v, want = %v", got, want)
	}

	if got, want := leftEncode(18446744073709551615), []byte{8, 255, 255, 255, 255, 255, 255, 255, 255}; !bytes.Equal(got, want) {
		t.Errorf("leftEncode(18446744073709551615) = %v, want = %v", got, want)
	}

	if got, want := leftEncode(12345), []byte{2, 48, 57}; !bytes.Equal(got, want) {
		t.Errorf("leftEncode(12345) = %v, want = %v", got, want)
	}
}

func TestRightEncode(t *testing.T) {
	t.Parallel()

	if got, want := rightEncode(0), []byte{0, 1}; !bytes.Equal(got, want) {
		t.Errorf("rightEncode(0) = %v, want = %v", got, want)
	}

	if got, want := rightEncode(128), []byte{128, 1}; !bytes.Equal(got, want) {
		t.Errorf("rightEncode(128) = %v, want = %v", got, want)
	}

	if got, want := rightEncode(65536), []byte{1, 0, 0, 3}; !bytes.Equal(got, want) {
		t.Errorf("rightEncode(65536) = %v, want = %v", got, want)
	}

	if got, want := rightEncode(4096), []byte{16, 0, 2}; !bytes.Equal(got, want) {
		t.Errorf("rightEncode(4096) = %v, want = %v", got, want)
	}

	if got, want := rightEncode(18446744073709551615), []byte{255, 255, 255, 255, 255, 255, 255, 255, 8}; !bytes.Equal(got, want) {
		t.Errorf("rightEncode(18446744073709551615) = %v, want = %v", got, want)
	}

	if got, want := rightEncode(12345), []byte{48, 57, 2}; !bytes.Equal(got, want) {
		t.Errorf("rightEncode(12345) = %v, want = %v", got, want)
	}
}

func FuzzLeftEncode(f *testing.F) {
	f.Add(uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, a uint64, b uint64) {
		ab := leftEncode(a)
		bb := leftEncode(b)

		if a == b && !bytes.Equal(ab, bb) {
			t.Errorf("leftEncode(%v) = %v, leftEncode(%v) = %v", a, ab, b, bb)
		} else if a != b && bytes.Equal(ab, bb) {
			t.Errorf("leftEncode(%v) = leftEncode(%v) = %v", a, b, ab)
		}
	})
}

func FuzzRightEncode(f *testing.F) {
	f.Add(uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, a uint64, b uint64) {
		ab := rightEncode(a)
		bb := rightEncode(b)

		if a == b && !bytes.Equal(ab, bb) {
			t.Errorf("rightEncode(%v) = %v, rightEncode(%v) = %v", a, ab, b, bb)
		} else if a != b && bytes.Equal(ab, bb) {
			t.Errorf("rightEncode(%v) = rightEncode(%v) = %v", a, b, ab)
		}
	})
}
