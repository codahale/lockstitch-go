package lockstitch

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
)

func TestSalt(t *testing.T) {
	t.Parallel()

	h := hmac.New(sha256.New, nil)
	h.Write([]byte("lockstitch"))

	if got, want := salt, h.Sum(nil); !bytes.Equal(got, want) {
		t.Errorf("salt = %x, want = %x", got, want)
	}
}

func TestClone(t *testing.T) {
	t.Parallel()

	p1 := NewProtocol("example")
	p2 := p1.Clone()

	if got, want := p2.state, p1.state; !bytes.Equal(got, want) {
		t.Errorf("Clone(state) = %x, want = %x", got, want)
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

	if got, want := hex.EncodeToString(protocol.Derive("third", nil, 8)), "f30a3c4582cf74b5"; got != want {
		t.Errorf("Derive('third') = %v, want = %v", got, want)
	}

	plaintext := []byte("this is an example")
	ciphertext := protocol.Encrypt("fourth", nil, plaintext)
	if got, want := hex.EncodeToString(ciphertext), "cbc0743dbcd23d85d16221fc94ae677d29d9"; got != want {
		t.Errorf("Encrypt('fourth') = %v, want = %v", got, want)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if got, want := hex.EncodeToString(ciphertext), "b965f961fb66a2e03287c1517e6ae3d1fb273e136cafca4382f78752f19717571087"; got != want {
		t.Errorf("Seal('fifth') = %v, want = %v", got, want)
	}

	if got, want := hex.EncodeToString(protocol.Derive("sixth", nil, 8)), "e11c63100f03f2bb"; got != want {
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

func TestMixAndMixWriter(t *testing.T) {
	t.Parallel()

	a := NewProtocol("test")
	a.Mix("one", []byte("111"))
	a.Mix("two", []byte("222"))

	b := NewProtocol("test")

	b1 := new(bytes.Buffer)
	w1 := b.MixWriter("one", b1)
	_, _ = w1.Write([]byte("1"))
	_, _ = w1.Write([]byte("1"))
	_, _ = w1.Write([]byte("1"))
	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := b1.Bytes(), []byte("111"); !bytes.Equal(got, want) {
		t.Errorf("Write('111') = %v, want = %v", got, want)
	}
	b2 := new(bytes.Buffer)
	w2 := b.MixWriter("two", b2)
	_, _ = w2.Write([]byte("2"))
	_, _ = w2.Write([]byte("2"))
	_, _ = w2.Write([]byte("2"))
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := b2.Bytes(), []byte("222"); !bytes.Equal(got, want) {
		t.Errorf("Write('222') = %v, want = %v", got, want)
	}

	if got, want := a.Derive("three", nil, 8), b.Derive("three", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('three') = %x, want = %x", got, want)
	}
}

func TestMixAndMixReader(t *testing.T) {
	t.Parallel()

	a := NewProtocol("test")
	a.Mix("one", []byte("111"))
	a.Mix("two", []byte("222"))

	b := NewProtocol("test")
	r1 := b.MixReader("one", bytes.NewReader([]byte("111")))
	b1 := new(bytes.Buffer)
	if _, err := io.Copy(b1, r1); err != nil {
		t.Fatal(err)
	}
	if err := r1.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := b1.Bytes(), []byte("111"); !bytes.Equal(got, want) {
		t.Errorf("Write('111') = %v, want = %v", got, want)
	}

	r2 := b.MixReader("two", bytes.NewReader([]byte("222")))
	b2 := new(bytes.Buffer)
	if _, err := io.Copy(b2, r2); err != nil {
		t.Fatal(err)
	}
	if err := r2.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := b2.Bytes(), []byte("222"); !bytes.Equal(got, want) {
		t.Errorf("Write('222') = %v, want = %v", got, want)
	}

	if got, want := a.Derive("three", nil, 8), b.Derive("three", nil, 8); !bytes.Equal(got, want) {
		t.Errorf("Derive('three') = %x, want = %x", got, want)
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
