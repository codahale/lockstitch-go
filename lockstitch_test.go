package lockstitch

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

func TestDeriveZeroOutputs(t *testing.T) {
	zero := make([]byte, 10)
	p1 := NewProtocol("example")
	zeroed := p1.Derive("test", zero[:0], 10)

	nonZero := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	p2 := NewProtocol("example")
	nonZeroed := p2.Derive("test", nonZero[:0], 10)

	if !bytes.Equal(zeroed, nonZeroed) {
		t.Errorf("expected %v but was %v", zeroed, nonZeroed)
	}
}

func TestDeriveArgValidation(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	p := NewProtocol("example")
	p.Derive("test", nil, -200)
}

func TestKnownAnswers(t *testing.T) {
	protocol := NewProtocol("com.example.kat")
	protocol.Mix("first", []byte("one"))
	protocol.Mix("second", []byte("two"))

	if expected, actual := "f30a3c4582cf74b5", hex.EncodeToString(protocol.Derive("third", nil, 8)); expected != actual {
		t.Errorf("Derive output mismatch, expected %v, got %v", expected, actual)
	}

	plaintext := []byte("this is an example")
	ciphertext := protocol.Encrypt("fourth", nil, plaintext)
	if expected, actual := "cbc0743dbcd23d85d16221fc94ae677d29d9", hex.EncodeToString(ciphertext); expected != actual {
		t.Errorf("Encrypt output mismatch, expected %v, got %v", expected, actual)
	}

	ciphertext = protocol.Seal("fifth", nil, []byte("this is an example"))
	if expected, actual := "b965f961fb66a2e03287c1517e6ae3d1fb273e136cafca4382f78752f19717571087", hex.EncodeToString(ciphertext); expected != actual {
		t.Errorf("Seal output mismatch, expected %v, got %v", expected, actual)
	}

	if expected, actual := "e11c63100f03f2bb", hex.EncodeToString(protocol.Derive("sixth", nil, 8)); expected != actual {
		t.Errorf("DeriveSlice output mismatch, expected %v, got %v", expected, actual)
	}
}

func TestLeftEncode(t *testing.T) {
	if expected, actual := []byte{1, 0}, leftEncode(0); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	if expected, actual := []byte{1, 128}, leftEncode(128); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	if expected, actual := []byte{3, 1, 0, 0}, leftEncode(65536); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	if expected, actual := []byte{2, 16, 0}, leftEncode(4096); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	if expected, actual := []byte{8, 255, 255, 255, 255, 255, 255, 255, 255}, leftEncode(18446744073709551615); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	if expected, actual := []byte{2, 48, 57}, leftEncode(12345); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}
}

func TestMixAndMixWriter(t *testing.T) {
	a := NewProtocol("test")
	a.Mix("one", []byte("111"))
	a.Mix("two", []byte("222"))
	ad := a.Derive("three", nil, 8)

	b := NewProtocol("test")

	b1 := new(bytes.Buffer)
	w1 := b.MixWriter("one", b1)
	_, _ = w1.Write([]byte("1"))
	_, _ = w1.Write([]byte("1"))
	_, _ = w1.Write([]byte("1"))
	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}
	if expected, actual := []byte("111"), b1.Bytes(); !bytes.Equal(expected, actual) {
		t.Errorf("expected write of %v but was %v", expected, actual)
	}
	b2 := new(bytes.Buffer)
	w2 := b.MixWriter("two", b2)
	_, _ = w2.Write([]byte("2"))
	_, _ = w2.Write([]byte("2"))
	_, _ = w2.Write([]byte("2"))
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if expected, actual := []byte("222"), b2.Bytes(); !bytes.Equal(expected, actual) {
		t.Errorf("expected write of %v but was %v", expected, actual)
	}

	bd := b.Derive("three", nil, 8)

	if !bytes.Equal(ad, bd) {
		t.Errorf("expected %v but was %v", ad, bd)
	}
}

func TestMixAndMixReader(t *testing.T) {
	a := NewProtocol("test")
	a.Mix("one", []byte("111"))
	a.Mix("two", []byte("222"))
	ad := a.Derive("three", nil, 8)

	b := NewProtocol("test")
	r1 := b.MixReader("one", bytes.NewReader([]byte("111")))
	b1 := new(bytes.Buffer)
	if _, err := io.Copy(b1, r1); err != nil {
		t.Fatal(err)
	}
	if err := r1.Close(); err != nil {
		t.Fatal(err)
	}
	if expected, actual := []byte("111"), b1.Bytes(); !bytes.Equal(expected, actual) {
		t.Errorf("expected write of %v but was %v", expected, actual)
	}

	r2 := b.MixReader("two", bytes.NewReader([]byte("222")))
	b2 := new(bytes.Buffer)
	if _, err := io.Copy(b2, r2); err != nil {
		t.Fatal(err)
	}
	if err := r2.Close(); err != nil {
		t.Fatal(err)
	}
	if expected, actual := []byte("222"), b2.Bytes(); !bytes.Equal(expected, actual) {
		t.Errorf("expected write of %v but was %v", expected, actual)
	}

	bd := b.Derive("three", nil, 8)

	if !bytes.Equal(ad, bd) {
		t.Errorf("expected %v but was %v", ad, bd)
	}
}

func FuzzLeftEncode(f *testing.F) {
	f.Add(uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, a uint64, b uint64) {
		ab := leftEncode(a)
		bb := leftEncode(b)

		if a == b && !bytes.Equal(ab, bb) {
			t.Errorf("%v encoded to both %v and %v", a, ab, bb)
		} else if a != b && bytes.Equal(ab, bb) {
			t.Errorf("%v and %v both encoded to %v", a, b, ab)
		}
	})
}
