package lockstitch

import (
	"bytes"
	"encoding/hex"
	"testing"
)

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
	if expected, actual := "94a54f24929bc03442d3f9945a34777dfff76ed2bb4e0e9b3e15608fefde7ef9fc51", hex.EncodeToString(ciphertext); expected != actual {
		t.Errorf("Seal output mismatch, expected %v, got %v", expected, actual)
	}

	if expected, actual := "61e6981b6849c5e6", hex.EncodeToString(protocol.Derive("sixth", nil, 8)); expected != actual {
		t.Errorf("DeriveSlice output mismatch, expected %v, got %v", expected, actual)
	}
}

func TestLeftEncode(t *testing.T) {
	buf := new(bytes.Buffer)
	leftEncode(buf, 0)
	if expected, actual := []byte{1, 0}, buf.Bytes(); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	buf.Reset()
	leftEncode(buf, 128)
	if expected, actual := []byte{1, 128}, buf.Bytes(); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	buf.Reset()
	leftEncode(buf, 65536)
	if expected, actual := []byte{3, 1, 0, 0}, buf.Bytes(); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	buf.Reset()
	leftEncode(buf, 4096)
	if expected, actual := []byte{2, 16, 0}, buf.Bytes(); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	buf.Reset()
	leftEncode(buf, 18446744073709551615)
	if expected, actual := []byte{8, 255, 255, 255, 255, 255, 255, 255, 255}, buf.Bytes(); !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}

	buf.Reset()
	leftEncode(buf, 12345)
	if expected, actual := []byte{2, 48, 57}, buf.Bytes(); !bytes.Equal(expected, actual) {
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

func FuzzLeftEncode(f *testing.F) {
	f.Add(uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, a uint64, b uint64) {
		ab := new(bytes.Buffer)
		leftEncode(ab, a)

		bb := new(bytes.Buffer)
		leftEncode(bb, b)

		if a == b && !bytes.Equal(ab.Bytes(), bb.Bytes()) {
			t.Errorf("%v encoded to both %v and %v", a, ab.Bytes(), bb.Bytes())
		} else if a != b && bytes.Equal(ab.Bytes(), bb.Bytes()) {
			t.Errorf("%v and %v both encoded to %v", a, b, ab.Bytes())
		}
	})
}
