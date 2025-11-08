package tuplehash_test

import (
	"bytes"
	"testing"

	"github.com/codahale/lockstitch-go/internal/tuplehash"
)

func TestLeftEncode(t *testing.T) {
	t.Parallel()

	if got, want := tuplehash.LeftEncode(0), []byte{1, 0}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.LeftEncode(0) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.LeftEncode(128), []byte{1, 128}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.LeftEncode(128) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.LeftEncode(65536), []byte{3, 1, 0, 0}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.LeftEncode(65536) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.LeftEncode(4096), []byte{2, 16, 0}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.LeftEncode(4096) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.LeftEncode(18446744073709551615), []byte{8, 255, 255, 255, 255, 255, 255, 255, 255}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.LeftEncode(18446744073709551615) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.LeftEncode(12345), []byte{2, 48, 57}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.LeftEncode(12345) = %v, want = %v", got, want)
	}
}

func TestRightEncode(t *testing.T) {
	t.Parallel()

	if got, want := tuplehash.RightEncode(0), []byte{0, 1}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.RightEncode(0) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.RightEncode(128), []byte{128, 1}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.RightEncode(128) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.RightEncode(65536), []byte{1, 0, 0, 3}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.RightEncode(65536) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.RightEncode(4096), []byte{16, 0, 2}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.RightEncode(4096) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.RightEncode(18446744073709551615), []byte{255, 255, 255, 255, 255, 255, 255, 255, 8}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.RightEncode(18446744073709551615) = %v, want = %v", got, want)
	}

	if got, want := tuplehash.RightEncode(12345), []byte{48, 57, 2}; !bytes.Equal(got, want) {
		t.Errorf("tuplehash.RightEncode(12345) = %v, want = %v", got, want)
	}
}

func FuzzLeftEncode(f *testing.F) {
	f.Add(uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, a uint64, b uint64) {
		ab := tuplehash.LeftEncode(a)
		bb := tuplehash.LeftEncode(b)

		if a == b && !bytes.Equal(ab, bb) {
			t.Errorf("tuplehash.LeftEncode(%v) = %v, tuplehash.LeftEncode(%v) = %v", a, ab, b, bb)
		} else if a != b && bytes.Equal(ab, bb) {
			t.Errorf("tuplehash.LeftEncode(%v) = tuplehash.LeftEncode(%v) = %v", a, b, ab)
		}
	})
}

func FuzzRightEncode(f *testing.F) {
	f.Add(uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, a uint64, b uint64) {
		ab := tuplehash.RightEncode(a)
		bb := tuplehash.RightEncode(b)

		if a == b && !bytes.Equal(ab, bb) {
			t.Errorf("tuplehash.RightEncode(%v) = %v, tuplehash.RightEncode(%v) = %v", a, ab, b, bb)
		} else if a != b && bytes.Equal(ab, bb) {
			t.Errorf("tuplehash.RightEncode(%v) = tuplehash.RightEncode(%v) = %v", a, b, ab)
		}
	})
}
