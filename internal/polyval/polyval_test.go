package polyval_test

import (
	"bytes"
	"testing"

	"github.com/codahale/lockstitch-go/internal/polyval"
)

func FuzzAuthenticator(f *testing.F) {
	f.Add([]byte("ayellowsubmarine"), []byte("0123456789012345"), []byte{1, 2, 3}, []byte{1, 2, 4})
	f.Fuzz(func(t *testing.T, keyA, keyB, msgA, msgB []byte) {
		if len(keyA) != 16 || len(keyB) != 16 ||
			len(msgA) == 0 || len(msgB) == 0 ||
			bytes.Equal(keyA, make([]byte, 16)) ||
			bytes.Equal(keyB, make([]byte, 16)) ||
			bytes.Equal(keyA, keyB) || bytes.Equal(msgA, msgB) {
			t.Skip()
		}

		authAA := polyval.Authenticator(keyA, msgA)
		authAB := polyval.Authenticator(keyA, msgB)
		authBA := polyval.Authenticator(keyB, msgA)

		if bytes.Equal(authAA[:], authAB[:]) {
			t.Error("same key, different messages, same authenticator")
		}

		if bytes.Equal(authAA[:], authBA[:]) {
			t.Log(keyA, keyB, msgA)
			t.Error("different keys, same message, same authenticator")
		}
	})
}
