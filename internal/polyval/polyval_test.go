package polyval_test

import (
	"bytes"
	"testing"

	"github.com/codahale/lockstitch-go/internal/polyval"
)

func FuzzAuthenticator(f *testing.F) {
	f.Add([]byte("ayellowsubmarine"), []byte{1, 2, 3}, []byte{1, 2, 4})
	f.Fuzz(func(t *testing.T, key, msgA, msgB []byte) {
		if len(key) != 16 {
			t.Skip()
		}

		if bytes.Equal(key, make([]byte, 16)) {
			t.Skip()
		}

		authA := polyval.Authenticator(nil, key, msgA)
		authB := polyval.Authenticator(nil, key, msgB)
		if bytes.Equal(msgA, msgB) != bytes.Equal(authA, authB) {
			t.Error("message/authenticator equality mismatch")
		}
	})
}
