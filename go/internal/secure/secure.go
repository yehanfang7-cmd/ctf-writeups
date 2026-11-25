// Package secure provides runtime decryption of the ciphertext blobs emitted by
// tools/securegen. It implements layer 3 of the hardening spec: a custom
// AES-GCM scheme that is independent of garble's -literals, so that
// scheme-specific recovery tools (e.g. GoStringUngarbler) do not apply.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"

	"sentinel/internal/secure/keymix"
)

// ErrDecrypt is returned (silently, by callers) when a blob fails to open. We
// never surface the underlying crypto error to avoid handing an analyst a
// semantic breadcrumb.
var ErrDecrypt = errors.New("x") // intentionally opaque

// Open decrypts a base64-encoded (nonce||ciphertext||tag) blob using the master
// key derived from the per-build fragment fragB. The returned slice is a fresh
// allocation the caller owns and SHOULD Wipe when done.
func Open(blob string, fragB []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, ErrDecrypt
	}
	key := keymix.Derive(fragB)
	block, err := aes.NewCipher(key[:])
	wipe(key[:])
	if err != nil {
		return nil, ErrDecrypt
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecrypt
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, ErrDecrypt
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// With decrypts blob, hands the plaintext to fn, then wipes it before returning.
// This is the preferred path for short-lived secrets (layer 3 requirement:
// "解密後的明文不要長期停留在記憶體, 用完即清"). The byte slice passed to fn is
// invalid after fn returns.
func With(blob string, fragB []byte, fn func([]byte)) error {
	pt, err := Open(blob, fragB)
	if err != nil {
		return err
	}
	defer wipe(pt)
	fn(pt)
	return nil
}

// String is a convenience that returns the plaintext as a Go string. Because a
// string cannot be wiped, only use this for values that are not secret by
// themselves (e.g. a non-sensitive label). Prefer With for real secrets.
func String(blob string, fragB []byte) string {
	pt, err := Open(blob, fragB)
	if err != nil {
		return ""
	}
	s := string(pt)
	wipe(pt)
	return s
}

// wipe overwrites b with zeros. Marked go:noinline so an optimizer is less
// likely to elide the "dead" store.
//
//go:noinline
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
