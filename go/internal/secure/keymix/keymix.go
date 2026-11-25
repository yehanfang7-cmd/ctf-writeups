// Package keymix holds the static key fragments and the mixing function used to
// derive the master AES key. It is deliberately standalone so that BOTH the
// runtime decryptor (internal/secure) and the build-time code generator
// (tools/securegen) can derive the identical key without an import cycle.
//
// Security note (see docs/hardening-report.md, layer 3): every fragment present
// here is, by definition, inside the shipped binary and therefore recoverable by
// a determined static analyst. The purpose of this layer is NOT to be unbreakable
// but to (a) defeat scheme-specific tools such as FLARE's GoStringUngarbler, which
// only understand garble's own -literals format, and (b) force bespoke per-build
// analysis. Long-lived secrets must come from the server (layer 5), never from here.
package keymix

import "crypto/sha256"

// fragA / fragC are two of the three key fragments. The third (fragB) is
// generated fresh on every build and lives in the generated appsecrets package,
// so that two different binaries built from the same source do not share a key.
var (
	fragA = []byte{
		0x8f, 0x2a, 0xc4, 0x51, 0x19, 0xe7, 0x6b, 0xd0,
		0x3c, 0xa5, 0x7e, 0x92, 0x44, 0xff, 0x08, 0x61,
	}
	fragC = []byte{
		0x5d, 0xb3, 0x77, 0x0e, 0xa1, 0x29, 0xcc, 0x84,
		0x6f, 0x13, 0x9a, 0xd8, 0x50, 0x2b, 0xe6, 0x47,
	}
	// salt is folded in to make the derivation non-obvious to a tool that merely
	// concatenates visible byte arrays.
	salt = []byte("sentinel/v1/kdf")
)

// Derive combines the static fragments with the per-build fragB into a 32-byte
// AES-256 key. The exact ordering and the salt must match on both sides.
func Derive(fragB []byte) [32]byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(fragA)
	h.Write(fragB)
	h.Write(fragC)
	// A second pass over a rotated view cheaply raises the bar for a naive
	// "concatenate the arrays and sha256" reimplementation.
	h.Write(rotate(fragA))
	h.Write(rotate(fragC))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func rotate(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i]<<3 | b[i]>>5
	}
	return out
}
