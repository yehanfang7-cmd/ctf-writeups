// Package device derives a stable, non-reversible device fingerprint used to
// bind a license grant to one machine (layer 5: 裝置指紋). The fingerprint is an
// HMAC, so the raw machine identifiers never leave the process and the server
// only ever sees an opaque tag.
package device

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strings"

	"sentinel/internal/appsecrets"
)

// Fingerprint returns a hex HMAC over coarse, stable machine attributes. It is
// intentionally not high-entropy PII: it identifies a machine without revealing
// its real identifiers.
func Fingerprint() string {
	host, _ := os.Hostname()
	parts := []string{
		host,
		runtime.GOOS,
		runtime.GOARCH,
		os.Getenv("COMPUTERNAME"),
		os.Getenv("PROCESSOR_IDENTIFIER"),
	}
	material := strings.Join(parts, "\x1f")

	var tag string
	_ = appsecrets.DeviceHmacSecret.Reveal(func(secret []byte) {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(material))
		tag = hex.EncodeToString(m.Sum(nil))
	})
	if tag == "" {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	return tag
}
