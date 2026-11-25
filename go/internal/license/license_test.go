package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"sentinel/internal/appsecrets"
)

func mintForTest(features []string) string {
	payload, _ := json.Marshal(map[string]any{
		"sub": "t", "features": features,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	var sig string
	_ = appsecrets.LicenseSalt.Reveal(func(k []byte) {
		m := hmac.New(sha256.New, k)
		m.Write(payload)
		sig = hex.EncodeToString(m.Sum(nil))
	})
	return base64.RawURLEncoding.EncodeToString(payload) + "." + sig
}

func TestFullPrecisionWithValidToken(t *testing.T) {
	st := Verify(mintForTest([]string{appsecrets.FeatureAlgoFull.String()}))
	if !st.FullPrecision() {
		t.Fatal("expected full precision with a valid token")
	}
}

func TestLockedWithoutToken(t *testing.T) {
	if Verify("").FullPrecision() {
		t.Fatal("expected locked state without a token")
	}
}

func TestTamperedTokenRejected(t *testing.T) {
	if Verify("garbage.deadbeef").FullPrecision() {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestMissingFeatureRejected(t *testing.T) {
	// Valid signature but wrong feature -> no full precision.
	if Verify(mintForTest([]string{"feature.other"})).FullPrecision() {
		t.Fatal("expected missing feature to be rejected")
	}
}
