package license

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"sentinel/internal/appsecrets"
	"sentinel/internal/device"
)

// This file sketches the layer-5 online protocol. The transport (pinned TLS),
// the anti-replay nonce, the device binding and the offline-grace cache are real
// and compile; the server itself is tools/mocklicense for local testing. In
// production the HMAC "signature" is replaced by the server's asymmetric
// signature verified against a pinned public key (see docs/backend-architecture.md).

// ErrOffline is returned when the server is unreachable AND no valid cached
// grant exists. It is deliberately vague.
var ErrOffline = errors.New("x")

type verifyRequest struct {
	Token       string `json:"token"`
	Nonce       string `json:"nonce"`
	Fingerprint string `json:"fingerprint"`
	TS          int64  `json:"ts"`
}

type verifyResponse struct {
	OK       bool     `json:"ok"`
	Nonce    string   `json:"nonce"` // must echo our nonce (anti-replay)
	Features []string `json:"features"`
	Exp      int64    `json:"exp"`
	Sig      string   `json:"sig"` // hex HMAC over canonical payload
}

type grant struct {
	Fingerprint string   `json:"fp"`
	Features    []string `json:"features"`
	Exp         int64    `json:"exp"`     // license expiry
	Until       int64    `json:"until"`   // offline-grace deadline
	Sig         string   `json:"sig"`     // HMAC over the above
}

// VerifyOnline checks the license with the server, binding the grant to this
// device and refreshing the offline-grace cache. On network failure it falls
// back to a cached grant within its grace window (layer 5: 離線容忍策略).
func VerifyOnline(ctx context.Context, token string) (*State, error) {
	fp := device.Fingerprint()

	resp, err := callServer(ctx, token, fp)
	if err != nil {
		// Network path failed — try the offline grace cache.
		if g, ok := loadGrant(); ok && g.valid(fp) {
			return stateFromFeatures(g.Features), nil
		}
		return nil, ErrOffline
	}

	// Persist a fresh grant for offline tolerance (default 72h grace).
	saveGrant(&grant{
		Fingerprint: fp,
		Features:    resp.Features,
		Exp:         resp.Exp,
		Until:       time.Now().Add(72 * time.Hour).Unix(),
	})
	return stateFromFeatures(resp.Features), nil
}

func callServer(ctx context.Context, token, fp string) (*verifyResponse, error) {
	nonce := randNonce()
	reqBody := verifyRequest{Token: token, Nonce: nonce, Fingerprint: fp, TS: time.Now().Unix()}
	body, _ := json.Marshal(reqBody)

	url := endpoint()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 8 * time.Second, Transport: pinnedTransport()}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, errors.New("x")
	}

	var vr verifyResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&vr); err != nil {
		return nil, err
	}
	// Anti-replay: the server must echo our exact nonce.
	if vr.Nonce != nonce {
		return nil, errors.New("x")
	}
	// Verify the server signature (HMAC stand-in for an asymmetric signature).
	if !verifyServerSig(&vr) || !vr.OK {
		return nil, errors.New("x")
	}
	return &vr, nil
}

// pinnedTransport enforces SPKI certificate pinning against LICENSE_PUBKEY_PIN.
// For the local mock server (plain HTTP) pinning is skipped; against a real
// HTTPS endpoint the pin is enforced.
func pinnedTransport() *http.Transport {
	pin := appsecrets.LicensePubkeyPin.String()
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if pin == "" || len(rawCerts) == 0 {
					return nil
				}
				sum := sha256.Sum256(rawCerts[0]) // cert DER; real code pins SPKI
				got := "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
				if hmac.Equal([]byte(got), []byte(pin)) {
					return nil
				}
				return errors.New("x")
			},
		},
	}
}

func verifyServerSig(vr *verifyResponse) bool {
	canonical := vr.Nonce + "|" + joinFeatures(vr.Features) + "|" + itoa(vr.Exp)
	sig, err := hex.DecodeString(vr.Sig)
	if err != nil {
		return false
	}
	ok := false
	_ = appsecrets.LicenseSalt.Reveal(func(key []byte) {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(canonical))
		ok = hmac.Equal(m.Sum(nil), sig)
	})
	return ok
}

// ---- grant cache ----------------------------------------------------------

func (g *grant) valid(fp string) bool {
	if g.Fingerprint != fp {
		return false
	}
	now := time.Now().Unix()
	if now > g.Until {
		return false
	}
	if g.Exp != 0 && now > g.Exp {
		return false
	}
	// Verify cache integrity so a user cannot hand-edit features/expiry.
	want := g.Sig
	g.Sig = ""
	ok := hmac.Equal([]byte(want), []byte(g.sign()))
	g.Sig = want
	return ok
}

func (g *grant) sign() string {
	canonical := g.Fingerprint + "|" + joinFeatures(g.Features) + "|" + itoa(g.Exp) + "|" + itoa(g.Until)
	var out string
	_ = appsecrets.LicenseSalt.Reveal(func(key []byte) {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(canonical))
		out = hex.EncodeToString(m.Sum(nil))
	})
	return out
}

func grantPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "sentinel", "grant.json")
}

func saveGrant(g *grant) {
	g.Sig = g.sign()
	p := grantPath()
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	b, _ := json.Marshal(g)
	_ = os.WriteFile(p, b, 0o600)
}

func loadGrant() (*grant, bool) {
	b, err := os.ReadFile(grantPath())
	if err != nil {
		return nil, false
	}
	var g grant
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, false
	}
	return &g, true
}

// ---- small helpers --------------------------------------------------------

func endpoint() string {
	if v := os.Getenv("SENTINEL_LICENSE_URL"); v != "" {
		return v // local mock override for testing
	}
	return appsecrets.ApiEndpoint.String() + appsecrets.LicenseVerifyPath.String()
}

func stateFromFeatures(features []string) *State {
	s := &State{fragSig: magicSig, fragFeat: magicFeat ^ 0xFFFF, fragEnv: magicEnv ^ 0xFFFF, health: 64}
	_ = appsecrets.FeatureAlgoFull.Reveal(func(want []byte) {
		for _, f := range features {
			if hmac.Equal([]byte(f), want) {
				s.fragFeat = magicFeat
			}
		}
	})
	if guardClean() {
		s.fragEnv = magicEnv
	}
	return s
}

func randNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func joinFeatures(fs []string) string {
	out := ""
	for i, f := range fs {
		if i > 0 {
			out += ","
		}
		out += f
	}
	return out
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
