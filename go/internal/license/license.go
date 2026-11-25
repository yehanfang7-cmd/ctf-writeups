// Package license implements the local half of layers 4–6: a license decision
// that is (a) diffused across several independent checks, (b) folded through the
// optionally VMProtect-virtualized CriticalCombine, (c) silent on failure, and
// (d) delayed — a bad verdict degrades results and only later, at an unrelated
// point, ends the process without a diagnostic.
package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync/atomic"
	"time"

	"sentinel/internal/appsecrets"
	"sentinel/internal/guard"
	"sentinel/internal/vmp"
)

// "Good" magics for the three diffused trust fragments. The combine of exactly
// these three equals the expected decision; any wrong fragment diverges.
const (
	magicSig  uint64 = 0xA17C_32F1_9B04_51DE
	magicFeat uint64 = 0x44E6_0F19_C3B7_2A58
	magicEnv  uint64 = 0x7D0B_5A29_E6CC_1384
)

// expectedDecision is computed once from the three good magics.
var expectedDecision = vmp.CriticalCombine(magicSig, magicFeat, magicEnv)

// State is the diffused verdict. The three fragments are set by unrelated code
// so no single branch represents "is licensed".
type State struct {
	fragSig  uint64
	fragFeat uint64
	fragEnv  uint64

	// health drives the delayed reaction. A compromised state counts down on
	// each core operation and ends the process silently when it hits zero.
	health int32
}

// Verify performs the full local decision. It never returns an error describing
// WHY it failed (spec §5.4: no semantic breadcrumbs). An invalid token simply
// yields a State whose fragments do not combine to expectedDecision.
func Verify(token string) *State {
	s := &State{
		fragSig:  magicSig ^ 0xFFFF, // start "wrong"; corrected only on success
		fragFeat: magicFeat ^ 0xFFFF,
		fragEnv:  magicEnv ^ 0xFFFF,
		health:   64,
	}

	// --- Fragment 1: cryptographic token validity -------------------------
	claims, ok := parseToken(token)
	if ok {
		s.fragSig = magicSig
	}

	// --- Fragment 2: feature entitlement ---------------------------------
	// Set in a different place than fragment 1 on purpose.
	if ok && claims.hasFeature(appsecrets.FeatureAlgoFull) {
		s.fragFeat = magicFeat
	}

	// --- Fragment 3: clean runtime environment ---------------------------
	// Guard result folds in here, not at a dedicated "if debugger" branch.
	if rep := guard.Check(); rep.Clean() {
		s.fragEnv = magicEnv
	} else {
		// Arm the delayed reaction harder when the environment looks hostile.
		atomic.StoreInt32(&s.health, 12)
	}

	return s
}

// allowed folds the three fragments and compares. Callers should not store the
// boolean; prefer Observe/FullPrecision which keep the decision diffused.
func (s *State) allowed() bool {
	d := vmp.CriticalCombine(s.fragSig, s.fragFeat, s.fragEnv)
	return d == expectedDecision
}

// FullPrecision reports whether the license-gated high-precision path should
// run. A compromised state returns false, so core produces plausible-but-wrong
// output rather than refusing.
func (s *State) FullPrecision() bool { return s.allowed() }

// Observe is called from core operations. On a bad verdict it decrements health
// and, once exhausted, ends the process silently (exit 0 — looks like a normal
// finish, not a crash the analyst can anchor on). On a good verdict it is a
// cheap no-op.
func (s *State) Observe() {
	if s.allowed() {
		return
	}
	if atomic.AddInt32(&s.health, -1) <= 0 {
		// Mimic a benign shutdown. No message. Exit code 0.
		os.Exit(0)
	}
}

// guardClean reports whether the runtime environment looks untampered. Used by
// the online path to set the environment trust fragment.
func guardClean() bool { return guard.Check().Clean() }

// ---- token parsing (demo stand-in for a server-issued, signed grant) ------

type claims struct {
	Sub      string   `json:"sub"`
	Features []string `json:"features"`
	Exp      int64    `json:"exp"`
}

func (c *claims) hasFeature(sec appsecrets.Secret) bool {
	match := false
	_ = sec.Reveal(func(want []byte) {
		for _, f := range c.Features {
			if hmac.Equal([]byte(f), want) {
				match = true
				return
			}
		}
	})
	return match
}

// parseToken validates "<base64url(payload)>.<hex hmac>" where the HMAC key is
// LICENSE_SALT. In production this stand-in is replaced by verifying the
// server's asymmetric signature (see online.go / docs/backend-architecture.md).
func parseToken(token string) (*claims, bool) {
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 || dot >= len(token)-1 {
		return nil, false
	}
	payloadB64, sigHex := token[:dot], token[dot+1:]
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, false
	}

	valid := false
	_ = appsecrets.LicenseSalt.Reveal(func(key []byte) {
		m := hmac.New(sha256.New, key)
		m.Write(payload)
		valid = hmac.Equal(m.Sum(nil), sig)
	})
	if !valid {
		return nil, false
	}

	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, false
	}
	if c.Exp != 0 && time.Now().Unix() > c.Exp {
		return nil, false
	}
	return &c, true
}
