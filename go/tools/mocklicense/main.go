// Command mocklicense is a local test double for the layer-5 license server and
// a token minter. It shares LICENSE_SALT with the client via internal/appsecrets,
// so tokens/grants it produces validate in the demo. It is a TEST TOOL, never
// shipped: a real deployment uses a server holding an asymmetric private key.
//
// Usage:
//
//	go run ./tools/mocklicense mint   > token.txt          # offline token
//	go run ./tools/mocklicense serve  :8099                # online endpoint
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"sentinel/internal/appsecrets"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mocklicense mint | serve [addr]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "mint":
		fmt.Println(mintToken())
	case "serve":
		addr := ":8099"
		if len(os.Args) > 2 {
			addr = os.Args[2]
		}
		serve(addr)
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}

func salt() []byte {
	var k []byte
	_ = appsecrets.LicenseSalt.Reveal(func(b []byte) { k = append([]byte(nil), b...) })
	return k
}

func feature() string { return appsecrets.FeatureAlgoFull.String() }

// mintToken builds "<base64url(payload)>.<hex hmac>" accepted by license.parseToken.
func mintToken() string {
	payload, _ := json.Marshal(map[string]any{
		"sub":      "demo-user",
		"features": []string{feature(), "feature.pro.enabled"},
		"exp":      time.Now().Add(365 * 24 * time.Hour).Unix(),
	})
	m := hmac.New(sha256.New, salt())
	m.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + hex.EncodeToString(m.Sum(nil))
}

func serve(addr string) {
	http.HandleFunc("/license/verify", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Token, Nonce, Fingerprint string
			TS                        int64
		}
		_ = json.Unmarshal(body, &req)

		features := []string{feature()}
		exp := time.Now().Add(30 * 24 * time.Hour).Unix()

		// Sign exactly as the client verifies: nonce|features|exp.
		canonical := req.Nonce + "|" + join(features) + "|" + fmt.Sprintf("%d", exp)
		m := hmac.New(sha256.New, salt())
		m.Write([]byte(canonical))

		resp := map[string]any{
			"ok":       req.Token != "",
			"nonce":    req.Nonce, // echo for anti-replay
			"features": features,
			"exp":      exp,
			"sig":      hex.EncodeToString(m.Sum(nil)),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	log.Printf("mock license server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func join(fs []string) string {
	out := ""
	for i, f := range fs {
		if i > 0 {
			out += ","
		}
		out += f
	}
	return out
}
