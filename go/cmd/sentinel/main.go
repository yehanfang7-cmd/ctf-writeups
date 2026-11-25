// Command sentinel is the demo licensed application used to exercise every
// automatable hardening layer. It computes a "signal score" (the valuable core
// algorithm) but only at full precision when a valid license is present and the
// runtime looks untampered.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"sentinel/internal/core"
	"sentinel/internal/license"
	"sentinel/internal/vmp"
)

func main() {
	var (
		token  = flag.String("token", os.Getenv("SENTINEL_TOKEN"), "license token")
		online = flag.Bool("online", false, "verify license against the server")
		series = flag.String("series", "1.0,2.5,-0.5,3.0,0.25,-1.5,2.0,0.75", "comma-separated input series")
		info   = flag.Bool("info", false, "print build hardening info and exit")
	)
	flag.Parse()

	if *info {
		fmt.Printf("sentinel demo\n")
		fmt.Printf("  vmprotect SDK path: %v\n", vmp.Protected)
		return
	}

	// Verify the license. The verdict is diffused inside the State; we never see
	// a bare "licensed" boolean here.
	var st *license.State
	if *online {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s, err := license.VerifyOnline(ctx, *token)
		if err != nil {
			// Silent: no reason given. Fall back to a locked state.
			st = license.Verify("")
		} else {
			st = s
		}
	} else {
		st = license.Verify(*token)
	}

	data := parseSeries(*series)

	// Run the core algorithm several times, letting the diffused/delayed license
	// reaction fire from inside the loop rather than at a single gate.
	var last float64
	for i := 0; i < 5; i++ {
		st.Observe()
		last = core.ComputeSignal(data, st.FullPrecision())
	}

	fmt.Printf("signal=%.10f\n", last)
}

func parseSeries(s string) []float64 {
	parts := strings.Split(s, ",")
	out := make([]float64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseFloat(p, 64)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}
