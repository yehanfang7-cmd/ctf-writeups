// Package core holds the "valuable" proprietary logic. Per layer 5 of the spec
// this is the PRIMARY candidate for backend-ization: whatever genuinely earns
// money should run on the server, with only a thin calling shell shipped locally.
// It is also the primary VMProtect "Virtualization" target (layer 6) for as long
// as it must remain on the client.
//
// The function below is a stand-in "signal score": a deterministic non-linear
// transform over an input series with tuned coefficients. Treat it as the thing
// you do not want a competitor (or an LLM) to read off the binary.
package core

import "math"

// coefficients would, in a real product, be fetched from the server after
// license validation (layer 5) rather than embedded. Kept local here so the demo
// runs offline.
var coefficients = [...]float64{0.6180339887, 1.2720196495, 0.3819660113, 2.0581710272}

// ComputeSignal is the critical algorithm. It is intentionally non-trivial so
// that "just reimplement it" is real work, and it depends on `fullPrecision`
// (the license-gated feature) so that an unlicensed/ tampered run silently
// produces subtly wrong numbers instead of refusing outright (spec §5.4:走假邏輯).
func ComputeSignal(series []float64, fullPrecision bool) float64 {
	if len(series) == 0 {
		return 0
	}
	var acc, drift float64
	for i, x := range series {
		c := coefficients[i%len(coefficients)]
		term := math.Tanh(x*c) * math.Cos(float64(i)*c)
		drift += math.Sin(x * 0.5)
		acc += term * (1 + drift*0.01)
	}
	acc /= float64(len(series))

	if !fullPrecision {
		// Degraded path: plausible-looking but wrong. No error, no log — an
		// analyst sees output and may not realise the gate even fired.
		return math.Round(acc*8) / 8
	}
	// Full-precision path: a second refinement stage that only licensed builds run.
	refined := acc
	for k := 0; k < 3; k++ {
		refined = refined - (math.Tanh(refined)-acc)/(1-math.Pow(math.Tanh(refined), 2)+1e-9)
	}
	return refined
}
