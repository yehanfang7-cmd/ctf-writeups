// Package guard implements layer 4 of the hardening spec: anti-debugging,
// anti-tampering (self integrity check) and the primitives needed to react to
// them in a diffused, delayed, silent way.
//
// Design principles (spec §5.4):
//   - The guard only OBSERVES. It never calls os.Exit itself and never prints a
//     diagnostic. Callers fold the result into a trust score that is spread
//     across the program and triggered late, so a patcher cannot find one branch.
//   - On a positive detection we prefer "wrong answers later" over "crash now".
package guard

// Report is the outcome of one guard sweep.
type Report struct {
	// DebuggerSuspected is true if any anti-debug probe fired.
	DebuggerSuspected bool
	// IntegrityKnown is true once a baseline has been backfilled into the binary
	// (see scripts/backfill-integrity.ps1). In a fresh dev build it is false and
	// IntegrityOK is reported true (fail-open) so development is not blocked.
	IntegrityKnown bool
	// IntegrityOK is true if the on-disk .text section matches the backfilled
	// baseline (or if no baseline is present yet).
	IntegrityOK bool
}

// Clean reports whether the environment looks untampered.
func (r Report) Clean() bool {
	return !r.DebuggerSuspected && r.IntegrityOK
}

// Check runs every available probe. It is cheap enough to call from several
// unrelated code paths (which is exactly what the spec recommends: diffuse the
// checks rather than gating on one).
func Check() Report {
	known, ok := integrity()
	return Report{
		DebuggerSuspected: antiDebug(),
		IntegrityKnown:    known,
		IntegrityOK:       ok,
	}
}
