package guard

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"os"
	"sync"
)

// The baseline record appended to the binary by scripts/backfill-integrity.ps1
// has layout: magic (8 bytes) | sha256 of .text (32 bytes), searched from the
// end of the file so a trailing Authenticode signature or packer overlay added
// after backfill does not hide it.
//
// The magic is stored XOR-obfuscated so the plaintext 8-byte needle does NOT
// appear anywhere in our own read-only data — otherwise findBaseline would match
// the embedded constant and read garbage as the baseline. The only plaintext
// occurrence is the trailer the post-build script writes.
var magicObf = [8]byte{0x09, 0x69, 0x14, 0x0e, 0x22, 0x13, 0x14, 0x0e} // "S3NTxINT" ^ 0x5A

func integrityNeedle() []byte {
	n := make([]byte, 8)
	for i := range magicObf {
		n[i] = magicObf[i] ^ 0x5A
	}
	return n
}

var (
	integrityOnce  sync.Once
	cachedKnown    bool
	cachedIntegrOK bool
)

// integrity returns (baselineKnown, ok). It is memoised: the on-disk file does
// not change under us, and repeated hashing would be wasteful.
func integrity() (bool, bool) {
	integrityOnce.Do(func() {
		cachedKnown, cachedIntegrOK = computeIntegrity()
	})
	return cachedKnown, cachedIntegrOK
}

func computeIntegrity() (known, ok bool) {
	exePath, err := os.Executable()
	if err != nil {
		return false, true // cannot verify -> fail open
	}
	data, err := os.ReadFile(exePath)
	if err != nil {
		return false, true
	}

	textHash, err := hashTextSection(exePath)
	if err != nil {
		return false, true
	}

	baseline, found := findBaseline(data)
	if !found {
		// No baseline backfilled yet (dev build). Fail open so development works.
		return false, true
	}
	return true, bytes.Equal(baseline, textHash)
}

// hashTextSection returns sha256 of the raw bytes of the PE ".text" section as
// stored on disk. The backfill script computes the same value.
func hashTextSection(path string) ([]byte, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sect := f.Section(".text")
	if sect == nil {
		// Some linkers name it differently; fall back to the first exec section.
		for _, s := range f.Sections {
			if s.Characteristics&0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
				sect = s
				break
			}
		}
	}
	if sect == nil {
		return nil, os.ErrNotExist
	}
	raw, err := sect.Data()
	if err != nil {
		return nil, err
	}
	// Section.Data() may return VirtualSize padded; trim to SizeOfRawData.
	if int(sect.Size) < len(raw) {
		raw = raw[:sect.Size]
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

// findBaseline locates the LAST integrityMagic in data and returns the 32 bytes
// that follow it.
func findBaseline(data []byte) ([]byte, bool) {
	needle := integrityNeedle()
	idx := bytes.LastIndex(data, needle)
	if idx < 0 {
		return nil, false
	}
	start := idx + len(needle)
	if start+32 > len(data) {
		return nil, false
	}
	return data[start : start+32], true
}
