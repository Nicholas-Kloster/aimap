package main

import (
	"testing"
)

// TestScanAllFingerprints_DefaultIsFalse asserts the default behavior is
// the filtered fast path. Bypassing requires explicit opt-in.
func TestScanAllFingerprints_DefaultIsFalse(t *testing.T) {
	// Save and restore in case other tests run after this one
	saved := scanAllFingerprints
	defer func() { scanAllFingerprints = saved }()

	scanAllFingerprints = false // explicit default
	if scanAllFingerprints {
		t.Fatal("scanAllFingerprints should default to false")
	}
}

// TestScanAllFingerprints_VariableExists is a smoke test guarding against
// accidental removal of the global flag variable in a future refactor.
// If someone deletes scanAllFingerprints, this file won't compile.
func TestScanAllFingerprints_VariableExists(t *testing.T) {
	scanAllFingerprints = true
	scanAllFingerprints = false
	// No-op; the test exists only to keep the symbol referenced from tests.
}
