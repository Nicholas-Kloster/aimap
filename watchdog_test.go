package main

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchdog_QuietWhenProgressing(t *testing.T) {
	var progress atomic.Int64
	var buf bytes.Buffer

	stop := startWatchdog(&progress, 50*time.Millisecond, &buf)

	// Tick progress up steadily for 200ms
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		progress.Add(1)
		time.Sleep(20 * time.Millisecond)
	}

	close(stop)
	time.Sleep(20 * time.Millisecond)

	if buf.Len() != 0 {
		t.Fatalf("expected no warning when progressing; got %q", buf.String())
	}
}

func TestWatchdog_WarnsAfterStall(t *testing.T) {
	var progress atomic.Int64
	progress.Store(5) // initial value
	var buf bytes.Buffer

	// Use a very short stall window so the test is fast
	stop := startWatchdog(&progress, 80*time.Millisecond, &buf)

	// Don't tick progress — let it stall for 250ms (3+ watchdog windows)
	time.Sleep(250 * time.Millisecond)

	close(stop)
	time.Sleep(20 * time.Millisecond)

	if buf.Len() == 0 {
		t.Fatalf("expected a stall warning; got none")
	}
	if !strings.Contains(buf.String(), "no progress") {
		t.Errorf("warning should mention stall; got %q", buf.String())
	}
}

func TestWatchdog_ResetsOnResumedProgress(t *testing.T) {
	var progress atomic.Int64
	var buf bytes.Buffer

	stop := startWatchdog(&progress, 80*time.Millisecond, &buf)

	// Stall for 50ms (under the threshold)
	time.Sleep(50 * time.Millisecond)
	// Resume progress
	progress.Add(10)
	// Stall again briefly, but the counter just moved so timer resets
	time.Sleep(50 * time.Millisecond)
	progress.Add(10)
	time.Sleep(50 * time.Millisecond)

	close(stop)
	time.Sleep(20 * time.Millisecond)

	if buf.Len() != 0 {
		t.Fatalf("watchdog should reset on progress; got warning %q", buf.String())
	}
}
