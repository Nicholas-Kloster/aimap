package main

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseTargetsVerbose_QuietOnCleanInput(t *testing.T) {
	var buf bytes.Buffer
	got := parseTargetsVerbose("192.0.2.10", &buf)
	want := []string{"192.0.2.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v; want %v", got, want)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected empty warning buffer; got %q", buf.String())
	}
}

func TestParseTargetsVerbose_WarnsOnPortStrip(t *testing.T) {
	var buf bytes.Buffer
	got := parseTargetsVerbose("78.135.66.61:5000", &buf)
	want := []string{"78.135.66.61"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v; want %v", got, want)
	}
	if buf.Len() == 0 {
		t.Fatalf("expected a warning to be emitted; got none")
	}
	// The warning should mention the original input and the kept host
	s := buf.String()
	if !bytes.Contains([]byte(s), []byte("78.135.66.61:5000")) {
		t.Errorf("warning should mention the original input; got %q", s)
	}
}

func TestParseTargetsVerbose_WarnsOnCommaSplit(t *testing.T) {
	var buf bytes.Buffer
	got := parseTargetsVerbose("1.2.3.4,5.6.7.8", &buf)
	want := []string{"1.2.3.4", "5.6.7.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v; want %v", got, want)
	}
	if buf.Len() == 0 {
		t.Fatalf("expected a warning on comma-split; got none")
	}
}

func TestParseTargetsVerbose_QuietOnCIDR(t *testing.T) {
	var buf bytes.Buffer
	parseTargetsVerbose("192.0.2.0/30", &buf)
	if buf.Len() != 0 {
		t.Fatalf("CIDR is a clean input; expected no warning; got %q", buf.String())
	}
}

func TestParseTargetsVerbose_QuietOnBracketedIPv6(t *testing.T) {
	// IPv6 with brackets and a port is the canonical form — not a typo.
	var buf bytes.Buffer
	got := parseTargetsVerbose("[2001:db8::1]:8080", &buf)
	want := []string{"2001:db8::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v; want %v", got, want)
	}
	// We still strip the port silently here — the bracketed form is standard.
	if buf.Len() != 0 {
		t.Fatalf("bracketed IPv6 is canonical; expected no warning; got %q", buf.String())
	}
}
