package main

import (
	"reflect"
	"testing"
)

func TestParseTargets_BareIPv4(t *testing.T) {
	got := parseTargets("192.0.2.10")
	want := []string{"192.0.2.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets(\"192.0.2.10\") = %v; want %v", got, want)
	}
}

func TestParseTargets_BareHostname(t *testing.T) {
	got := parseTargets("api.example.com")
	want := []string{"api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets(\"api.example.com\") = %v; want %v", got, want)
	}
}

func TestParseTargets_CIDR(t *testing.T) {
	got := parseTargets("192.0.2.0/30")
	// /30 has 4 addresses, of which 2 are usable (net + broadcast stripped).
	if len(got) != 2 {
		t.Fatalf("parseTargets(\"192.0.2.0/30\") returned %d hosts; want 2 (%v)", len(got), got)
	}
}

// --- The bugs we're fixing ---

func TestParseTargets_StripsPortSuffix(t *testing.T) {
	// Common typo: user passes IP:port from another tool's output.
	// Should strip ":port" and return the bare host, not hang.
	got := parseTargets("78.135.66.61:5000")
	want := []string{"78.135.66.61"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets(\"78.135.66.61:5000\") = %v; want %v", got, want)
	}
}

func TestParseTargets_StripsPortFromHostname(t *testing.T) {
	got := parseTargets("api.example.com:8080")
	want := []string{"api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets(\"api.example.com:8080\") = %v; want %v", got, want)
	}
}

func TestParseTargets_SplitsCommaJoined(t *testing.T) {
	// Common typo: a comma-joined list passed as a single -target argument.
	got := parseTargets("1.2.3.4,5.6.7.8,api.example.com")
	want := []string{"1.2.3.4", "5.6.7.8", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets comma-joined = %v; want %v", got, want)
	}
}

func TestParseTargets_SplitsCommaWithSpaces(t *testing.T) {
	got := parseTargets("1.2.3.4, 5.6.7.8 ,api.example.com")
	want := []string{"1.2.3.4", "5.6.7.8", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets comma-with-spaces = %v; want %v", got, want)
	}
}

func TestParseTargets_IPv6InBrackets(t *testing.T) {
	// IPv6 hostnames are bracketed; the colon in the IP shouldn't be confused
	// with a port suffix.
	got := parseTargets("[2001:db8::1]:8080")
	want := []string{"2001:db8::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets IPv6 bracketed = %v; want %v", got, want)
	}
}

func TestParseTargets_BareIPv6(t *testing.T) {
	// A bare IPv6 without brackets is ambiguous (every colon could be a port).
	// We accept it as a single target — net.Dial will handle it.
	got := parseTargets("2001:db8::1")
	want := []string{"2001:db8::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets bare IPv6 = %v; want %v", got, want)
	}
}

func TestParseTargets_EmptyAndWhitespace(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n"} {
		got := parseTargets(in)
		if len(got) != 0 {
			t.Fatalf("parseTargets(%q) returned %v; want empty", in, got)
		}
	}
}

func TestParseTargets_TrailingCommaIgnored(t *testing.T) {
	got := parseTargets("1.2.3.4,,5.6.7.8,")
	want := []string{"1.2.3.4", "5.6.7.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets trailing-comma = %v; want %v", got, want)
	}
}
