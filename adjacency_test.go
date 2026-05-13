package main

import (
	"testing"
)

// TestAdjacency_FlagsPostgresOnMLflowHost is the canonical Insight #20
// example: a host running unauth MLflow on :5000 with PostgreSQL exposed
// on :5432. Without the adjacency rule aimap returns "1 AI service found"
// and ignores the open Postgres. With the rule, the Postgres is flagged
// as ML-adjacent because it's almost certainly the MLflow backend store.
func TestAdjacency_FlagsPostgresOnMLflowHost(t *testing.T) {
	services := []ServiceMatch{
		{Host: "78.135.66.61", Port: 5000, Service: "MLflow", Severity: "high"},
	}
	openPorts := []PortResult{
		{Host: "78.135.66.61", Port: 5000, Open: true},
		{Host: "78.135.66.61", Port: 5432, Open: true},
		{Host: "78.135.66.61", Port: 6379, Open: true},
		{Host: "78.135.66.61", Port: 8080, Open: true},
	}

	adj := buildAdjacencies(services, openPorts)

	want := map[int]bool{5432: true, 6379: true}
	got := make(map[int]bool)
	for _, a := range adj {
		got[a.Port] = true
	}
	for p := range want {
		if !got[p] {
			t.Errorf("expected adjacency match for port %d; got none", p)
		}
	}
	if len(adj) != len(want) {
		t.Errorf("got %d adjacency matches; want %d (%v)", len(adj), len(want), adj)
	}
}

// TestAdjacency_NoAIServiceMeansNoAdjacency: if the host has no confirmed
// AI service, even a Postgres on :5432 is not flagged. The whole point of
// the rule is the conjunction with an AI service.
func TestAdjacency_NoAIServiceMeansNoAdjacency(t *testing.T) {
	services := []ServiceMatch{}
	openPorts := []PortResult{
		{Host: "203.0.113.10", Port: 5432, Open: true},
		{Host: "203.0.113.10", Port: 6379, Open: true},
	}
	adj := buildAdjacencies(services, openPorts)
	if len(adj) != 0 {
		t.Fatalf("expected no adjacency without an AI service; got %v", adj)
	}
}

// TestAdjacency_PerHostScope: a Postgres on a DIFFERENT host than the AI
// service shouldn't be flagged.
func TestAdjacency_PerHostScope(t *testing.T) {
	services := []ServiceMatch{
		{Host: "203.0.113.10", Port: 5000, Service: "MLflow", Severity: "high"},
	}
	openPorts := []PortResult{
		{Host: "203.0.113.10", Port: 5000, Open: true},
		{Host: "203.0.113.20", Port: 5432, Open: true}, // different host
	}
	adj := buildAdjacencies(services, openPorts)
	if len(adj) != 0 {
		t.Fatalf("adjacency should be per-host; got %v", adj)
	}
}

// TestAdjacency_DoesNotFlagPortItselfFingerprinted: if a port is already
// classified as an AI service (e.g. 6379 fingerprinted as Redis-as-AI-cache
// in a hypothetical future FP), it shouldn't also be in the adjacency list.
// The adjacency list is for ports NOT in the services list.
func TestAdjacency_DoesNotFlagPortInServiceList(t *testing.T) {
	services := []ServiceMatch{
		{Host: "203.0.113.10", Port: 5000, Service: "MLflow", Severity: "high"},
		{Host: "203.0.113.10", Port: 5432, Service: "PostgreSQL (test)", Severity: "info"},
	}
	openPorts := []PortResult{
		{Host: "203.0.113.10", Port: 5000, Open: true},
		{Host: "203.0.113.10", Port: 5432, Open: true},
		{Host: "203.0.113.10", Port: 6379, Open: true},
	}
	adj := buildAdjacencies(services, openPorts)
	for _, a := range adj {
		if a.Port == 5432 {
			t.Fatalf("port 5432 already in services; shouldn't be in adjacency too")
		}
	}
}

// TestAdjacency_EachDataTierPortIsRecognized covers the data-tier ports
// the insight calls out: 5432, 6379, 9000/9001, 9092, 5672/15672.
func TestAdjacency_EachDataTierPortIsRecognized(t *testing.T) {
	services := []ServiceMatch{
		{Host: "203.0.113.10", Port: 5000, Service: "MLflow", Severity: "high"},
	}
	cases := []int{5432, 6379, 9000, 9001, 9092, 5672, 15672, 1025, 8025}
	for _, p := range cases {
		openPorts := []PortResult{
			{Host: "203.0.113.10", Port: 5000, Open: true},
			{Host: "203.0.113.10", Port: p, Open: true},
		}
		adj := buildAdjacencies(services, openPorts)
		found := false
		for _, a := range adj {
			if a.Port == p {
				found = true
			}
		}
		if !found {
			t.Errorf("data-tier port %d not flagged as ML-adjacent", p)
		}
	}
}

// TestAdjacency_IgnoresUnrelatedPorts: a random open port like SSH (:22)
// shouldn't be flagged just because the host runs an AI service.
func TestAdjacency_IgnoresUnrelatedPorts(t *testing.T) {
	services := []ServiceMatch{
		{Host: "203.0.113.10", Port: 5000, Service: "MLflow", Severity: "high"},
	}
	openPorts := []PortResult{
		{Host: "203.0.113.10", Port: 5000, Open: true},
		{Host: "203.0.113.10", Port: 22, Open: true},   // SSH
		{Host: "203.0.113.10", Port: 25, Open: true},   // SMTP
		{Host: "203.0.113.10", Port: 443, Open: true},  // generic HTTPS
	}
	adj := buildAdjacencies(services, openPorts)
	for _, a := range adj {
		if a.Port == 22 || a.Port == 25 || a.Port == 443 {
			t.Errorf("port %d should not be flagged as ML-adjacent", a.Port)
		}
	}
}
