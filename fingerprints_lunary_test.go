package main

import (
	"testing"
)

// Iter 21: Lunary FP catastrophic over-match against Elasticsearch.
//
// During the n8n corpus sweep, the Lunary FP fired on 283 hosts (of 235
// probed = wildly impossible). Investigation showed the FP's primary
// probe `/api/v1/health` + `json_field:status` was matching Elasticsearch's
// `/_cluster/health`-shaped response `{"cluster_name":"prodcluster",
// "status":"green", "active_shards":1, ...}` proxied at `/api/v1/health`
// by a reverse-proxy in front of an ES cluster.
//
// Real Lunary returns `{"status":"OK"}` from /api/v1/health (Phase 2
// captured this at 100.26.119.0:443). Need to:
//   1. Match on the Lunary-specific {"status":"OK"} shape
//   2. Anti-match on the Elasticsearch shape (cluster_name + active_shards)

func TestLunary_MatchesRealHealthShape(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.90", Port: 443, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers: map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"status":"OK"}`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Lunary" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/api/v1/health" {
				continue
			}
			if matchProbe(probe, pr) {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("Lunary FP did not match the real {\"status\":\"OK\"} health response")
	}
}

func TestLunary_RejectsElasticsearchHealthShape(t *testing.T) {
	// This is the live shape that caused 283 false positives.
	pr := PortResult{
		Host: "203.0.113.91", Port: 443, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers: map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{
  "cluster_name" : "prodcluster",
  "status" : "green",
  "timed_out" : false,
  "number_of_nodes" : 1,
  "number_of_data_nodes" : 1,
  "active_primary_shards" : 1,
  "active_shards" : 1,
  "relocating_shards" : 0
}`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "Lunary" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/api/v1/health" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("Lunary FP over-matched an Elasticsearch /_cluster/health response (the 283-host false-positive class)")
			}
		}
	}
}

// Title-based probe should still work for Lunary instances exposing the
// dashboard but without an unauthenticated API endpoint.
func TestLunary_MatchesDashboardTitle(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.92", Port: 443, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>Dashboard | Lunary</title></head>`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Lunary" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("Lunary FP no longer matches the canonical dashboard title")
	}
}
