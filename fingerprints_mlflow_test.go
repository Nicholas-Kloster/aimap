package main

import (
	"testing"
)

// TestMLflowFingerprint_MatchesModernIndex asserts that the MLflow fingerprint
// matches a port-5000 response that mirrors what a real MLflow server returns
// on GET / today: a 200 with an HTML body whose <title> is "MLflow" and a
// Server header of "gunicorn". This is the response shape we captured live
// from 78.135.66.61:5000 on 2026-05-13.
//
// Prior to iter 4, the fingerprint probed /api/2.0/mlflow/experiments/list,
// an endpoint removed by upstream MLflow years ago. Every modern MLflow
// tracker was silently invisible to aimap.
func TestMLflowFingerprint_MatchesModernIndex(t *testing.T) {
	pr := PortResult{
		Host:        "203.0.113.10",
		Port:        5000,
		Open:        true,
		StatusCode:  200,
		Server:      "gunicorn",
		ContentType: "text/html; charset=utf-8",
		Headers:     map[string]string{"Server": "gunicorn", "Content-Type": "text/html; charset=utf-8"},
		BodySnippet: `<!doctype html><html lang="en"><head><meta charset="utf-8"/>` +
			`<meta name="viewport" content="width=device-width,initial-scale=1,shrink-to-fit=no"/>` +
			`<link rel="shortcut icon" href="./static-files/favicon.ico"/>` +
			`<meta name="theme-color" content="#000000"/>` +
			`<link rel="manifest" href="./static-files/manifest.json"/>` +
			`<title>MLflow</title>`,
	}

	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "MLflow" {
			continue
		}
		for _, probe := range fp.Probes {
			// Only test the GET / probe (path "/" or "") — we don't make
			// network calls in tests. The point is the match logic.
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				matched = true
				break
			}
		}
	}
	if !matched {
		t.Fatal("MLflow fingerprint did not match a real-shape MLflow index page on port 5000")
	}
}

// TestMLflowFingerprint_HasGETIndexProbe is the lower-level check: at least
// one MLflow probe must target "/" so that the FP works against the modern
// server before any deprecated paths.
func TestMLflowFingerprint_HasGETIndexProbe(t *testing.T) {
	for _, fp := range Fingerprints {
		if fp.Name != "MLflow" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path == "/" || probe.Path == "" {
				return
			}
		}
		t.Fatal("MLflow fingerprint has no GET-index probe; modern MLflow needs one")
	}
	t.Fatal("MLflow fingerprint not found at all")
}

// TestMLflowFingerprint_DoesNotMatchPlainGunicorn guards against the bug
// where "Server: gunicorn" alone matches MLflow. Real ML/AI servers often
// run on gunicorn — Phoenix, FastAPI apps, Flask apps, anything.
func TestMLflowFingerprint_DoesNotMatchPlainGunicorn(t *testing.T) {
	pr := PortResult{
		Host:        "203.0.113.20",
		Port:        5000,
		Open:        true,
		StatusCode:  200,
		Server:      "gunicorn",
		ContentType: "application/json",
		Headers:     map[string]string{"Server": "gunicorn"},
		BodySnippet: `{"name":"NotMLflow","version":"1.0"}`,
	}

	for _, fp := range Fingerprints {
		if fp.Name != "MLflow" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("MLflow fingerprint over-matched a plain gunicorn server without MLflow content")
			}
		}
	}
}
