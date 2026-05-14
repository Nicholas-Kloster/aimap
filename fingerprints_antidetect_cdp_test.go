package main

import (
	"testing"
)

// Anti-detect CDP browser-automation server fingerprint.
//
// Field-discovered 2026-05-14 in the browser-automation backend survey
// (159.195.70.69, 23.19.231.93). A Python aiohttp server fronts Chrome's
// DevTools Protocol on :9222. Unlike raw Chrome CDP (Chrome's own HTTP
// server) and unlike a port-forwarder bridge, this server exposes a
// distinctive root path:
//
//   GET /  → {"status":"ok","active":1,"processes":{"__default__":{
//             "pid":13,"port":5100,"seed":"71062","connections":2,
//             "timezone":null,"locale":null,"proxy":null}}}
//
// The per-process seed/proxy/timezone/locale fields are anti-fingerprint
// controls — each browser process gets a randomized fingerprint seed and
// can be pinned to a proxy/timezone/locale. That root shape plus a
// Server: aiohttp header plus a valid CDP /json/version is the signature.
//
// Critical to NOT match the CDP honeypot fleet (byte-identical Chrome/120,
// 220-340 open ports): the honeypot fakes /json/version but does NOT serve
// this aiohttp control-plane root, so requiring the root-path match
// excludes it.

func matchAny(name string, pr PortResult) bool {
	for _, fp := range Fingerprints {
		if fp.Name != name {
			continue
		}
		for _, probe := range fp.Probes {
			if matchProbe(probe, pr) {
				return true
			}
		}
	}
	return false
}

// The aiohttp control-plane root path is the primary signal.
func TestAntiDetectCDP_MatchesControlPlaneRoot(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.50", Port: 9222, Open: true,
		StatusCode: 200,
		Server:     "Python/3.12 aiohttp/3.13.5",
		Headers: map[string]string{
			"Server":       "Python/3.12 aiohttp/3.13.5",
			"Content-Type": "application/json; charset=utf-8",
		},
		BodySnippet: `{"status": "ok", "active": 1, "processes": {"__default__": {"pid": 13, "port": 5100, "seed": "71062", "connections": 2, "timezone": null, "locale": null, "proxy": null}}}`,
	}
	if !matchAny("Anti-detect CDP server", pr) {
		t.Fatal("Anti-detect CDP FP did not match the aiohttp control-plane root")
	}
}

// A valid CDP /json/version on the same server must also match.
func TestAntiDetectCDP_MatchesJsonVersion(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.51", Port: 9222, Open: true,
		StatusCode: 200,
		Server:     "Python/3.12 aiohttp/3.13.5",
		Headers: map[string]string{
			"Server":       "Python/3.12 aiohttp/3.13.5",
			"Content-Type": "application/json; charset=utf-8",
		},
		BodySnippet: `{"Browser":"Chrome/146.0.7680.177","Protocol-Version":"1.3","webSocketDebuggerUrl":"ws://203.0.113.51:9222/devtools/browser/abc"}`,
	}
	if !matchAny("Anti-detect CDP server", pr) {
		t.Fatal("Anti-detect CDP FP did not match a valid /json/version on the aiohttp server")
	}
}

// The CDP honeypot fleet fakes /json/version but does NOT serve the
// aiohttp control-plane root, and its server header is bare Chrome, not
// aiohttp. It must NOT match this fingerprint.
func TestAntiDetectCDP_DoesNotMatchHoneypotFleet(t *testing.T) {
	// honeypot /json/version: real-looking CDP JSON, but no aiohttp header
	pr := PortResult{
		Host: "203.0.113.99", Port: 9222, Open: true,
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		BodySnippet: `{"Browser":"Chrome/120.0.6099.109","Protocol-Version":"1.3","webSocketDebuggerUrl":"ws://203.0.113.99:9222/devtools/browser/xyz"}`,
	}
	if matchAny("Anti-detect CDP server", pr) {
		t.Fatal("Anti-detect CDP FP must NOT match the honeypot fleet's faked /json/version (no aiohttp header)")
	}
}

// Raw Chrome CDP (Chrome's own HTTP server, no aiohttp wrapper) is a
// different platform — it must not match this fingerprint either. It is
// covered by the separate raw-CDP detection path, not this one.
func TestAntiDetectCDP_DoesNotMatchRawChrome(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.60", Port: 9222, Open: true,
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json; charset=UTF-8",
		},
		BodySnippet: `{"Browser":"Chrome/144.0.7559.96","Protocol-Version":"1.3","webSocketDebuggerUrl":"ws://203.0.113.60:9222/devtools/browser/raw"}`,
	}
	if matchAny("Anti-detect CDP server", pr) {
		t.Fatal("Anti-detect CDP FP must NOT match raw Chrome CDP (no aiohttp wrapper)")
	}
}

// A plain aiohttp app that is not a CDP server (no processes/seed root,
// no CDP /json/version) must not match on the Server header alone.
func TestAntiDetectCDP_DoesNotMatchPlainAiohttp(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.70", Port: 9222, Open: true,
		StatusCode: 200,
		Server:     "Python/3.12 aiohttp/3.13.5",
		Headers: map[string]string{
			"Server":       "Python/3.12 aiohttp/3.13.5",
			"Content-Type": "application/json",
		},
		BodySnippet: `{"message":"hello","items":[]}`,
	}
	if matchAny("Anti-detect CDP server", pr) {
		t.Fatal("Anti-detect CDP FP must NOT match a plain aiohttp app on the Server header alone")
	}
}

func TestAntiDetectCDP_FingerprintRegistered(t *testing.T) {
	found := false
	for _, fp := range Fingerprints {
		if fp.Name == "Anti-detect CDP server" {
			found = true
			if fp.Severity != "high" {
				t.Errorf("expected severity high, got %q", fp.Severity)
			}
			hasPort := false
			for _, p := range fp.DefaultPorts {
				if p == 9222 {
					hasPort = true
				}
			}
			if !hasPort {
				t.Error("Anti-detect CDP FP should include port 9222 in DefaultPorts")
			}
		}
	}
	if !found {
		t.Fatal("Anti-detect CDP server fingerprint is not registered in Fingerprints")
	}
}
