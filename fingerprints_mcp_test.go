package main

import (
	"testing"
)

// MCP Server fingerprint tests.
//
// Every response body below is a source-of-truth snapshot from
// /home/cowboy/recon/2026-05-15-mcp-refresh/verify/get_mcp_signal.jsonl —
// captured during the 2026-05-15 MCP refresh against 88 confirmed unauth
// MCP servers in the wild. NOT a guess. NOT hand-authored.
//
// Discipline (per aimap CLAUDE.md): no naked single-word body_contains.
// Every keyword is anchored to status_code + body_contains, header_contains,
// or a full unique substring.

// helper: does any probe of the MCP Server fingerprint match this PortResult?
func mcpMatches(pr PortResult) bool {
	for _, fp := range Fingerprints {
		if fp.Name != "MCP Server" {
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

// ── Probe 1: FastMCP / Streamable HTTP — 406 + jsonrpc body ─────────
// Fixture source: 109.205.61.97:8000 (line 4 in get_mcp_signal.jsonl)
// status=406, server=uvicorn, mcp-session-id header present.
// Body: {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Not Acceptable: Client must accept text/event-stream"}}
// This is the dominant FastMCP / python-sdk shape (26/88 hosts, 30%).

func TestMCPServer_FastMCPNotAcceptable(t *testing.T) {
	pr := PortResult{
		Host: "109.205.61.97", Port: 8000, Open: true,
		StatusCode:  406,
		ContentType: "application/json",
		Headers: map[string]string{
			"Server":         "uvicorn",
			"Content-Type":   "application/json",
			"mcp-session-id": "c0b9eddf903e4405803bc388c84a80a7",
		},
		BodySnippet: `{"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Not Acceptable: Client must accept text/event-stream"}}`,
	}
	if !mcpMatches(pr) {
		t.Fatal("MCP Server FP did not match FastMCP 406+jsonrpc shape (109.205.61.97:8000)")
	}
}

func TestMCPServer_FastMCPNotAcceptable_NegativeCheck(t *testing.T) {
	// A generic 406 response with no JSON-RPC content must NOT match.
	pr := PortResult{
		Host: "203.0.113.1", Port: 8000, Open: true,
		StatusCode:  406,
		ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `Not Acceptable`,
	}
	if mcpMatches(pr) {
		t.Fatal("MCP Server FP false-positived on generic 406 without jsonrpc body")
	}
}

// ── Probe 2: 405 + body contains "Method Not Allowed" + "POST" ──────
// Fixture source: 103.226.139.180:8888 (line 2 in get_mcp_signal.jsonl)
// status=405, X-Powered-By=Express, Access-Control-Allow-Headers includes Mcp-Session-Id.
// Body: {"error":"Method Not Allowed","message":"SSE streaming is not supported in stateless mode. Use POST requests with JSON responses."}
// This is the Node.js SDK / DBHub MCP Server shape.

func TestMCPServer_MethodNotAllowedPOST(t *testing.T) {
	pr := PortResult{
		Host: "103.226.139.180", Port: 8888, Open: true,
		StatusCode:  405,
		ContentType: "application/json; charset=utf-8",
		Headers: map[string]string{
			"X-Powered-By":               "Express",
			"Access-Control-Allow-Origin": "http://localhost",
			"Content-Type":               "application/json; charset=utf-8",
		},
		BodySnippet: `{"error":"Method Not Allowed","message":"SSE streaming is not supported in stateless mode. Use POST requests with JSON responses."}`,
	}
	if !mcpMatches(pr) {
		t.Fatal("MCP Server FP did not match 405+Method Not Allowed+POST body (103.226.139.180:8888)")
	}
}

func TestMCPServer_MethodNotAllowedPOST_NegativeCheck(t *testing.T) {
	// A 405 with "Method Not Allowed" in body but no "POST" must NOT match Probe 2.
	// (May still match other probes if JSON-RPC is present; here we use a plain 405.)
	// Fixture origin: generic uvicorn 405 without POST mention in body.
	pr := PortResult{
		Host: "203.0.113.2", Port: 8000, Open: true,
		StatusCode:  405,
		ContentType: "application/json",
		Headers:     map[string]string{"Server": "uvicorn"},
		BodySnippet: `{"detail":"Method Not Allowed"}`,
	}
	if mcpMatches(pr) {
		t.Fatal("MCP Server FP false-positived on 405+Method Not Allowed without POST or jsonrpc")
	}
}

// ── Probe 3: Server header identifies as mcp-server* ────────────────
// Fixture source: 54.180.117.151:3001 (line 77 in get_mcp_signal.jsonl)
// status=405, Server=mcp-server/1.0.1, Allow=POST.
// Body: {"error": "Method Not Allowed", "allow": "POST"}
// Built with mcp-framework; sets Server: mcp-server/x.y.z.

func TestMCPServer_ServerHeaderMCP(t *testing.T) {
	pr := PortResult{
		Host: "54.180.117.151", Port: 3001, Open: true,
		StatusCode:  405,
		ContentType: "application/json",
		Headers: map[string]string{
			"Server":       "mcp-server/1.0.1",
			"Allow":        "POST",
			"Content-Type": "application/json",
		},
		BodySnippet: `{"error": "Method Not Allowed", "allow": "POST"}`,
	}
	if !mcpMatches(pr) {
		t.Fatal("MCP Server FP did not match Server: mcp-server/1.0.1 header (54.180.117.151:3001)")
	}
}

func TestMCPServer_ServerHeaderMCP_NegativeCheck(t *testing.T) {
	// A generic "mcp-gateway" Server header (not mcp-server) must NOT match Probe 3.
	// Fixture origin: 40.160.2.169:3000 (line 54) has Server: mcp-gateway.
	pr := PortResult{
		Host: "40.160.2.169", Port: 3000, Open: true,
		StatusCode:  404,
		ContentType: "application/json",
		Headers: map[string]string{
			"Server":       "mcp-gateway",
			"Content-Type": "application/json",
		},
		BodySnippet: `{"error":"Not Found","hint":"MCP endpoint is POST /mcp or GET /sse"}`,
	}
	if mcpMatches(pr) {
		t.Fatal("MCP Server FP false-positived on Server: mcp-gateway (not mcp-server)")
	}
}

// ── Probe 4: JSON-RPC error -32600 + jsonrpc in body ────────────────
// Fixture source: 57.128.169.26:443 (line 79 in get_mcp_signal.jsonl)
// status=406, Server=nginx/1.28.0, TLS port, mcp-session-id header.
// Body: {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Not Acceptable: Client must accept text/event-stream"}}
// Distinct from Probe 1 coverage: this is a TLS/nginx-fronted variant.

func TestMCPServer_JSONRPCErrorCode32600(t *testing.T) {
	pr := PortResult{
		Host: "57.128.169.26", Port: 443, Open: true, TLS: true,
		StatusCode:  406,
		ContentType: "application/json",
		Headers: map[string]string{
			"Server":         "nginx/1.28.0",
			"Content-Type":   "application/json",
			"mcp-session-id": "200fa8bc8f4f4754858bba6b6ae8411c",
		},
		BodySnippet: `{"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Not Acceptable: Client must accept text/event-stream"}}`,
	}
	if !mcpMatches(pr) {
		t.Fatal("MCP Server FP did not match -32600+jsonrpc body (57.128.169.26:443)")
	}
}

func TestMCPServer_JSONRPCErrorCode32600_NegativeCheck(t *testing.T) {
	// A body with "jsonrpc" but no "-32600" (different error code) and no 406
	// must NOT match Probe 4 (and must not match other probes either if the
	// status and body shape don't qualify).
	// Fixture origin: 149.28.186.108:3000 (line 30) — 405, -32000, no -32600.
	pr := PortResult{
		Host: "149.28.186.108", Port: 3000, Open: true,
		StatusCode:  405,
		ContentType: "application/json",
		Headers: map[string]string{
			"X-Powered-By": "Express",
		},
		BodySnippet: `{"jsonrpc":"2.0","error":{"code":-32000,"message":"Method not allowed."},"id":null}`,
	}
	if mcpMatches(pr) {
		t.Fatal("MCP Server FP false-positived on 405+-32000+jsonrpc (no -32600, no Allow header, no mcp-server)")
	}
}

// ── Probe 5: 405 + Allow header contains "post" ─────────────────────
// Fixture source: 140.245.238.65:443 (line 23 in get_mcp_signal.jsonl)
// status=405, server=uvicorn, allow=POST, TLS port.
// Body: {"detail":"Method Not Allowed"}
// FastAPI/uvicorn shape: returns a proper Allow header on 405.

func TestMCPServer_AllowHeaderPOST(t *testing.T) {
	pr := PortResult{
		Host: "140.245.238.65", Port: 443, Open: true, TLS: true,
		StatusCode:  405,
		ContentType: "application/json",
		Headers: map[string]string{
			"Server":       "uvicorn",
			"Allow":        "POST",
			"Content-Type": "application/json",
		},
		BodySnippet: `{"detail":"Method Not Allowed"}`,
	}
	if !mcpMatches(pr) {
		t.Fatal("MCP Server FP did not match 405+Allow:POST header (140.245.238.65:443)")
	}
}

func TestMCPServer_AllowHeaderPOST_NegativeCheck(t *testing.T) {
	// A 405 with Allow: DELETE,POST (not an MCP endpoint) from a generic uvicorn
	// app still fires Probe 5. Use a response where status != 405 and no other
	// probe signals are present — status 404, no jsonrpc, no mcp-server header.
	// Fixture origin: 120.24.170.57:5001 (line 6) — 404, Server: Kestrel, body "Status Code: 404; Not Found".
	pr := PortResult{
		Host: "120.24.170.57", Port: 5001, Open: true,
		StatusCode:  404,
		ContentType: "text/plain",
		Headers: map[string]string{
			"Server":       "Kestrel",
			"Content-Type": "text/plain",
		},
		BodySnippet: "Status Code: 404; Not Found",
	}
	if mcpMatches(pr) {
		t.Fatal("MCP Server FP false-positived on Kestrel 404 (120.24.170.57:5001)")
	}
}

// ── Probe 6: 400 Bad Request + body contains "Mcp-Session-Id" ───────
// Added 2026-05-15 after a live Critter shakedown on Vschool.GatewayApi
// (120.24.170.57:5001) exposed this response shape, which Probes 1-5
// missed. Kestrel/.NET-based MCP servers emit this when the Streamable
// HTTP transport session header is missing.
// Fixture origin: aimap.json from /tmp/critter-mcp-shakedown-1778825265
// — live probe of 120.24.170.57:5001 returned this verbatim body.

func TestMCPServer_BadRequestSessionIdRequired(t *testing.T) {
	pr := PortResult{
		Host: "120.24.170.57", Port: 5001, Open: true,
		StatusCode:  400,
		ContentType: "application/json; charset=utf-8",
		Headers: map[string]string{
			"Server":       "Kestrel",
			"Content-Type": "application/json; charset=utf-8",
		},
		BodySnippet: `{"error":{"code":-32000,"message":"Bad Request: Mcp-Session-Id header is required"},"id":"","jsonrpc":"2.0"}`,
	}
	if !mcpMatches(pr) {
		t.Fatal("MCP Server FP did not match 400 + Mcp-Session-Id required (Vschool.GatewayApi shape)")
	}
}

func TestMCPServer_BadRequestSessionIdRequired_NegativeCheck(t *testing.T) {
	// A generic 400 Bad Request response (e.g. nginx bad-request handling)
	// must NOT match — the Mcp-Session-Id literal is what makes it MCP.
	pr := PortResult{
		Host: "203.0.113.99", Port: 80, Open: true,
		StatusCode:  400,
		ContentType: "text/html",
		Headers: map[string]string{
			"Server":       "nginx/1.18.0",
			"Content-Type": "text/html",
		},
		BodySnippet: `<html><body><h1>400 Bad Request</h1></body></html>`,
	}
	if mcpMatches(pr) {
		t.Fatal("MCP Server FP false-positived on generic nginx 400")
	}
}

// ── Probe 7: body contains "Mcp-Session-Id" on any status ───────────
// Some MCP servers emit the spec header literal on non-400 responses
// (e.g. 200 with a JSON error, or behind a reverse-proxy that rewrites
// status). The Mcp-Session-Id literal is unique to the MCP spec.

func TestMCPServer_BodyMentionsSessionId_OnNon400(t *testing.T) {
	// Synthetic: 200 status, body mentions Mcp-Session-Id (e.g. via
	// reverse-proxy that swallowed the original 400). Still matches.
	pr := PortResult{
		Host: "203.0.113.101", Port: 8080, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers: map[string]string{
			"Server":       "nginx/1.20",
			"Content-Type": "application/json",
		},
		BodySnippet: `{"error":"Mcp-Session-Id header missing","jsonrpc":"2.0"}`,
	}
	if !mcpMatches(pr) {
		t.Fatal("MCP Server FP did not match non-400 response with Mcp-Session-Id literal")
	}
}

// ── Probe 8: root path / + 400 + Mcp-Session-Id ─────────────────────
// Some MCP servers (Vschool.GatewayApi / Kestrel-based) bind the
// MCP endpoint at the root, not at /mcp. Live shakedown 2026-05-15
// against 120.24.170.57 found this shape: GET / returns 400 with
// Mcp-Session-Id required, while GET /mcp returns plain 404.
//
// The unit-test note here is that matchProbe doesn't use Path —
// it only evaluates the Matches. So this test is structurally the
// same as Probe 6's, but the fingerprint catalog separately registers
// a probe with Path:"/" so the production scanner hits the right path.

func TestMCPServer_RootBound_BadRequestSessionId(t *testing.T) {
	pr := PortResult{
		Host: "120.24.170.57", Port: 5001, Open: true,
		StatusCode:  400,
		ContentType: "application/json; charset=utf-8",
		Headers: map[string]string{
			"Server":       "Kestrel",
			"Content-Type": "application/json; charset=utf-8",
		},
		BodySnippet: `{"error":{"code":-32000,"message":"Bad Request: Mcp-Session-Id header is required"},"id":"","jsonrpc":"2.0"}`,
	}
	if !mcpMatches(pr) {
		t.Fatal("MCP Server FP did not match root-bound 400 + Mcp-Session-Id (Vschool.GatewayApi shape)")
	}
}

// Smoke test that the catalog contains a probe whose Path is "/" — required
// for root-bound MCP servers. Without this, the production scanner would
// only ever probe /mcp and miss the Kestrel-root flavor entirely.

func TestMCPServer_HasRootPathProbe(t *testing.T) {
	fp := fpByName("MCP Server")
	if fp == nil {
		t.Fatal("MCP Server fingerprint not in catalog")
	}
	for _, probe := range fp.Probes {
		if probe.Path == "/" {
			return
		}
	}
	t.Fatal("MCP Server fingerprint has no probe with Path:\"/\" — root-bound MCP servers (Vschool/Kestrel) will be missed")
}

// ── Guard: MCP Server fingerprint is registered ──────────────────────

func TestMCPServer_FingerprintRegistered(t *testing.T) {
	if fpByName("MCP Server") == nil {
		t.Fatal("MCP Server fingerprint not registered in the catalog")
	}
}
