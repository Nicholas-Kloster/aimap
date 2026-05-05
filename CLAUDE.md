# aimap

`nmap` for AI infrastructure. Single Go binary that finds exposed LLM runtimes, vector databases, ML model servers, MCP servers, AI safety / eval / guardrails platforms, observability/tracing services, and orchestrators. Enumerates what's running, what's unprotected, and what data is inside via dedicated deep enumerators per platform class.

**48 service fingerprints + 30 deep enumerators** (as of v1.x — see `CHANGELOG.md`).

## Language
Go (single static binary, ~8 MB)

## Build & Run
```
go build -o aimap .

# scan a single host
aimap -target 192.0.2.10

# scan a CIDR
aimap -target 192.0.2.0/24 -threads 50

# scan from a list of targets
aimap -list ips.txt -ports 1984,5000,7575,8000,8080,11434,15500 -o report.json

# wide port coverage on one investigation host
aimap -target 192.0.2.10 -ports 80,443,3000,5000,5001,6333,7860,8000,8001,8080,8265,8443,8888,9091,11434,15500,19530,51000,55000

# tests (when added — currently 0)
go test ./...
```

## Layout
```
main.go              # CLI entry + flag parsing
fingerprints.go      # 48 service fingerprints + matcher engine (matchFingerprints, evalMatch)
enumerators.go       # 30 dedicated deep enumerators (Langfuse, MLflow, Open WebUI, Qdrant, etc.)
scanner.go           # port discovery + scheme selection (HTTP / HTTPS dual try)
reporter.go          # JSON output + terminal dashboard
utils.go             # shared HTTP client + parseJSON + jStr / jHas helpers
aimap-profile/       # companion Python tool: target classification + disclosure routing
aimap.1              # man page
PKGBUILD             # ArchLinux/BlackArch packaging
CHANGELOG.md         # release notes
dist/                # release artifacts
```

## Matcher schema (load-bearing)

A fingerprint is a `(Name, DefaultPorts[], Probes[], Severity)` tuple. Each `Probe` is `(Path, Matches[])`. **All conditions in a Probe's `Matches[]` must satisfy** for the probe to fire — conjunctive matching, not "any of":

```go
{
    Name:         "DeepEval Server",
    DefaultPorts: []int{5000, 8000, 8080},
    Probes: []Probe{
        {Path: "/api/health", Matches: []MatchCond{
            {Type: "status_code", Value: "200"},
            {Type: "json_field", Field: "service"},
            {Type: "body_contains", Value: "deepeval"},
        }},
    },
}
```

Match types: `status_code`, `body_contains`, `json_field`, `json_array`, `header_contains`.

**Methodology lesson — naked single-word `body_contains` is unsound at population scale.** Session-9 caught a bespoke probe (`data/aisafety-probe.py` in AI-LLM-Infrastructure-OSINT) that used `b"garak" in body` and `b"confident" in body` — produced 6 FPs and 0 TPs across 1,017 cloud prefixes. A personal video clip browser matched as Garak because of an anime filename "Garakuta no Kamisama". A French Discord bot matched as DeepEval because of marketing copy with "confident". Anchor every keyword match to a structured signal: `status_code` + `json_field` + `body_contains` together, not alone.

## Companion tool: `aimap-profile`

Python single-file at `aimap-profile/aimap_profile.py`. Target classification + disclosure routing. Classifies category (HIPAA / clinical / personal / commercial / research / honeypot), surfaces ethics flags, finds disclosure channels.

## Claude Code Notes
- Read README.md for the full CLI surface, output schema, risk-level taxonomy, integration examples (CI/CD, cron, SIEM)
- Read CHANGELOG.md for release history
- When extending fingerprints: never use a single-word `body_contains` as the only match condition — anchor it to `status_code` + `json_field` (see the Methodology lesson above)
- Output JSON is consumable by VisorLog ingest (`visorlog ingest --from report.json --format ndjson` with adapter, or via the broader chain)
- Built with [Claude Code](https://claude.ai/code)
