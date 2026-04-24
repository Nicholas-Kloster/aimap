package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// ── ASCII banner ────────────────────────────────────────────────────

var asciiBanner = `
   █████╗ ██╗███╗   ███╗ █████╗ ██████╗
  ██╔══██╗██║████╗ ████║██╔══██╗██╔══██╗
  ███████║██║██╔████╔██║███████║██████╔╝
  ██╔══██║██║██║╚██╔╝██║██╔══██║██╔═══╝
  ██║  ██║██║██║ ╚═╝ ██║██║  ██║██║
  ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝`

func printBanner() {
	fmt.Println(cyan(asciiBanner))
	fmt.Println(dim("  AI Infrastructure Mapper v1.0"))
	fmt.Println(dim("  by NuClide"))
}

// ── Phase headers ───────────────────────────────────────────────────

func printPhase(num int, title string) {
	fmt.Printf("\n  %s\n", bold(fmt.Sprintf("PHASE %d: %s", num, title)))
	fmt.Println("  " + dim(strings.Repeat("─", 58)))
}

// ── Progress bar ────────────────────────────────────────────────────

func startProgress(progress *atomic.Int64, total int64) chan struct{} {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(150 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				renderProgress(progress.Load(), total)
			}
		}
	}()
	return stop
}

func renderProgress(current, total int64) {
	if total == 0 {
		return
	}
	pct := float64(current) / float64(total) * 100
	if pct > 100 {
		pct = 100
	}
	width := 40
	filled := int(float64(width) * pct / 100)
	if filled > width {
		filled = width
	}
	bar := cGreen + strings.Repeat("█", filled) + cReset + strings.Repeat(" ", width-filled)
	fmt.Printf("\r    [%s] %.0f%% — %s ports scanned", bar, pct, fmtNum(int(current)))
}

func finalizeProgress(total int64) {
	bar := green(strings.Repeat("█", 40))
	fmt.Printf("\r    [%s] 100%% — %s ports scanned\n", bar, fmtNum(int(total)))
}

// ── Phase 1 results ─────────────────────────────────────────────────

func printOpenPorts(ports []PortResult) {
	hosts := uniqueHosts(ports)
	fmt.Printf("\n  %s Found %s across %s\n",
		green("✓"),
		green(fmt.Sprintf("%d open port(s)", len(ports))),
		green(fmt.Sprintf("%d host(s)", hosts)))
}

// ── Phase 2 results ─────────────────────────────────────────────────

func printFingerprints(services []ServiceMatch, totalPorts int) {
	fmt.Println()
	for i, svc := range services {
		fmt.Printf("    [%d/%d] %s:%d → %s %s\n",
			i+1, totalPorts, svc.Host, svc.Port,
			green(svc.Service), dim(svc.Version))
	}
	hosts := uniqueServiceHosts(services)
	fmt.Printf("\n  %s Identified %s across %s\n",
		green("✓"),
		green(fmt.Sprintf("%d AI service(s)", len(services))),
		green(fmt.Sprintf("%d host(s)", hosts)))
}

// ── Phase 3: service cards ──────────────────────────────────────────

func printServiceCard(er EnumResult) {
	border := dim("│")
	fmt.Println()
	fmt.Println(dim("  ┌" + strings.Repeat("─", 62) + "┐"))
	fmt.Printf("  %s %s:%d — %s %s\n", border,
		er.Host, er.Port, bold(er.Service), er.Version)
	fmt.Printf("  %s   Auth: %s  Risk: %s\n", border,
		authDisplay(er.AuthStatus), riskBadge(er.RiskLevel))

	if len(er.Details) > 0 {
		fmt.Println("  " + border)
		for _, d := range er.Details {
			fmt.Printf("  %s   %s\n", border, d)
		}
	}

	if len(er.Findings) > 0 {
		fmt.Println("  " + border)
		for _, f := range er.Findings {
			fmt.Printf("  %s   %s %s\n", border, sevIcon(f.Severity), bold(f.Title))
			if f.Detail != "" {
				det := f.Detail
				if len(det) > 56 {
					det = det[:53] + "..."
				}
				fmt.Printf("  %s       %s\n", border, dim(det))
			}
		}
	}
	fmt.Println(dim("  └" + strings.Repeat("─", 62) + "┘"))
}

// ── Summary table ───────────────────────────────────────────────────

func printSummaryTable(results []EnumResult) {
	fmt.Println()
	fmt.Printf("  %-18s %-7s %-14s %-10s%s\n",
		"HOST", "PORT", "SERVICE", "AUTH", "RISK")
	fmt.Println("  " + strings.Repeat("─", 58))

	for _, er := range results {
		authText := "NONE"
		authColor := cRed
		if er.AuthStatus != "none" && er.AuthStatus != "unknown" {
			authText = "LOGIN"
			authColor = cYellow
		}
		fmt.Printf("  %-18s %-7d %-14s %s  %s\n",
			truncStr(er.Host, 18), er.Port,
			truncStr(er.Service, 14),
			colorPad(authText, authColor, 8),
			riskBadge(er.RiskLevel))
	}
}

// ── Stats ───────────────────────────────────────────────────────────

func printStats(rpt ScanReport) {
	fmt.Println()
	fmt.Printf("  Hosts scanned:     %s\n", fmtNum(rpt.Summary.TotalTargets))
	fmt.Printf("  AI services found: %d\n", rpt.Summary.ServicesFound)
	if rpt.Summary.Unauthed > 0 {
		fmt.Printf("  Unauthenticated:   %s\n", red(fmt.Sprintf("%d", rpt.Summary.Unauthed)))
	}
	fmt.Printf("  Total findings:    %d\n", rpt.Summary.TotalFindings)

	fmt.Println()
	if rpt.Summary.Critical > 0 {
		fmt.Printf("    %s %s\n", sevIcon("critical"), red(fmt.Sprintf("%d Critical", rpt.Summary.Critical)))
	}
	if rpt.Summary.High > 0 {
		fmt.Printf("    %s %s\n", sevIcon("high"), red(fmt.Sprintf("%d High", rpt.Summary.High)))
	}
	if rpt.Summary.Medium > 0 {
		fmt.Printf("    %s %s\n", sevIcon("medium"), yellow(fmt.Sprintf("%d Medium", rpt.Summary.Medium)))
	}
	if rpt.Summary.Low > 0 {
		fmt.Printf("    %s %s\n", sevIcon("low"), blue(fmt.Sprintf("%d Low", rpt.Summary.Low)))
	}
	if rpt.Summary.Info > 0 {
		fmt.Printf("    %s %s\n", sevIcon("info"), dim(fmt.Sprintf("%d Info", rpt.Summary.Info)))
	}

	fmt.Printf("\n  Scan duration: %s\n", rpt.Summary.Duration)
}

// ── Report builder ──────────────────────────────────────────────────

func buildReport(hosts []string, portsPerHost int, openPorts []PortResult,
	services []ServiceMatch, enumResults []EnumResult, duration time.Duration) ScanReport {

	rpt := ScanReport{
		Tool:         "aimap",
		ToolVersion:  "1.0.0",
		Target:       strings.Join(hosts, ", "),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		PortsScanned: len(hosts) * portsPerHost,
		OpenPorts:    openPorts,
		Services:     services,
		EnumResults:  enumResults,
	}
	rpt.Summary.TotalTargets = len(hosts)
	rpt.Summary.OpenPorts = len(openPorts)
	rpt.Summary.ServicesFound = len(services)
	rpt.Summary.Duration = duration.Round(time.Second).String()

	for _, er := range enumResults {
		if er.AuthStatus == "none" {
			rpt.Summary.Unauthed++
		}
		for _, f := range er.Findings {
			rpt.Summary.TotalFindings++
			switch f.Severity {
			case "critical":
				rpt.Summary.Critical++
			case "high":
				rpt.Summary.High++
			case "medium":
				rpt.Summary.Medium++
			case "low":
				rpt.Summary.Low++
			default:
				rpt.Summary.Info++
			}
		}
	}
	return rpt
}

// ── JSON output ─────────────────────────────────────────────────────

func writeJSON(rpt ScanReport, path string) {
	data, err := json.MarshalIndent(rpt, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  %s JSON error: %v\n", red("[!]"), err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "\n  %s Write error: %v\n", red("[!]"), err)
		return
	}
	fmt.Printf("\n  %s JSON report written to %s\n", green("✓"), path)
}

// ── Helpers ─────────────────────────────────────────────────────────

func authDisplay(s string) string {
	if s == "none" {
		return red("NONE") + " — " + red("Unauthenticated")
	}
	if strings.Contains(s, "required") {
		return green(s)
	}
	return yellow(s)
}

func uniqueHosts(ports []PortResult) int {
	seen := make(map[string]bool)
	for _, p := range ports {
		seen[p.Host] = true
	}
	return len(seen)
}

func uniqueServiceHosts(services []ServiceMatch) int {
	seen := make(map[string]bool)
	for _, s := range services {
		seen[s.Host] = true
	}
	return len(seen)
}
