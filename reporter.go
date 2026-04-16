package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ── Banner ──────────────────────────────────────────────────────────

func printBanner(hosts []string, ports []int) {
	fmt.Println()
	fmt.Println(cyan("┌──────────────────────────────────────────────────────────────┐"))
	fmt.Println(cyan("│") + "  " + bold("aimap v1.0.0") + " -- AI Infrastructure Scanner" + "                   " + cyan("│"))
	fmt.Println(cyan("└──────────────────────────────────────────────────────────────┘"))

	hostStr := strings.Join(hosts, ", ")
	if len(hostStr) > 50 {
		hostStr = hostStr[:47] + "..."
	}
	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = fmt.Sprintf("%d", p)
	}
	portStr := strings.Join(portStrs, ",")
	if len(portStr) > 50 {
		portStr = portStr[:47] + "..."
	}

	fmt.Printf("  Targets:      %s\n", hostStr)
	fmt.Printf("  Ports:        %s\n", portStr)
	fmt.Printf("  Time:         %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("  Fingerprints: %d services loaded\n", len(Fingerprints))
}

// ── Results ─────────────────────────────────────────────────────────

func printReport(rpt ScanReport) {
	if len(rpt.Services) == 0 {
		fmt.Printf("\n%s No AI/ML services identified.\n", yellow("[!]"))
		printSummary(rpt)
		return
	}

	// Service table
	fmt.Println()
	printSection("SERVICE DISCOVERY")
	fmt.Printf("  %-20s %-6s %-24s %-10s %-8s %s\n",
		bold("HOST"), bold("PORT"), bold("SERVICE"), bold("VERSION"), bold("AUTH"), bold("RISK"))
	fmt.Printf("  %-20s %-6s %-24s %-10s %-8s %s\n",
		strings.Repeat("─", 20), strings.Repeat("─", 5),
		strings.Repeat("─", 24), strings.Repeat("─", 10),
		strings.Repeat("─", 8), strings.Repeat("─", 10))

	for _, er := range rpt.EnumResults {
		fmt.Printf("  %-20s %-6d %-24s %-10s %-8s %s\n",
			truncStr(er.Host, 20), er.Port, er.Service,
			truncStr(er.Version, 10), truncStr(er.AuthStatus, 8),
			sevColor(er.RiskLevel))
	}

	// Per-service detail
	for _, er := range rpt.EnumResults {
		fmt.Println()
		printSection(fmt.Sprintf("%s @ %s:%d", strings.ToUpper(er.Service), er.Host, er.Port))
		fmt.Printf("  Version:     %s\n", er.Version)
		fmt.Printf("  Auth:        %s\n", authColor(er.AuthStatus))
		fmt.Printf("  Risk:        %s\n", sevColor(er.RiskLevel))

		if len(er.Findings) > 0 {
			fmt.Println()
			for _, f := range er.Findings {
				fmt.Printf("  [%s] %s\n", sevColor(f.Severity), f.Title)
				if f.Detail != "" {
					det := f.Detail
					if len(det) > 72 {
						det = det[:69] + "..."
					}
					fmt.Printf("  %s %s\n", dim("│"), det)
				}
			}
		}
	}

	printSummary(rpt)
}

func printSummary(rpt ScanReport) {
	fmt.Println()
	printSection("SUMMARY")
	fmt.Printf("  Targets scanned:   %d\n", rpt.Summary.TotalTargets)
	fmt.Printf("  Open ports:        %d\n", rpt.Summary.OpenPorts)
	fmt.Printf("  Services found:    %d\n", rpt.Summary.ServicesFound)
	fmt.Printf("  Findings:          %s crit / %s high / %s med / %s low / %s info\n",
		red(fmt.Sprintf("%d", rpt.Summary.Critical)),
		red(fmt.Sprintf("%d", rpt.Summary.High)),
		yellow(fmt.Sprintf("%d", rpt.Summary.Medium)),
		blue(fmt.Sprintf("%d", rpt.Summary.Low)),
		dim(fmt.Sprintf("%d", rpt.Summary.Info)))
	fmt.Println()
}

func printSection(title string) {
	pad := 60 - len(title)
	if pad < 4 {
		pad = 4
	}
	fmt.Printf("%s %s %s\n", cyan("──"), bold(title), cyan(strings.Repeat("─", pad)))
}

// ── Report builder ──────────────────────────────────────────────────

func buildReport(hosts []string, portsPerHost int, openPorts []PortResult,
	services []ServiceMatch, enumResults []EnumResult) ScanReport {

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

	for _, er := range enumResults {
		for _, f := range er.Findings {
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
		fmt.Fprintf(os.Stderr, "%s JSON marshal error: %v\n", red("[!]"), err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to write %s: %v\n", red("[!]"), path, err)
		return
	}
	fmt.Printf("%s Report saved: %s (%d bytes)\n", green("[+]"), path, len(data))
}

// ── Helpers ─────────────────────────────────────────────────────────

func truncStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "~"
}

func authColor(s string) string {
	if s == "none" {
		return red("none (unauthenticated)")
	}
	if strings.Contains(s, "required") {
		return green(s)
	}
	return yellow(s)
}
