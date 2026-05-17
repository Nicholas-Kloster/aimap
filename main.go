package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func main() {
	target := flag.String("target", "", "Single target (IP, hostname, or CIDR)")
	list := flag.String("list", "", "File containing list of targets (one per line)")
	ports := flag.String("ports",
		"80,443,1984,2379,3000,3001,4000,4040,4200,5000,5001,5678,6333,7575,7576,7860,8000,8001,8080,8081,8088,8123,8233,8265,8443,8501,8787,8888,8889,9000,9090,9091,9200,10000,11434,15500,18080,18789,19530,30000,51000,55000",
		"Comma-separated ports to scan")
	timeout := flag.Duration("timeout", 5*time.Second, "Connection timeout")
	threads := flag.Int("threads", 20, "Concurrent scan threads")
	output := flag.String("o", "", "JSON report output file")
	verbose := flag.Bool("v", false, "Verbose output")
	scanAll := flag.Bool("scan-all-fingerprints", false,
		"Probe every fingerprint against every open port (bypasses DefaultPorts filter). "+
			"Use when services may be on non-canonical ports; trades ~30x more requests for thorough coverage.")
	excludeCompromised := flag.Bool("exclude-compromised", false,
		"Drop hosts marked compromised-by-extortion (e.g. Meow-class wiped Elasticsearch with read_me index) from the JSON report. "+
			"Use for disclosure-pipeline input — you don't want to send 'your host is exposed' to a host that's already been wiped.")
	flag.Parse()

	scanAllFingerprints = *scanAll

	if *target == "" && flag.NArg() > 0 {
		*target = flag.Arg(0)
	}

	var hosts []string
	if *target != "" {
		hosts = parseTargetsVerbose(*target, os.Stderr)
	}
	if *list != "" {
		f, err := os.Open(*list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Cannot open target list: %v\n", err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			hosts = append(hosts, parseTargetsVerbose(line, os.Stderr)...)
		}
		f.Close()
	}

	if len(hosts) == 0 {
		printBanner()
		fmt.Println()
		fmt.Println("  Usage:")
		fmt.Println("    aimap -target <ip|host|cidr> [flags]")
		fmt.Println("    aimap -list targets.txt [flags]")
		fmt.Println()
		flag.PrintDefaults()
		fmt.Printf("\n  Fingerprints: %d AI/ML services\n\n", len(Fingerprints))
		os.Exit(0)
	}

	var portList []int
	for _, p := range strings.Split(*ports, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			portList = append(portList, n)
		}
	}

	targets := make([]Target, len(hosts))
	for i, h := range hosts {
		targets[i] = Target{Host: h, Ports: portList}
	}

	startTime := time.Now()

	// ── Banner ───────────────────────────────────────────────────
	printBanner()

	// ── Phase 1: Port Scan ───────────────────────────────────────
	printPhase(1, "PORT DISCOVERY")
	fmt.Println()
	fmt.Printf("    Scanning %s (%s hosts)\n", *target, fmtNum(len(hosts)))

	portStrs := make([]string, len(portList))
	for i, p := range portList {
		portStrs[i] = fmt.Sprintf("%d", p)
	}
	portStr := strings.Join(portStrs, ",")
	if len(portStr) > 55 {
		portStr = portStr[:52] + "..."
	}
	fmt.Printf("    Ports: %s\n", portStr)
	fmt.Printf("    Threads: %d\n", *threads)
	fmt.Println()

	var progress atomic.Int64
	total := int64(len(hosts)) * int64(len(portList))

	var stopCh chan struct{}
	if !*verbose {
		stopCh = startProgress(&progress, total)
	}
	// Watchdog: warn on stderr if scan stalls. Threshold scales with the
	// connection timeout — three failed connection attempts' worth of time
	// is a reasonable "something's wrong" signal.
	stallThreshold := 12 * (*timeout)
	if stallThreshold < 30*time.Second {
		stallThreshold = 30 * time.Second
	}
	watchdogStop := startWatchdog(&progress, stallThreshold, os.Stderr)

	openPorts := scanPorts(targets, *timeout, *threads, *verbose, &progress)

	close(watchdogStop)
	if !*verbose {
		close(stopCh)
		time.Sleep(20 * time.Millisecond) // let goroutine exit
		finalizeProgress(int64(len(hosts)))
	}

	printOpenPorts(openPorts)

	if len(openPorts) == 0 {
		fmt.Printf("\n  %s No open ports — nothing to fingerprint.\n\n", yellow("[!]"))
		if *output != "" {
			rpt := buildReport(hosts, len(portList), openPorts, nil, nil, time.Since(startTime))
			writeJSON(rpt, *output)
		}
		return
	}

	// ── Phase 2: Fingerprinting ──────────────────────────────────
	printPhase(2, "AI SERVICE FINGERPRINTING")

	services := matchFingerprints(openPorts, *timeout, *verbose, *threads)

	if len(services) == 0 {
		fmt.Printf("\n  %s No AI/ML services identified on open ports.\n\n", yellow("[!]"))
		if *output != "" {
			rpt := buildReport(hosts, len(portList), openPorts, services, nil, time.Since(startTime))
			writeJSON(rpt, *output)
		}
		return
	}

	printFingerprints(services, len(openPorts))

	// ── Phase 3: Deep Enumeration ────────────────────────────────
	printPhase(3, "DEEP ENUMERATION")

	enumResults := runEnumerators(services, *timeout, *verbose, *threads)

	// ── Extortion filter (v1.9.9) ────────────────────────────────
	// --exclude-compromised drops hosts that aimap classified as
	// compromised-by-extortion (Meow / Indexrm-class read_me marker).
	// These are NOT valid "your-host-is-exposed" disclosure targets —
	// they're already-compromised hosts that need a different framing.
	if *excludeCompromised {
		var filtered []EnumResult
		dropped := 0
		for _, er := range enumResults {
			tag, _ := er.RawData["pipeline_tag"].(string)
			if tag == "compromised-wiped" || tag == "compromised-marked" {
				dropped++
				continue
			}
			filtered = append(filtered, er)
		}
		if dropped > 0 {
			fmt.Printf("\n  [v1.9.9 filter] Excluded %d compromised-by-extortion host(s) from report (use without --exclude-compromised to see them).\n\n", dropped)
		}
		enumResults = filtered
	}

	for _, er := range enumResults {
		printServiceCard(er)
	}

	// ── ML adjacency (Insight #20) ───────────────────────────────
	adjacencies := buildAdjacencies(services, openPorts)
	printAdjacencies(adjacencies)

	// ── Summary ──────────────────────────────────────────────────
	printSummaryTable(enumResults)

	rpt := buildReport(hosts, len(portList), openPorts, services, enumResults, time.Since(startTime))
	printStats(rpt)

	if *output != "" {
		writeJSON(rpt, *output)
	}

	fmt.Println()
}
