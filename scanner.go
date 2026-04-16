package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func scanPorts(targets []Target, timeout time.Duration, threads int, verbose bool, progress *atomic.Int64) []PortResult {
	var (
		results []PortResult
		mu      sync.Mutex
		wg      sync.WaitGroup
	)
	pool := newPool(threads)
	client := newHTTPClient(timeout)

	for _, t := range targets {
		for _, port := range t.Ports {
			wg.Add(1)
			pool.Acquire()
			go func(host string, port int) {
				defer wg.Done()
				defer pool.Release()
				defer progress.Add(1)

				addr := fmt.Sprintf("%s:%d", host, port)
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err != nil {
					if verbose {
						fmt.Printf("    %s %s\n", dim("closed"), dim(addr))
					}
					return
				}
				conn.Close()

				r := PortResult{
					Host:    host,
					Port:    port,
					Open:    true,
					Headers: make(map[string]string),
				}

				for _, scheme := range []string{"https", "http"} {
					url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
					status, hdrs, body, err := httpGET(client, url)
					if err != nil {
						continue
					}
					r.TLS = (scheme == "https")
					r.StatusCode = status
					r.Headers = hdrs
					r.Server = hdrs["Server"]
					r.ContentType = hdrs["Content-Type"]
					snip := string(body)
					if len(snip) > 500 {
						snip = snip[:500]
					}
					r.BodySnippet = snip
					break
				}

				if verbose {
					fmt.Printf("    %s %s (HTTP %d)\n", green("open"), addr, r.StatusCode)
				}

				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}(t.Host, port)
		}
	}
	wg.Wait()
	return results
}
