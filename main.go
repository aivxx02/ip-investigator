package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ip-investigator/config"
	"ip-investigator/enrichers"
	"ip-investigator/models"
	"ip-investigator/progress"
	"ip-investigator/report"
	"ip-investigator/summary"
)

func main() {
	ips, err := collectIPs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		fmt.Fprintln(os.Stderr, "Usage: ip-investigator <ip>")
		fmt.Fprintln(os.Stderr, "       ip-investigator --file ips.txt")
		os.Exit(1)
	}

	var valid []string
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping invalid IP %q\n", ip)
			continue
		}
		valid = append(valid, ip)
	}
	if len(valid) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no valid IPs found")
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	for i, ip := range valid {
		runIP(ip, cfg)
		if i < len(valid)-1 {
			fmt.Fprintln(os.Stdout, strings.Repeat("─", 60))
		}
	}
}

func runIP(ip string, cfg *config.Config) {
	all := []enrichers.Enricher{
		&enrichers.IPInfo{Key: cfg.IPInfoKey},
		&enrichers.ReverseDNS{},
		&enrichers.WHOIS{},
		&enrichers.VirusTotal{Key: cfg.VirusTotalKey},
		&enrichers.GoogleTI{Key: cfg.GoogleTIKey},
		&enrichers.AbuseIPDB{Key: cfg.AbuseIPDBKey},
		&enrichers.GreyNoise{Key: cfg.GreyNoiseKey},
		&enrichers.OTX{Key: cfg.OTXKey},
		&enrichers.Shodan{Key: cfg.ShodanKey},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tracker := progress.New(nil)
	tracker.Start(ip, toolNames(all))

	ch := make(chan models.EnrichResult, len(all))
	results := make([]models.EnrichResult, len(all))
	go enrichers.RunAllLive(ctx, ip, all, ch)
	for r := range ch {
		results[r.Index] = r
		tracker.Complete(r.Index, r.Status, r.Elapsed, r.Note)
	}

	var aiText string
	if cfg.OpenRouterKey != "" {
		tracker.StartAI()
		aiCtx, aiCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer aiCancel()
		aiStart := time.Now()
		o := &summary.OpenRouter{Key: cfg.OpenRouterKey, Model: cfg.OpenRouterModel}
		var err error
		aiText, err = o.Summarize(aiCtx, ip, results)
		if err != nil {
			aiText = fmt.Sprintf("(OpenRouter unavailable: %v)", err)
		}
		tracker.DoneAI(time.Since(aiStart))
	}

	tracker.Clear()
	report.Render(os.Stdout, ip, results, aiText)
}

func collectIPs() ([]string, error) {
	args := os.Args[1:]

	if len(args) == 0 {
		return nil, fmt.Errorf("Please provide an IP address or use --file to provide a list of IPs")
	}

	// --file flag
	if args[0] == "--file" {
		if len(args) < 2 {
			return nil, fmt.Errorf("Please provide a file path after --file (example: --file ips.txt)")
		}
		path := args[1]
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".txt" && ext != ".md" {
			return nil, fmt.Errorf("Only .txt or .md files are supported. Please convert your file and try again")
		}
		return readIPsFromFile(path)
	}

	// multiple bare args
	if len(args) > 1 {
		return nil, fmt.Errorf("To scan multiple IPs, save them in a .txt file and use --file instead")
	}

	return []string{args[0]}, nil
}

func readIPsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Could not open the file. Please check the path and try again")
	}
	defer f.Close()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("Something went wrong while reading the file. Make sure it is not corrupted")
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("No valid IP addresses were found in the file. Please check the contents and try again")
	}
	return ips, nil
}

func toolNames(all []enrichers.Enricher) []string {
	names := make([]string, len(all))
	for i, e := range all {
		names[i] = e.Name()
	}
	return names
}
