package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"ip-investigator/config"
	"ip-investigator/enrichers"
	"ip-investigator/report"
	"ip-investigator/summary"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: ip-investigator <ip>")
		os.Exit(1)
	}

	ip := os.Args[1]
	if net.ParseIP(ip) == nil {
		fmt.Fprintf(os.Stderr, "Error: %q is not a valid IP address\n", ip)
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

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

	results := enrichers.RunAll(ctx, ip, all)

	var aiText string
	if cfg.GeminiKey != "" {
		g := &summary.Gemini{Key: cfg.GeminiKey}
		aiText, err = g.Summarize(ctx, ip, results)
		if err != nil {
			aiText = fmt.Sprintf("(Gemini unavailable: %v)", err)
		}
	}

	report.Render(os.Stdout, ip, results, aiText)
}
