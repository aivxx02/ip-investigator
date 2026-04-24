package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"ip-investigator/config"
	"ip-investigator/enrichers"
	"ip-investigator/models"
	"ip-investigator/progress"
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

	tracker := progress.New(nil)
	tracker.Start(ip, toolNames(all))

	ch := make(chan models.EnrichResult, len(all))
	results := make([]models.EnrichResult, len(all))
	go enrichers.RunAllLive(ctx, ip, all, ch)
	for r := range ch {
		results[r.Index] = r
		tracker.Complete(r.Index, r.Status, r.Elapsed)
	}

	var aiText string
	if cfg.OpenRouterKey != "" {
		tracker.StartAI()
		aiCtx, aiCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer aiCancel()
		aiStart := time.Now()
		o := &summary.OpenRouter{Key: cfg.OpenRouterKey, Model: cfg.OpenRouterModel}
		aiText, err = o.Summarize(aiCtx, ip, results)
		if err != nil {
			aiText = fmt.Sprintf("(OpenRouter unavailable: %v)", err)
		}
		tracker.DoneAI(time.Since(aiStart))
	}

	tracker.Clear()
	report.Render(os.Stdout, ip, results, aiText)
}

func toolNames(all []enrichers.Enricher) []string {
	names := make([]string, len(all))
	for i, e := range all {
		names[i] = e.Name()
	}
	return names
}
