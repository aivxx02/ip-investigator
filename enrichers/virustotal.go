package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ip-investigator/models"
)

type VirusTotal struct {
	Key     string
	baseURL string
	timeout time.Duration
}

func (e *VirusTotal) Name() string { return "VirusTotal" }

func (e *VirusTotal) Enrich(ctx context.Context, ip string) models.EnrichResult {
	if e.Key == "" {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "no API key"}
	}
	base := e.baseURL
	if base == "" {
		base = "https://www.virustotal.com/api/v3"
	}
	timeout := e.timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	url := fmt.Sprintf("%s/ip_addresses/%s", base, ip)
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	req.Header.Set("x-apikey", e.Key)

	resp, err := client.Do(req)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusPartial, Note: "rate limit reached"}
	}
	if resp.StatusCode != 200 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	var body struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				Categories map[string]string `json:"categories"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "parse error"}
	}

	stats := body.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected

	// Deduplicate categories (multiple engines may report the same category)
	seen := make(map[string]struct{})
	var categories []string
	for _, v := range body.Data.Attributes.Categories {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			categories = append(categories, v)
		}
	}

	return models.EnrichResult{
		Tool:   e.Name(),
		Status: models.StatusOK,
		Data: models.VirusTotalResult{
			Detections: stats.Malicious,
			Total:      total,
			Categories: categories,
		},
	}
}
