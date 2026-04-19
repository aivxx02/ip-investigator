package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ip-investigator/models"
)

type AbuseIPDB struct {
	Key     string
	baseURL string
	timeout time.Duration
}

func (e *AbuseIPDB) Name() string { return "AbuseIPDB" }

func (e *AbuseIPDB) Enrich(ctx context.Context, ip string) models.EnrichResult {
	if e.Key == "" {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "no API key"}
	}
	base := e.baseURL
	if base == "" {
		base = "https://api.abuseipdb.com/api/v2"
	}
	timeout := e.timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	url := fmt.Sprintf("%s/check?ipAddress=%s&maxAgeInDays=90", base, ip)
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	req.Header.Set("Key", e.Key)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusPartial, Note: "daily limit reached"}
	}
	if resp.StatusCode != 200 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	var body struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
			LastReportedAt       string `json:"lastReportedAt"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "parse error"}
	}

	return models.EnrichResult{
		Tool:   e.Name(),
		Status: models.StatusOK,
		Data: models.AbuseIPDBResult{
			Score:      body.Data.AbuseConfidenceScore,
			Reports:    body.Data.TotalReports,
			LastReport: body.Data.LastReportedAt,
		},
	}
}
