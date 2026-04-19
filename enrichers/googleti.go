package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ip-investigator/models"
)

type GoogleTI struct {
	Key     string
	baseURL string
	timeout time.Duration
}

func (e *GoogleTI) Name() string { return "Google TI" }

func (e *GoogleTI) Enrich(ctx context.Context, ip string) models.EnrichResult {
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
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusPartial, Note: "rate limit"}
	}
	if resp.StatusCode != 200 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	var body struct {
		Data struct {
			Attributes struct {
				ThreatSeverity struct {
					LevelDescription string `json:"level_description"`
				} `json:"threat_severity"`
				CrowdsourcedContext []struct {
					Title string `json:"title"`
				} `json:"crowdsourced_context"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "parse error"}
	}

	verdict := body.Data.Attributes.ThreatSeverity.LevelDescription
	if verdict == "" {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusNoData}
	}

	result := models.GoogleTIResult{
		Verdict:   verdict,
		Campaigns: len(body.Data.Attributes.CrowdsourcedContext),
	}
	if len(body.Data.Attributes.CrowdsourcedContext) > 0 {
		result.Actor = body.Data.Attributes.CrowdsourcedContext[0].Title
	}
	return models.EnrichResult{Tool: e.Name(), Status: models.StatusOK, Data: result}
}
