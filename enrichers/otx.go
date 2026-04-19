package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ip-investigator/models"
)

type OTX struct {
	Key     string
	baseURL string
	timeout time.Duration
}

func (e *OTX) Name() string { return "AlienVault OTX" }

func (e *OTX) Enrich(ctx context.Context, ip string) models.EnrichResult {
	if e.Key == "" {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "no API key"}
	}
	base := e.baseURL
	if base == "" {
		base = "https://otx.alienvault.com/api/v1/indicators/IPv4"
	}
	timeout := e.timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	url := fmt.Sprintf("%s/%s/general", base, ip)
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	req.Header.Set("X-OTX-API-KEY", e.Key)

	resp, err := client.Do(req)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	var body struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Modified string `json:"modified"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "parse error"}
	}

	if body.PulseInfo.Count == 0 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusNoData}
	}

	lastSeen := ""
	if len(body.PulseInfo.Pulses) > 0 {
		lastSeen = body.PulseInfo.Pulses[0].Modified
	}

	return models.EnrichResult{
		Tool:   e.Name(),
		Status: models.StatusOK,
		Data: models.OTXResult{
			Pulses:   body.PulseInfo.Count,
			LastSeen: lastSeen,
		},
	}
}
