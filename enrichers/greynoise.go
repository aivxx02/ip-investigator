package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ip-investigator/models"
)

type GreyNoise struct {
	Key     string
	baseURL string
	timeout time.Duration
}

func (e *GreyNoise) Name() string { return "GreyNoise" }

func (e *GreyNoise) Enrich(ctx context.Context, ip string) models.EnrichResult {
	if e.Key == "" {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "no API key"}
	}
	base := e.baseURL
	if base == "" {
		base = "https://api.greynoise.io/v3/community"
	}
	timeout := e.timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	url := fmt.Sprintf("%s/%s", base, ip)
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	req.Header.Set("key", e.Key)

	resp, err := client.Do(req)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusNoData}
	}
	if resp.StatusCode == 429 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusPartial, Note: "rate limit"}
	}
	if resp.StatusCode != 200 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	var body struct {
		Classification string `json:"classification"`
		LastSeen       string `json:"last_seen"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "parse error"}
	}

	return models.EnrichResult{
		Tool:   e.Name(),
		Status: models.StatusOK,
		Data: models.GreyNoiseResult{
			Classification: body.Classification,
			LastSeen:       body.LastSeen,
		},
	}
}
