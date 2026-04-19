package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ip-investigator/models"
)

type Shodan struct {
	Key     string
	baseURL string
	timeout time.Duration
}

func (e *Shodan) Name() string { return "Shodan" }

func (e *Shodan) Enrich(ctx context.Context, ip string) models.EnrichResult {
	if e.Key == "" {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "no API key"}
	}
	base := e.baseURL
	if base == "" {
		base = "https://api.shodan.io/shodan/host"
	}
	timeout := e.timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	url := fmt.Sprintf("%s/%s?key=%s", base, ip, e.Key)
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}

	resp, err := client.Do(req)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusNoData}
	}
	if resp.StatusCode == 401 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "invalid API key"}
	}
	if resp.StatusCode != 200 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	var body struct {
		Ports      []int  `json:"ports"`
		LastUpdate string `json:"last_update"`
		Data       []struct {
			Banner string         `json:"banner"`
			Vulns  map[string]any `json:"vulns"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "parse error"}
	}

	seen := map[string]struct{}{}
	var banners, cves []string
	for _, d := range body.Data {
		if d.Banner != "" {
			banners = append(banners, d.Banner)
		}
		for cve := range d.Vulns {
			if _, ok := seen[cve]; !ok {
				seen[cve] = struct{}{}
				cves = append(cves, cve)
			}
		}
	}

	return models.EnrichResult{
		Tool:   e.Name(),
		Status: models.StatusOK,
		Data: models.ShodanResult{
			Ports:    body.Ports,
			Banners:  banners,
			CVEs:     cves,
			LastScan: body.LastUpdate,
		},
	}
}
