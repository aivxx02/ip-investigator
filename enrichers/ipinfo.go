package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ip-investigator/models"
)

type IPInfo struct {
	Key     string
	baseURL string        // override in tests
	timeout time.Duration // override in tests
}

func (e *IPInfo) Name() string { return "ipinfo.io" }

func (e *IPInfo) Enrich(ctx context.Context, ip string) models.EnrichResult {
	base := e.baseURL
	if base == "" {
		base = "https://ipinfo.io"
	}
	timeout := e.timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	url := fmt.Sprintf("%s/%s/json", base, ip)
	if e.Key != "" {
		url += "?token=" + e.Key
	}

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

	var raw struct {
		Country string `json:"country"`
		City    string `json:"city"`
		Org     string `json:"org"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: "parse error"}
	}
	if raw.Country == "" {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusNoData}
	}

	asn, isp := models.ParseOrg(raw.Org)
	return models.EnrichResult{
		Tool:   e.Name(),
		Status: models.StatusOK,
		Data: models.GeoResult{
			Country: raw.Country,
			City:    raw.City,
			ASN:     asn,
			ISP:     isp,
		},
	}
}
