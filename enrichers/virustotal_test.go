package enrichers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ip-investigator/models"
)

func TestVirusTotal_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") == "" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"attributes": map[string]any{
					"last_analysis_stats": map[string]any{
						"malicious":  12,
						"suspicious": 0,
						"harmless":   82,
						"undetected": 0,
					},
					"categories": map[string]any{
						"engine1": "malware",
						"engine2": "C2",
					},
				},
			},
		})
	}))
	defer srv.Close()

	e := &VirusTotal{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "185.220.101.45")

	if result.Status != models.StatusOK {
		t.Fatalf("status = %v, want StatusOK", result.Status)
	}
	data := result.Data.(models.VirusTotalResult)
	if data.Detections != 12 {
		t.Errorf("Detections = %d, want 12", data.Detections)
	}
	if data.Total != 94 {
		t.Errorf("Total = %d, want 94", data.Total)
	}
	if len(data.Categories) == 0 {
		t.Error("expected at least one category")
	}
}

func TestVirusTotal_NoKey(t *testing.T) {
	e := &VirusTotal{Key: ""}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusError {
		t.Errorf("expected StatusError when no API key, got %v", result.Status)
	}
}

func TestVirusTotal_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
	}))
	defer srv.Close()

	e := &VirusTotal{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusPartial {
		t.Errorf("expected StatusPartial on 429, got %v", result.Status)
	}
}
