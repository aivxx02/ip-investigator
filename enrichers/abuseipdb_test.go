package enrichers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ip-investigator/models"
)

func TestAbuseIPDB_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") == "" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"abuseConfidenceScore": 97,
				"totalReports":         142,
				"lastReportedAt":       "2024-01-14T10:00:00+00:00",
			},
		})
	}))
	defer srv.Close()

	e := &AbuseIPDB{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "185.220.101.45")

	if result.Status != models.StatusOK {
		t.Fatalf("status = %v, want StatusOK", result.Status)
	}
	data := result.Data.(models.AbuseIPDBResult)
	if data.Score != 97 {
		t.Errorf("Score = %d, want 97", data.Score)
	}
	if data.Reports != 142 {
		t.Errorf("Reports = %d, want 142", data.Reports)
	}
}

func TestAbuseIPDB_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
	}))
	defer srv.Close()

	e := &AbuseIPDB{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusPartial {
		t.Errorf("expected StatusPartial on 429, got %v", result.Status)
	}
}

func TestAbuseIPDB_NoKey(t *testing.T) {
	e := &AbuseIPDB{Key: ""}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusError {
		t.Errorf("expected StatusError, got %v", result.Status)
	}
}
