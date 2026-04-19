package enrichers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ip-investigator/models"
)

func TestShodan_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ports":       []int{22, 443, 4444},
			"last_update": "2024-01-10T00:00:00",
			"data": []map[string]any{
				{
					"port":   22,
					"banner": "SSH-2.0-OpenSSH_8.2",
					"vulns":  map[string]any{"CVE-2023-38408": map[string]any{}},
				},
			},
		})
	}))
	defer srv.Close()

	e := &Shodan{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "185.220.101.45")

	if result.Status != models.StatusOK {
		t.Fatalf("status = %v, want StatusOK", result.Status)
	}
	data := result.Data.(models.ShodanResult)
	if len(data.Ports) != 3 {
		t.Errorf("Ports count = %d, want 3", len(data.Ports))
	}
	if len(data.CVEs) == 0 {
		t.Error("expected at least one CVE")
	}
}

func TestShodan_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	e := &Shodan{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusNoData {
		t.Errorf("expected StatusNoData, got %v", result.Status)
	}
}

func TestShodan_NoKey(t *testing.T) {
	e := &Shodan{Key: ""}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusError {
		t.Errorf("expected StatusError, got %v", result.Status)
	}
}
