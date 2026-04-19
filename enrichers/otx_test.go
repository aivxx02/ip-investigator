package enrichers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ip-investigator/models"
)

func TestOTX_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"pulse_info": map[string]any{
				"count": 4,
				"pulses": []map[string]any{
					{"name": "Mirai botnet campaign", "modified": "2024-01-13T00:00:00"},
				},
			},
		})
	}))
	defer srv.Close()

	e := &OTX{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "185.220.101.45")

	if result.Status != models.StatusOK {
		t.Fatalf("status = %v, want StatusOK", result.Status)
	}
	data := result.Data.(models.OTXResult)
	if data.Pulses != 4 {
		t.Errorf("Pulses = %d, want 4", data.Pulses)
	}
}

func TestOTX_NoResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"pulse_info": map[string]any{"count": 0, "pulses": []any{}},
		})
	}))
	defer srv.Close()

	e := &OTX{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusNoData {
		t.Errorf("expected StatusNoData, got %v", result.Status)
	}
}

func TestOTX_NoKey(t *testing.T) {
	e := &OTX{Key: ""}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusError {
		t.Errorf("expected StatusError, got %v", result.Status)
	}
}
