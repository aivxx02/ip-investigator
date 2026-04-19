package enrichers

import (
	"context"
	"fmt"
	"testing"

	"ip-investigator/models"
)

func TestReverseDNS_Found(t *testing.T) {
	e := &ReverseDNS{
		lookup: func(ctx context.Context, addr string) ([]string, error) {
			return []string{"tor-exit.example.com."}, nil
		},
	}
	result := e.Enrich(context.Background(), "185.220.101.45")
	if result.Status != models.StatusOK {
		t.Fatalf("status = %v, want StatusOK", result.Status)
	}
	data := result.Data.(models.ReverseDNSResult)
	if data.PTR != "tor-exit.example.com" {
		t.Errorf("PTR = %q, want tor-exit.example.com (trailing dot stripped)", data.PTR)
	}
}

func TestReverseDNS_NotFound(t *testing.T) {
	e := &ReverseDNS{
		lookup: func(ctx context.Context, addr string) ([]string, error) {
			return nil, nil
		},
	}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusNoData {
		t.Errorf("expected StatusNoData, got %v", result.Status)
	}
}

func TestReverseDNS_Error(t *testing.T) {
	e := &ReverseDNS{
		lookup: func(ctx context.Context, addr string) ([]string, error) {
			return nil, fmt.Errorf("dns timeout")
		},
	}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusNoData {
		t.Errorf("expected StatusNoData on DNS error, got %v", result.Status)
	}
}
