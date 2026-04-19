package enrichers

import (
	"context"
	"testing"
	"time"

	"ip-investigator/models"
)

type fakeEnricher struct {
	name   string
	delay  time.Duration
	result models.EnrichResult
}

func (f *fakeEnricher) Name() string { return f.name }
func (f *fakeEnricher) Enrich(ctx context.Context, ip string) models.EnrichResult {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.result
}

func TestRunAll_OrderPreserved(t *testing.T) {
	all := []Enricher{
		&fakeEnricher{name: "A", result: models.EnrichResult{Tool: "A", Status: models.StatusOK}},
		&fakeEnricher{name: "B", result: models.EnrichResult{Tool: "B", Status: models.StatusError}},
		&fakeEnricher{name: "C", result: models.EnrichResult{Tool: "C", Status: models.StatusNoData}},
	}
	results := RunAll(context.Background(), "1.2.3.4", all)
	for i, want := range []string{"A", "B", "C"} {
		if results[i].Tool != want {
			t.Errorf("results[%d].Tool = %q, want %q", i, results[i].Tool, want)
		}
	}
}

func TestRunAll_RunsConcurrently(t *testing.T) {
	all := []Enricher{
		&fakeEnricher{name: "A", delay: 100 * time.Millisecond, result: models.EnrichResult{Tool: "A"}},
		&fakeEnricher{name: "B", delay: 100 * time.Millisecond, result: models.EnrichResult{Tool: "B"}},
		&fakeEnricher{name: "C", delay: 100 * time.Millisecond, result: models.EnrichResult{Tool: "C"}},
	}
	start := time.Now()
	RunAll(context.Background(), "1.2.3.4", all)
	elapsed := time.Since(start)
	if elapsed > 250*time.Millisecond {
		t.Errorf("RunAll took %v — enrichers are not running concurrently", elapsed)
	}
}
