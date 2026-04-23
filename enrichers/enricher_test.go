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

func TestRunAllLive(t *testing.T) {
	tools := []Enricher{
		&fakeEnricher{name: "A", delay: 10 * time.Millisecond, result: models.EnrichResult{Tool: "A", Status: models.StatusOK}},
		&fakeEnricher{name: "B", delay: 30 * time.Millisecond, result: models.EnrichResult{Tool: "B", Status: models.StatusOK}},
		&fakeEnricher{name: "C", delay: 5 * time.Millisecond, result: models.EnrichResult{Tool: "C", Status: models.StatusOK}},
	}

	ch := make(chan models.EnrichResult, len(tools))
	ctx := context.Background()
	go RunAllLive(ctx, "1.2.3.4", tools, ch)

	var got []models.EnrichResult
	for r := range ch {
		got = append(got, r)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 results, got %d", len(got))
	}

	seen := make(map[int]bool)
	for _, r := range got {
		seen[r.Index] = true
		if r.Elapsed == 0 {
			t.Errorf("tool %s has zero Elapsed", r.Tool)
		}
	}
	for i := 0; i < 3; i++ {
		if !seen[i] {
			t.Errorf("missing Index %d in results", i)
		}
	}
}
