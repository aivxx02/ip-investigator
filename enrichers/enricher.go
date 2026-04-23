package enrichers

import (
	"context"
	"sync"
	"time"

	"ip-investigator/models"
)

// Enricher is the interface every threat-intel source must implement.
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, ip string) models.EnrichResult
}

// RunAll runs all enrichers concurrently and returns results in original order.
func RunAll(ctx context.Context, ip string, all []Enricher) []models.EnrichResult {
	results := make([]models.EnrichResult, len(all))
	var wg sync.WaitGroup
	for i, e := range all {
		wg.Add(1)
		go func(idx int, enr Enricher) {
			defer wg.Done()
			results[idx] = enr.Enrich(ctx, ip)
		}(i, e)
	}
	wg.Wait()
	return results
}

// RunAllLive runs all enrichers concurrently and sends each result to ch as it
// completes. ch is closed when all enrichers finish. Each result has Index and
// Elapsed set. RunAll is unchanged and used by existing tests.
func RunAllLive(ctx context.Context, ip string, all []Enricher, ch chan<- models.EnrichResult) {
	var wg sync.WaitGroup
	for i, e := range all {
		wg.Add(1)
		go func(idx int, enr Enricher) {
			defer wg.Done()
			start := time.Now()
			r := enr.Enrich(ctx, ip)
			r.Index = idx
			r.Elapsed = time.Since(start)
			ch <- r
		}(i, e)
	}
	wg.Wait()
	close(ch)
}
