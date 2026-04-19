package enrichers

import (
	"context"
	"sync"

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
