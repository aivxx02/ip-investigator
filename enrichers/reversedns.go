package enrichers

import (
	"context"
	"net"
	"strings"

	"ip-investigator/models"
)

type ReverseDNS struct {
	lookup func(ctx context.Context, addr string) ([]string, error)
}

func (e *ReverseDNS) Name() string { return "Reverse DNS" }

func (e *ReverseDNS) Enrich(ctx context.Context, ip string) models.EnrichResult {
	fn := e.lookup
	if fn == nil {
		fn = net.DefaultResolver.LookupAddr
	}
	names, err := fn(ctx, ip)
	if err != nil || len(names) == 0 {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusNoData}
	}
	ptr := strings.TrimSuffix(names[0], ".")
	return models.EnrichResult{
		Tool:   e.Name(),
		Status: models.StatusOK,
		Data:   models.ReverseDNSResult{PTR: ptr},
	}
}
