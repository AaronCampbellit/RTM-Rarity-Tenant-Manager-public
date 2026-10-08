package server

import (
	"context"
	"sync"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/model"
)

const tenantCountConcurrency = 4

func (s *Server) tenantUserCount(ctx context.Context, tenantID string, fallback int) int {
	counter, ok := s.graph.(graph.UserCounter)
	if !ok {
		return fallback
	}
	count, err := counter.UserCount(ctx, tenantID)
	if err != nil {
		s.log.Warn("tenant summary: user count unavailable", "tenant", tenantID, "error", err)
		return fallback
	}
	return count
}

// Tenant summaries are global, so count tenants in parallel with a small
// ceiling. Each request is the lightweight Graph count projection, not a full
// user inventory read.
func (s *Server) enrichTenantUserCounts(ctx context.Context, tenants []model.Tenant) {
	if _, ok := s.graph.(graph.UserCounter); !ok {
		return
	}
	sem := make(chan struct{}, tenantCountConcurrency)
	var wg sync.WaitGroup
	for i := range tenants {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			tenants[i].Users = s.tenantUserCount(ctx, tenants[i].ID, tenants[i].Users)
		}()
	}
	wg.Wait()
}
