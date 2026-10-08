package server

import (
	"context"
	"time"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/threatlocker"
)

const threatLockerInventoryTTL = 60 * time.Second

func cloneTLApplications(apps []model.TLApplication) []model.TLApplication {
	return append([]model.TLApplication(nil), apps...)
}

func (s *Server) cachedTLApplicationInventory(now time.Time) ([]model.TLApplication, bool) {
	s.tlAppsMu.Lock()
	defer s.tlAppsMu.Unlock()
	if s.tlApps == nil || !now.Before(s.tlAppsExpiresAt) {
		return nil, false
	}
	return cloneTLApplications(s.tlApps), true
}

func (s *Server) tlApplicationInventory(
	ctx context.Context,
	force bool,
) ([]model.TLApplication, error) {
	if force {
		s.tlAppsMu.Lock()
		s.tlApps = nil
		s.tlAppsExpiresAt = time.Time{}
		s.tlAppsGeneration++
		s.tlAppsMu.Unlock()
		s.tlAppsFlight.Forget("inventory")
	} else if apps, ok := s.cachedTLApplicationInventory(time.Now()); ok {
		return apps, nil
	}

	value, err, _ := s.tlAppsFlight.Do("inventory", func() (any, error) {
		if apps, ok := s.cachedTLApplicationInventory(time.Now()); ok {
			return apps, nil
		}
		s.tlAppsMu.Lock()
		generation := s.tlAppsGeneration
		s.tlAppsMu.Unlock()
		apps, err := s.tl.Applications(ctx, "", threatlocker.AppSearchRequest{
			SearchText: " ", SearchBy: "app", IncludeChildOrganizations: true, IncludeUnused: true,
		})
		if err != nil {
			return nil, err
		}
		s.tlAppsMu.Lock()
		if generation == s.tlAppsGeneration {
			s.tlApps = cloneTLApplications(apps)
			s.tlAppsExpiresAt = time.Now().Add(threatLockerInventoryTTL)
		}
		s.tlAppsMu.Unlock()
		return cloneTLApplications(apps), nil
	})
	if err != nil {
		return nil, err
	}
	return cloneTLApplications(value.([]model.TLApplication)), nil
}
