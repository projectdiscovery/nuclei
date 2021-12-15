package scans

import (
	"context"
	"strconv"

	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
)

// CalculateTargetCount calculates target count from Target ID (int) or static targets.
func CalculateTargetCount(targets []string, db *db.Database) int64 {
	var targetCount int64

	for _, target := range targets {
		targetID, err := strconv.ParseInt(target, 10, 64)
		if err != nil {
			targetCount++
		} else {
			resp, _ := db.Queries().GetTarget(context.Background(), targetID)
			targetCount += resp.Total.Int64
		}
	}
	return targetCount
}
