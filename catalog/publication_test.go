package catalog

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestPublicationFreshnessAndSourcePriority(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ name, expiry, want string }{
		{"healthy", now.Add(7 * 24 * time.Hour).Format(time.RFC3339), "published"},
		{"warning boundary", now.Add(RenewalWindow).Format(time.RFC3339), "expiring"},
		{"expiry boundary", now.Format(time.RFC3339), "stale"},
		{"expired", now.Add(-time.Hour).Format(time.RFC3339), "stale"},
		{"malformed", "broken", "unknown"},
		{"missing", "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sequence":1,"skills":[{}],"valid_until":%q}`, tc.expiry)))
			p := DescribePublication([]byte(fmt.Sprintf(`{"payload":%q}`, payload)), now)
			if p.Status != tc.want {
				t.Fatalf("status = %s, want %s", p.Status, tc.want)
			}
			if p.Status != "published" && (p.Action == "" || p.Actor != "publisher") {
				t.Fatalf("no accountable recovery: %+v", p)
			}
			if tc.want != "published" && p.WithSource("", "").Status != p.Status {
				t.Fatal("missing source hides the primary problem")
			}
		})
	}
}
