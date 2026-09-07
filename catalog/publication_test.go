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

// A console that shows "11 skills" has to be able to show which eleven, and a single
// malformed member must not take the summary down with it — the counts have always been
// robust to that and the lists have to be too.
func TestDescribePublicationListsTheSkillsItCounts(t *testing.T) {
	payload := `{"version":1,"sequence":7,"valid_until":"` + time.Now().Add(24*time.Hour).Format(time.RFC3339) + `",` +
		`"skills":[{"name":"deploy-runbook","digest":"sha256:aaa","version":"1.2.0"},` +
		`{"name":"review-checklist","digest":"sha256:bbb"},` +
		`"this member is not an object"],` +
		`"revoked":[{"digest":"sha256:ccc","reason":"leaked","revoked_at":"2026-09-01T00:00:00Z"}]}`
	body := []byte(`{"payload":"` + base64.StdEncoding.EncodeToString([]byte(payload)) + `","signatures":[{},{}]}`)

	out := DescribePublication(body, time.Now())
	if out.Skills != 3 || len(out.Published) != 2 {
		t.Fatalf("skills counted %d, listed %d; the unreadable member must be counted and left out", out.Skills, len(out.Published))
	}
	if out.Published[0].Name != "deploy-runbook" || out.Published[0].Version != "1.2.0" || out.Published[0].Digest != "sha256:aaa" {
		t.Fatalf("first skill = %+v", out.Published[0])
	}
	if len(out.Withdrawn) != 1 || out.Withdrawn[0].Digest != "sha256:ccc" || out.Withdrawn[0].Reason != "leaked" {
		t.Fatalf("withdrawn = %+v", out.Withdrawn)
	}
	if out.Expired {
		t.Fatal("a catalog valid until tomorrow is not expired")
	}
}
