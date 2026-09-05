package catalog

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// RenewalWindow gives a publisher a day to renew the usual seven-day catalog.
// It is a display warning, never an extension of the signed expiry.
const RenewalWindow = 24 * time.Hour

// Publication describes a catalog already accepted by a notary. It does not verify
// signatures or authorize installation; consumers must still call VerifySigners.
type Publication struct {
	Status     string `json:"status"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Action     string `json:"action,omitempty"`
	Actor      string `json:"actor,omitempty"`
	Sequence   int64  `json:"sequence"`
	ValidUntil string `json:"valid_until,omitempty"`
	Expired    bool   `json:"expired,omitempty"`
	Skills     int    `json:"skills"`
	Revoked    int    `json:"revoked"`
	Signatures int    `json:"signatures"`
}

// DescribePublication is the common display rule for the CLI, MCP and console.
// Incomplete or malformed dates are unknown, never healthy by default.
func DescribePublication(body []byte, now time.Time) Publication {
	out := Publication{Status: "unknown", Title: "Needs attention",
		Detail: "The stored catalog could not be summarised. The publisher needs to check it and publish a valid catalog.",
		Action: "inspect_catalog", Actor: "publisher"}
	var envelope struct {
		Payload    string            `json:"payload"`
		Signatures []json.RawMessage `json:"signatures"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return out
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return out
	}
	var snapshot struct {
		Sequence   int64             `json:"sequence"`
		ValidUntil string            `json:"valid_until"`
		Skills     []json.RawMessage `json:"skills"`
		Revoked    []json.RawMessage `json:"revoked"`
	}
	if json.Unmarshal(payload, &snapshot) != nil {
		return out
	}
	until, err := time.Parse(time.RFC3339, snapshot.ValidUntil)
	if err != nil || until.IsZero() || snapshot.Sequence < 1 {
		return out
	}
	out.Sequence, out.ValidUntil = snapshot.Sequence, snapshot.ValidUntil
	out.Skills, out.Revoked, out.Signatures = len(snapshot.Skills), len(snapshot.Revoked), len(envelope.Signatures)
	out.Expired = !now.Before(until)
	out.Action, out.Actor = "publish_catalog", "publisher"
	switch {
	case out.Skills == 0 && out.Revoked == 0:
		out.Status, out.Title = "empty_catalog_only", "Waiting for publication"
		out.Detail = "Only a placeholder is published here. We are still waiting for the first catalog with skills."
	case out.Skills == 0:
		out.Status, out.Title = "revocations_only", "Waiting for publication"
		out.Detail = "Only removals are published here. We are still waiting for the first catalog with skills."
	case out.Expired:
		out.Status, out.Title, out.Action = "stale", "Needs renewal", "renew_catalog"
		out.Detail = "This catalog has expired. Its publisher needs to renew it with the existing signing key and publish the renewal."
	case !until.After(now.Add(RenewalWindow)):
		out.Status, out.Title, out.Action = "expiring", "Renew soon", "renew_catalog"
		out.Detail = "This catalog expires within 24 hours. Its publisher can renew it now with the existing signing key."
	default:
		out.Status, out.Title = "published", "Published"
		out.Detail, out.Action, out.Actor = "A catalog with skills is live here.", "", ""
	}
	return out
}

// WithSource adds the hosted publication's repository evidence. An absent source
// must not hide an expired catalog or a warning that it will expire soon.
func (p Publication) WithSource(repository, commit string) Publication {
	if p.Status == "published" && (repository == "" || commit == "") {
		p.Status, p.Title = "needs_provenance_republish", "Publish once from this repository"
		p.Detail = "A catalog with skills is live here, but its source was not recorded. Publish it once from the registered repository to confirm the source."
		p.Action, p.Actor = "publish_catalog", "publisher"
	}
	return p
}
