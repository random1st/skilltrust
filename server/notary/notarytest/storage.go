// Package notarytest holds the conformance suite for the notary's seams.
//
// A Storage implementation is trusted with the catalogs machines verify against, and the
// interface makes promises a caller relies on without being able to see them: that an
// absent catalog is ErrAbsent and not an empty one, that a redelivered event is stored
// once, that state cannot be lowered. An implementation that gets one of those subtly
// wrong fails in production rather than in a build, so every implementation runs this.
package notarytest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/report"
	"github.com/random1st/skilltrust/server/notary"
)

// Contract runs every promise the Storage interface makes. The argument returns a fresh,
// empty storage for each subtest, so one case's writes cannot decide another's outcome.
func Contract(t *testing.T, fresh func(t *testing.T) notary.Storage) {
	t.Run("an absent catalog is ErrAbsent", func(t *testing.T) {
		storage := fresh(t)

		body, err := storage.GetCatalog("acme", "plugins")
		if !errors.Is(err, notary.ErrAbsent) {
			t.Fatalf("got (%q, %v), want ErrAbsent — a missing catalog must not read as an empty one", body, err)
		}
	})

	t.Run("a stored catalog comes back byte for byte", func(t *testing.T) {
		storage := fresh(t)
		// Bytes a signature covers: whitespace and ordering are part of what was signed,
		// so anything that re-serialises on the way through breaks verification.
		original := []byte("{\n  \"payloadType\": \"x\",\n  \"payload\": \"eyJ9\"\n}\n")

		if err := storage.PutCatalog("acme", "plugins", original); err != nil {
			t.Fatal(err)
		}
		stored, err := storage.GetCatalog("acme", "plugins")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(stored, original) {
			t.Fatalf("storage changed the bytes:\n stored %q\n   want %q", stored, original)
		}
	})

	t.Run("publishing again replaces what was there", func(t *testing.T) {
		storage := fresh(t)

		if err := storage.PutCatalog("acme", "plugins", []byte("first")); err != nil {
			t.Fatal(err)
		}
		if err := storage.PutCatalog("acme", "plugins", []byte("second")); err != nil {
			t.Fatal(err)
		}
		stored, err := storage.GetCatalog("acme", "plugins")
		if err != nil {
			t.Fatal(err)
		}
		if string(stored) != "second" {
			t.Fatalf("got %q, want the newer catalog", stored)
		}
	})

	t.Run("organisations cannot see each other", func(t *testing.T) {
		storage := fresh(t)

		if err := storage.PutCatalog("acme", "plugins", []byte("acme's")); err != nil {
			t.Fatal(err)
		}
		if _, err := storage.GetCatalog("other", "plugins"); !errors.Is(err, notary.ErrAbsent) {
			t.Fatalf("another organisation's catalog answered %v", err)
		}
		if names := storage.Marketplaces("other"); len(names) != 0 {
			t.Fatalf("another organisation lists %v", names)
		}
	})

	t.Run("marketplaces lists what has a catalog", func(t *testing.T) {
		storage := fresh(t)

		if names := storage.Marketplaces("acme"); len(names) != 0 {
			t.Fatalf("an organisation with nothing published lists %v", names)
		}
		for _, name := range []string{"plugins", "runbooks"} {
			if err := storage.PutCatalog("acme", name, []byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		// Events live beside the marketplaces and are not one of them; a console that
		// listed "events" as a marketplace would render a row for something unsigned.
		if err := storage.PutEvent("acme", "aaaaaaaa.json", []byte(`{"payloadType":"e"}`)); err != nil {
			t.Fatal(err)
		}

		names := storage.Marketplaces("acme")
		found := map[string]bool{}
		for _, name := range names {
			found[name] = true
		}
		if !found["plugins"] || !found["runbooks"] || found["events"] || len(names) != 2 {
			t.Fatalf("listed %v, want exactly plugins and runbooks", names)
		}
	})

	t.Run("state starts at zero and round trips", func(t *testing.T) {
		storage := fresh(t)
		now := time.Now().UTC()

		state, err := storage.LoadState("acme", "plugins")
		if err != nil {
			t.Fatalf("unrecorded state must not be an error: %v", err)
		}
		if state.Sequence != 0 {
			t.Fatalf("unrecorded state is sequence %d, want 0 — nothing seen cannot have gone backwards", state.Sequence)
		}

		if err := storage.SaveState("acme", "plugins", state, 7, now); err != nil {
			t.Fatal(err)
		}
		reloaded, err := storage.LoadState("acme", "plugins")
		if err != nil {
			t.Fatal(err)
		}
		if reloaded.Sequence != 7 {
			t.Fatalf("reloaded sequence %d, want 7", reloaded.Sequence)
		}
	})

	t.Run("state cannot be lowered", func(t *testing.T) {
		storage := fresh(t)
		now := time.Now().UTC()

		state, err := storage.LoadState("acme", "plugins")
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.SaveState("acme", "plugins", state, 9, now); err != nil {
			t.Fatal(err)
		}

		current, err := storage.LoadState("acme", "plugins")
		if err != nil {
			t.Fatal(err)
		}
		// This is the rollback guard itself: accepting it would let a replayed older
		// catalog un-revoke something.
		if err := storage.SaveState("acme", "plugins", current, 4, now); !errors.Is(err, catalog.ErrRolledBack) {
			t.Fatalf("lowering the sequence answered %v, want ErrRolledBack", err)
		}
		after, err := storage.LoadState("acme", "plugins")
		if err != nil {
			t.Fatal(err)
		}
		if after.Sequence != 9 {
			t.Fatalf("a refused save still moved the sequence to %d", after.Sequence)
		}
	})

	t.Run("republishing the same sequence is allowed", func(t *testing.T) {
		storage := fresh(t)
		now := time.Now().UTC()

		state, err := storage.LoadState("acme", "plugins")
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.SaveState("acme", "plugins", state, 3, now); err != nil {
			t.Fatal(err)
		}
		current, err := storage.LoadState("acme", "plugins")
		if err != nil {
			t.Fatal(err)
		}
		// A re-run of the same CI job submits the same catalog. That is idempotent, not
		// an attack, and must not fail the pipeline.
		if err := storage.SaveState("acme", "plugins", current, 3, now); err != nil {
			t.Fatalf("re-recording the same sequence failed: %v", err)
		}
	})

	t.Run("no events is not an error", func(t *testing.T) {
		storage := fresh(t)

		events, err := storage.ListEvents("acme")
		if err != nil {
			t.Fatalf("an organisation that filed nothing answered %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("got %d events from an empty mailbox", len(events))
		}
	})

	t.Run("events are stored once and listed in order", func(t *testing.T) {
		storage := fresh(t)

		// Names are content-derived, so a redelivered event arrives under the name it
		// already has. Storing it twice must leave one, or every retry inflates the
		// incident count an operator reads.
		for range 2 {
			if err := storage.PutEvent("acme", "bbbbbbbb.json", []byte(`{"payloadType":"e","n":2}`)); err != nil {
				t.Fatal(err)
			}
		}
		if err := storage.PutEvent("acme", "aaaaaaaa.json", []byte(`{"payloadType":"e","n":1}`)); err != nil {
			t.Fatal(err)
		}

		events, err := storage.ListEvents("acme")
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 2 {
			t.Fatalf("got %d events, want 2 — a redelivery must not duplicate", len(events))
		}
		if !bytes.Contains(events[0], []byte(`"n":1`)) {
			t.Fatalf("events are not ordered by name: first is %q", events[0])
		}
	})

	t.Run("no checks is not an error", func(t *testing.T) {
		storage := fresh(t)

		checks, err := storage.ListChecks("acme")
		if err != nil {
			t.Fatalf("an organisation with no current checks answered %v", err)
		}
		if len(checks) != 0 {
			t.Fatalf("got %d checks from an empty state store", len(checks))
		}
	})

	t.Run("checks stay bounded to the latest signer and scope", func(t *testing.T) {
		storage := fresh(t)
		now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

		for _, record := range []notary.CheckRecord{
			{
				Result: report.CheckResult{
					Machine: "laptop-1", Scope: "managed", Sequence: 3,
					CheckedAt: now.Add(-2 * time.Minute), FreshUntil: now.Add(time.Hour),
					Complete: true, Checked: 2,
				},
				Receipt: notary.Receipt{Signer: "sha256:machine-1", AcceptedAt: now.Add(-2 * time.Minute), Digest: "a"},
			},
			{
				Result: report.CheckResult{
					Machine: "laptop-1", Scope: "managed", Sequence: 3,
					CheckedAt: now.Add(-time.Minute), FreshUntil: now.Add(time.Hour),
					Complete: true, Checked: 4,
				},
				Receipt: notary.Receipt{Signer: "sha256:machine-1", AcceptedAt: now.Add(-time.Minute), Digest: "b"},
			},
			{
				Result: report.CheckResult{
					Machine: "laptop-1", Scope: "managed", Sequence: 2,
					CheckedAt: now, FreshUntil: now.Add(time.Hour), Complete: true, Checked: 1,
				},
				Receipt: notary.Receipt{Signer: "sha256:machine-1", AcceptedAt: now, Digest: "c"},
			},
			{
				Result: report.CheckResult{
					Machine: "laptop-1", Scope: report.CheckScopeApprovedSkills, Sequence: 1,
					CheckedAt: now, Complete: false, Checked: 0, Errors: 1,
				},
				Receipt: notary.Receipt{Signer: "sha256:machine-1", AcceptedAt: now, Digest: "d"},
			},
		} {
			receipt, err := storage.SaveCheck("acme", record)
			if record.Receipt.Digest == "b" || record.Receipt.Digest == "c" {
				if !errors.Is(err, notary.ErrRefused) {
					t.Fatalf("save %q = %v, want ErrRefused", record.Receipt.Digest, err)
				}
				if !receipt.AcceptedAt.IsZero() || receipt.Digest != "" {
					t.Fatalf("refused save returned receipt %+v", receipt)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if receipt != record.Receipt {
				t.Fatalf("receipt = %+v, want %+v", receipt, record.Receipt)
			}
		}

		checks, err := storage.ListChecks("acme")
		if err != nil {
			t.Fatal(err)
		}
		if len(checks) != 2 {
			t.Fatalf("got %d current checks, want 2 scopes", len(checks))
		}

		found := map[string]notary.CheckRecord{}
		for _, one := range checks {
			found[one.Result.Scope] = one
		}
		if found["managed"].Result.Checked != 2 || found["managed"].Result.Sequence != 3 {
			t.Fatalf("managed = %+v, want the first accepted sequence and not a same-sequence overwrite or rollback", found["managed"])
		}
		if found[report.CheckScopeApprovedSkills].Receipt.Digest != "d" {
			t.Fatalf("second scope lost its own latest check: %+v", found[report.CheckScopeApprovedSkills])
		}
	})

	t.Run("check envelopes round trip byte for byte with their receipt digest", func(t *testing.T) {
		storage := fresh(t)
		envelope := []byte("{\n  \"payloadType\": \"application/vnd.skilltrust.check.v1+json\",\n  \"payload\": \"eyJzY29wZSI6Im1hbmFnZWQifQ==\"\n}\n")
		digest := sha256.Sum256(envelope)
		record := notary.CheckRecord{
			Result: report.CheckResult{
				Machine: "laptop-1", Scope: "managed", Sequence: 1,
				CheckedAt:  time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
				FreshUntil: time.Date(2026, 9, 4, 13, 0, 0, 0, time.UTC),
				Complete:   true, Checked: 1,
			},
			Receipt: notary.Receipt{
				Signer: "sha256:machine-1", AcceptedAt: time.Date(2026, 9, 4, 12, 0, 30, 0, time.UTC),
				Digest: hex.EncodeToString(digest[:]),
			},
			Envelope: envelope,
		}
		if _, err := storage.SaveCheck("acme", record); err != nil {
			t.Fatal(err)
		}
		checks, err := storage.ListChecks("acme")
		if err != nil {
			t.Fatal(err)
		}
		if len(checks) != 1 {
			t.Fatalf("got %d checks, want 1", len(checks))
		}
		if !bytes.Equal(checks[0].Envelope, envelope) {
			t.Fatalf("storage changed the signed check bytes:\n stored %q\n   want %q", checks[0].Envelope, envelope)
		}
		reloaded := sha256.Sum256(checks[0].Envelope)
		if checks[0].Receipt.Digest != hex.EncodeToString(reloaded[:]) {
			t.Fatalf("receipt digest %q no longer matches reloaded envelope %q", checks[0].Receipt.Digest, hex.EncodeToString(reloaded[:]))
		}
	})
}
