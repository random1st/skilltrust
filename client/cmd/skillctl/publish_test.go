package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/enrollment"
	"github.com/random1st/skilltrust/internal/marketplace"
)

type publishFixture struct {
	repository string
	key        ed25519.PrivateKey
	notary     ed25519.PrivateKey
	server     *httptest.Server
	ready      bool
	hosted     *attest.Envelope
}

func newPublishFixture(t *testing.T, root bool) *publishFixture {
	t.Helper()
	repository, key := signedMarketplace(t)
	if root {
		if err := os.WriteFile(filepath.Join(repository, marketplace.ManifestPath), []byte(`{"name":"acme","plugins":[{"name":"runbook","source":"./","version":"1.0.0"}]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := testMarketplaceGit(repository, "add", marketplace.ManifestPath); err != nil {
			t.Fatal(err)
		}
		if err := testMarketplaceGit(repository, "commit", "-m", "root plugin"); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"remote", "add", "origin", "https://github.com/acme/skills.git"}, {"config", "user.name", "Test Publisher"}, {"config", "user.email", "publisher@example.invalid"}, {"config", "commit.gpgsign", "false"}} {
		if err := testMarketplaceGit(repository, args...); err != nil {
			t.Fatal(err)
		}
	}
	pub, notary, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := attest.EncodePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	f := &publishFixture{repository: repository, key: key, notary: notary, ready: true}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/publishing/status":
			var proof attest.Envelope
			if json.NewDecoder(r.Body).Decode(&proof) != nil {
				http.Error(w, "proof", 400)
				return
			}
			request, _, err := enrollment.VerifyPublishing(&proof, f.server.URL, time.Now())
			if err != nil || request.Repository != "acme/skills@refs/heads/main" {
				http.Error(w, "proof", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(enrollment.PublishingSetup{Ready: f.ready, NotaryKeys: []string{string(pem)}})
		case "/v1/catalogs/acme/acme":
			if f.hosted == nil {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(f.hosted)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *publishFixture) options() publishOptions {
	return publishOptions{Directory: f.repository, Organisation: "acme", ServiceURL: f.server.URL, NoBrowser: true}
}

func (f *publishFixture) prepare(t *testing.T) publishingResult {
	t.Helper()
	out, err := publish(f.options())
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "prepared" || out.ReviewID == "" {
		t.Fatalf("not prepared: %+v", out)
	}
	return out
}

func TestPublishBrowserSetupResumesWithoutExposingCredentials(t *testing.T) {
	f := newPublishFixture(t, false)
	f.ready = false
	out, err := publish(f.options())
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "approval_pending" || !strings.Contains(out.ApprovalURL, "/publish?request=") || out.NextAction.Actor != "owner" {
		t.Fatalf("%+v", out)
	}
	body, _ := json.Marshal(out)
	for _, secret := range []string{"PRIVATE KEY", "key_path", defaultSigningKey(), "reporting.token"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("public result contains %s", secret)
		}
	}
	f.ready = true
	f.prepare(t)
}

func TestPublishPreparationIsIdempotentAndIncludesRootWorkflow(t *testing.T) {
	f := newPublishFixture(t, true)
	before, err := publishingGit(f.repository, nil, "ls-files", "--stage")
	if err != nil {
		t.Fatal(err)
	}
	first := f.prepare(t)
	second := f.prepare(t)
	if first.ReviewID != second.ReviewID || first.Sequence != second.Sequence {
		t.Fatalf("retry changed approval: %+v / %+v", first, second)
	}
	after, err := publishingGit(f.repository, nil, "ls-files", "--stage")
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("preparation changed the user's index")
	}
	if err := testMarketplaceGit(f.repository, "add", CatalogFileName, publishWorkflow); err != nil {
		t.Fatal(err)
	}
	if err := testMarketplaceGit(f.repository, "commit", "-m", "reviewed"); err != nil {
		t.Fatal(err)
	}
	manifest, err := marketplace.Load(f.repository)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := marketplace.Plan(f.repository, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Skills, coverage.Signed) {
		t.Fatalf("committed root differs from signature: %v / %v", first.Skills, coverage.Signed)
	}
}

func TestPublishSubmitRequiresExactReviewAndPreservesUnrelatedStaging(t *testing.T) {
	f := newPublishFixture(t, false)
	first := f.prepare(t)
	pushes := 0
	old := publishingPush
	publishingPush = func(record *publishingRecord) error { pushes++; return errors.New("unavailable") }
	t.Cleanup(func() { publishingPush = old })
	opts := f.options()
	opts.Submit = true
	for _, approval := range []string{"", "someone-elses-review"} {
		opts.Approve = approval
		if _, err := publish(opts); err == nil {
			t.Fatal("submitted without this review's approval")
		}
	}
	opts.Approve = first.ReviewID
	path := filepath.Join(f.repository, publishWorkflow)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte{}, original...), []byte("# changed after review\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publish(opts); err == nil {
		t.Fatal("submitted changed workflow with old approval")
	}
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.repository, "unrelated.txt"), []byte("keep staged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := testMarketplaceGit(f.repository, "add", "unrelated.txt"); err != nil {
		t.Fatal(err)
	}
	result, err := publish(opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "submission_pending" || result.Commit == "" || pushes != 1 {
		t.Fatalf("%+v / pushes %d", result, pushes)
	}
	retry, err := publish(opts)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Commit != result.Commit || pushes != 2 {
		t.Fatalf("retry created another commit: %+v", retry)
	}
	staged, err := publishingGit(f.repository, nil, "diff", "--cached", "--name-only")
	if err != nil {
		t.Fatal(err)
	}
	if staged != "unrelated.txt" {
		t.Fatalf("unrelated staging changed: %q", staged)
	}
	committed, err := publishingGit(f.repository, nil, "show", "--pretty=format:", "--name-only", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(committed, "unrelated.txt") {
		t.Fatal("committed an unrelated staged file")
	}
}

func TestPublishRenewalPreservesRevocationsAndRejectsChangedSkills(t *testing.T) {
	f := newPublishFixture(t, false)
	old := catalog.Snapshot{Name: "acme", Sequence: 9, IssuedAt: time.Now().Add(-8 * 24 * time.Hour), ValidUntil: time.Now().Add(-time.Hour), Revoked: []catalog.Entry{{Digest: strings.Repeat("a", 64), Reason: "withdrawn", RevokedAt: time.Now().UTC().Add(-48 * time.Hour)}}}
	manifest, err := marketplace.Load(f.repository)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := marketplace.Plan(f.repository, manifest)
	if err != nil {
		t.Fatal(err)
	}
	old.Skills = coverage.Signed
	envelope, err := catalog.Sign(old, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.Save(filepath.Join(f.repository, CatalogFileName)); err != nil {
		t.Fatal(err)
	}
	opts := f.options()
	opts.Renew = true
	out, err := publish(opts)
	if err != nil {
		t.Fatal(err)
	}
	if out.Sequence != 10 {
		t.Fatalf("sequence %d", out.Sequence)
	}
	retry, err := publish(opts)
	if err != nil {
		t.Fatal(err)
	}
	if retry.ReviewID != out.ReviewID || retry.Sequence != 10 {
		t.Fatal("renewal retry signed again")
	}
	renewed, err := attest.LoadEnvelope(filepath.Join(f.repository, CatalogFileName))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := catalog.Open(renewed, attest.NewTrustedKeys(f.key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.Revoked, old.Revoked) {
		t.Fatalf("lost revocations: %+v", snapshot.Revoked)
	}
	if err := os.WriteFile(filepath.Join(f.repository, "plugins/runbook/SKILL.md"), []byte("new instructions"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := testMarketplaceGit(f.repository, "add", "plugins"); err != nil {
		t.Fatal(err)
	}
	if err := testMarketplaceGit(f.repository, "commit", "-m", "changed source"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(f.repository, CatalogFileName))
	if _, err := publish(opts); err == nil {
		t.Fatal("renewed changed skill approvals")
	}
	after, _ := os.ReadFile(filepath.Join(f.repository, CatalogFileName))
	if string(before) != string(after) {
		t.Fatal("refused renewal replaced catalog")
	}
}

func TestPublishStatusRequiresExactPayloadAndBothIndependentSigners(t *testing.T) {
	f := newPublishFixture(t, false)
	f.prepare(t)
	expected, err := attest.LoadEnvelope(filepath.Join(f.repository, CatalogFileName))
	if err != nil {
		t.Fatal(err)
	}
	opts := f.options()
	opts.Status = true
	for _, mode := range []string{"missing", "publisher_only", "notary_only", "wrong_revision", "both"} {
		t.Run(mode, func(t *testing.T) {
			clone := *expected
			clone.Signatures = append([]attest.Signature{}, expected.Signatures...)
			f.hosted = &clone
			switch mode {
			case "missing":
				f.hosted = nil
			case "notary_only":
				clone.Signatures = nil
				if err := attest.Countersign(&clone, f.notary); err != nil {
					t.Fatal(err)
				}
			case "wrong_revision":
				snapshot, _, _ := catalog.Open(expected, attest.NewTrustedKeys(f.key.Public().(ed25519.PublicKey)))
				snapshot.Sequence++
				cloneEnv, err := catalog.Sign(*snapshot, f.key)
				if err != nil {
					t.Fatal(err)
				}
				f.hosted = cloneEnv
				if err := attest.Countersign(f.hosted, f.notary); err != nil {
					t.Fatal(err)
				}
			case "both":
				if err := attest.Countersign(&clone, f.notary); err != nil {
					t.Fatal(err)
				}
			}
			out, err := publish(opts)
			if mode == "both" {
				if err != nil || out.Status != "published" {
					t.Fatalf("%+v / %v", out, err)
				}
			} else if err == nil && out.Status == "published" {
				t.Fatalf("accepted %s", mode)
			}
		})
	}
}

func TestPublishRejectsDifferentPublisherAndUnreviewedSource(t *testing.T) {
	f := newPublishFixture(t, false)
	_, stranger, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "stranger.key")
	if err := attest.WritePrivateKey(path, stranger); err != nil {
		t.Fatal(err)
	}
	opts := f.options()
	opts.KeyPath = path
	if _, err := publish(opts); err == nil {
		t.Fatal("accepted a replacement signer")
	}
	if err := os.WriteFile(filepath.Join(f.repository, "plugins/runbook/unreviewed.md"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publish(f.options()); err == nil {
		t.Fatal("ignored an untracked skill source")
	}
}

func TestPublishStatusRejectsALocalCatalogChangedAfterReview(t *testing.T) {
	f := newPublishFixture(t, false)
	f.prepare(t)
	path := filepath.Join(f.repository, CatalogFileName)
	envelope, err := attest.LoadEnvelope(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := catalog.Open(envelope, attest.NewTrustedKeys(f.key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Sequence++
	changed, err := catalog.Sign(*snapshot, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := changed.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := attest.Countersign(changed, f.notary); err != nil {
		t.Fatal(err)
	}
	f.hosted = changed
	opts := f.options()
	opts.Status = true
	if out, err := publish(opts); err == nil || out.Status == "published" {
		t.Fatalf("an unreviewed local revision became publication proof: %+v / %v", out, err)
	}
}

func TestPublishSavedSignerCannotChangeWithoutACatalog(t *testing.T) {
	f := newPublishFixture(t, false)
	if err := os.Remove(filepath.Join(f.repository, CatalogFileName)); err != nil {
		t.Fatal(err)
	}
	_, other, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "other.key")
	if err := attest.WritePrivateKey(path, other); err != nil {
		t.Fatal(err)
	}
	opts := f.options()
	opts.KeyPath = path
	if _, err := publish(opts); err == nil {
		t.Fatal("replaced the configured signer when its catalog was absent")
	}
}
