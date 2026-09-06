package notary

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/subscription"
)

type subscriptionSourceStorage struct {
	Storage
	sources map[string]Provenance
}

func (s *subscriptionSourceStorage) PutCatalogProvenance(org, catalog string, where Provenance, digest string) error {
	where.Organisation, where.Marketplace = org, catalog
	s.sources[digest] = where
	return nil
}

func (s *subscriptionSourceStorage) GetCatalogProvenance(_, _, digest string) (Provenance, error) {
	where, found := s.sources[digest]
	if !found {
		return Provenance{}, ErrAbsent
	}
	return where, nil
}

func publicSubscriptionFixture(t *testing.T) (*fixture, *subscriptionSourceStorage, Provenance) {
	t.Helper()
	f := newFixture(t)
	storage := &subscriptionSourceStorage{Storage: f.service.storage, sources: map[string]Provenance{}}
	f.service.storage = storage
	where := Provenance{Organisation: "acme", Marketplace: "plugins", Repository: "acme/skills", Ref: "refs/heads/main", Commit: strings.Repeat("a", 40), RepositoryVisibility: "public"}
	org := f.orgs["acme"]
	org.GitHubRepositories = []string{"acme/skills@refs/heads/main"}
	f.orgs["acme"] = org
	return f, storage, where
}

func TestSubscriptionDescriptorUsesOnlyActualPublishersAndCurrentNotaries(t *testing.T) {
	f, _, where := publicSubscriptionFixture(t)
	unused, _, _ := attest.GenerateKey()
	org := f.orgs["acme"]
	org.Publishers = attest.NewTrustedKeys(f.publisherPub, unused)
	f.orgs["acme"] = org
	incoming, incomingKey, _ := attest.GenerateKey()
	f.service.keys = append(f.service.keys, incomingKey)
	now := time.Now().UTC()
	envelope, _ := catalog.Sign(catalog.Snapshot{Name: "plugins", Sequence: 1, IssuedAt: now, ValidUntil: now.Add(30 * time.Second)}, f.publisher)
	body, _ := json.Marshal(envelope)
	served, err := f.service.AcceptFrom(context.Background(), org, "plugins", body, where)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, signed, err := f.service.SubscriptionDescriptor("acme", "plugins", now)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(served)
	wantPublisher, _ := attest.EncodePublicKey(f.publisherPub)
	if descriptor.CatalogDigest != hex.EncodeToString(sum[:]) || len(descriptor.PublisherKeys) != 1 || descriptor.PublisherKeys[0] != string(wantPublisher) || descriptor.Commit != where.Commit || descriptor.ExpiresAt.After(now.Add(30*time.Second)) {
		t.Fatalf("incorrect public descriptor: %+v", descriptor)
	}
	for _, keys := range []*attest.TrustedKeys{attest.NewTrustedKeys(f.notaryPub), attest.NewTrustedKeys(incoming)} {
		if _, signers, err := subscription.Verify(signed, keys, "acme", "plugins", now); err != nil || len(signers) != 1 {
			t.Fatalf("rotation descriptor = %v, %v", signers, err)
		}
	}
}

func TestSubscriptionDescriptorRefusesUnprovenPrivateOrDamagedCatalogs(t *testing.T) {
	for _, mode := range []string{"private", "internal", "legacy", "unknown visibility", "wrong source identity", "wrong source catalog", "invalid repository", "invalid ref", "invalid commit", "changed exact bytes", "no publisher", "no current notary", "same party", "expired", "rollback", "other snapshot"} {
		t.Run(mode, func(t *testing.T) {
			f, storage, where := publicSubscriptionFixture(t)
			if mode == "private" || mode == "internal" {
				where.RepositoryVisibility = mode
			}
			if mode == "legacy" {
				where.RepositoryVisibility = ""
			}
			if mode == "unknown visibility" {
				where.RepositoryVisibility = "unknown"
			}
			body, err := f.service.AcceptFrom(context.Background(), f.orgs["acme"], "plugins", f.signedCatalog(t, 1), where)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			sum := sha256.Sum256(body)
			key := hex.EncodeToString(sum[:])
			switch mode {
			case "wrong source identity":
				where.Organisation = "other"
				storage.sources[key] = where
			case "wrong source catalog":
				where.Marketplace = "other"
				storage.sources[key] = where
			case "invalid repository":
				where.Repository = "acme/../secrets"
				storage.sources[key] = where
			case "invalid ref":
				where.Ref = "refs/heads/main@{yesterday}"
				storage.sources[key] = where
			case "invalid commit":
				where.Commit = "HEAD"
				storage.sources[key] = where
			case "changed exact bytes":
				if err := storage.PutCatalog("acme", "plugins", append(body, '\n')); err != nil {
					t.Fatal(err)
				}
			case "no publisher":
				other, _, _ := attest.GenerateKey()
				org := f.orgs["acme"]
				org.Publishers = attest.NewTrustedKeys(other)
				f.orgs["acme"] = org
			case "no current notary":
				_, other, _ := attest.GenerateKey()
				f.service.keys = f.service.keys[:0]
				f.service.keys = append(f.service.keys, other)
			case "same party":
				org := f.orgs["acme"]
				org.Publishers = attest.NewTrustedKeys(f.notaryPub)
				f.orgs["acme"] = org
			case "expired":
				now = now.Add(8 * 24 * time.Hour)
			case "rollback":
				state, _ := storage.LoadState("acme", "plugins")
				if err := storage.SaveState("acme", "plugins", state, 2, now); err != nil {
					t.Fatal(err)
				}
			case "other snapshot":
				envelope, _ := catalog.Sign(catalog.Snapshot{Name: "other", Sequence: 1, IssuedAt: now, ValidUntil: now.Add(time.Hour)}, f.publisher)
				if err := attest.Countersign(envelope, f.service.keys[0]); err != nil {
					t.Fatal(err)
				}
				body, _ := json.Marshal(envelope)
				sum := sha256.Sum256(body)
				storage.sources[hex.EncodeToString(sum[:])] = where
				if err := storage.PutCatalog("acme", "plugins", body); err != nil {
					t.Fatal(err)
				}
			}
			if _, envelope, err := f.service.SubscriptionDescriptor("acme", "plugins", now); !errors.Is(err, ErrAbsent) || envelope != nil {
				t.Fatalf("unsafe public descriptor = %v, %v", envelope, err)
			}
			if mode == "private" || mode == "internal" {
				return // These proven sources are deliberately available to team readers.
			}
			if verified, err := f.service.Subscription("acme", "plugins", now); !errors.Is(err, ErrAbsent) || len(verified.Catalog) != 0 || verified.Descriptor.Catalog != "" {
				t.Fatalf("unsafe verified subscription = %+v, %v", verified, err)
			}
			if _, envelope, err := f.service.TeamSubscriptionDescriptor("acme", "plugins", key, "sha256:"+strings.Repeat("b", 64), now); !errors.Is(err, ErrAbsent) || envelope != nil {
				t.Fatalf("unsafe team descriptor = %v, %v", envelope, err)
			}
		})
	}
}

func TestTeamSubscriptionDescriptorBindsVerifiedSourceAndCatalog(t *testing.T) {
	for _, visibility := range []string{"public", "private", "internal"} {
		t.Run(visibility, func(t *testing.T) {
			f, _, where := publicSubscriptionFixture(t)
			where.RepositoryVisibility = visibility
			incoming, incomingKey, _ := attest.GenerateKey()
			f.service.keys = append(f.service.keys, incomingKey)
			body, err := f.service.AcceptFrom(context.Background(), f.orgs["acme"], "plugins", f.signedCatalog(t, 1), where)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			verified, err := f.service.Subscription("acme", "plugins", now)
			if err != nil || !bytes.Equal(verified.Catalog, body) || verified.Visibility != visibility {
				t.Fatalf("verified current catalog = %+v, %v", verified, err)
			}
			catalogDigest := sha256.Sum256(body)
			if verified.Descriptor.Repository != "https://github.com/acme/skills.git" || verified.Descriptor.Ref != where.Ref || verified.Descriptor.Commit != where.Commit || verified.Descriptor.CatalogDigest != hex.EncodeToString(catalogDigest[:]) {
				t.Fatalf("unbound source identity: %+v", verified.Descriptor)
			}
			sourceDigest := "sha256:" + strings.Repeat("c", 64)
			descriptor, signed, err := f.service.TeamSubscriptionDescriptor("acme", "plugins", verified.Descriptor.CatalogDigest, sourceDigest, now)
			if err != nil {
				t.Fatal(err)
			}
			wantSource := subscription.Origin + "/v1/subscriptions/acme/plugins/source/" + verified.Descriptor.CatalogDigest
			if descriptor.Access != "team" || descriptor.SourceDigest != sourceDigest || descriptor.SourceURL != wantSource || descriptor.CatalogDigest != verified.Descriptor.CatalogDigest {
				t.Fatalf("unbound team archive: %+v", descriptor)
			}
			for _, trusted := range []*attest.TrustedKeys{attest.NewTrustedKeys(f.notaryPub), attest.NewTrustedKeys(incoming)} {
				decoded, signers, err := subscription.Verify(signed, trusted, "acme", "plugins", now)
				if err != nil || len(signers) != 1 || decoded.SourceDigest != sourceDigest || decoded.Access != "team" {
					t.Fatalf("team descriptor not verifiable through notary rotation: %+v, %v, %v", decoded, signers, err)
				}
			}
			if _, _, err := subscription.Verify(signed, attest.NewTrustedKeys(f.publisherPub), "acme", "plugins", now); err == nil {
				t.Fatal("publisher key authenticated the hosted archive descriptor")
			}
			if visibility != "public" {
				if _, envelope, err := f.service.SubscriptionDescriptor("acme", "plugins", now); !errors.Is(err, ErrAbsent) || envelope != nil {
					t.Fatalf("confidential source became public: %v, %v", envelope, err)
				}
			}
		})
	}
}

func TestTeamSubscriptionReverifiesAfterSourceWasBuilt(t *testing.T) {
	for _, change := range []string{"new publication", "publisher revoked", "notary revoked", "source removed", "source ref narrowed"} {
		t.Run(change, func(t *testing.T) {
			f, _, where := publicSubscriptionFixture(t)
			where.RepositoryVisibility = "private"
			if _, err := f.service.AcceptFrom(context.Background(), f.orgs["acme"], "plugins", f.signedCatalog(t, 1), where); err != nil {
				t.Fatal(err)
			}
			verified, err := f.service.Subscription("acme", "plugins", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			org := f.orgs["acme"]
			switch change {
			case "new publication":
				where.Commit = strings.Repeat("d", 40)
				if _, err := f.service.AcceptFrom(context.Background(), org, "plugins", f.signedCatalog(t, 2), where); err != nil {
					t.Fatal(err)
				}
			case "publisher revoked":
				other, _, _ := attest.GenerateKey()
				org.Publishers = attest.NewTrustedKeys(other)
			case "notary revoked":
				_, other, _ := attest.GenerateKey()
				f.service.keys = append(f.service.keys[:0], other)
			case "source removed":
				org.GitHubRepositories = nil
			case "source ref narrowed":
				org.GitHubRepositories = []string{"acme/skills@refs/heads/release"}
			}
			f.orgs["acme"] = org
			if _, envelope, err := f.service.TeamSubscriptionDescriptor("acme", "plugins", verified.Descriptor.CatalogDigest, "sha256:"+strings.Repeat("b", 64), time.Now()); !errors.Is(err, ErrAbsent) || envelope != nil {
				t.Fatalf("source from a stale authorization became available: %v, %v", envelope, err)
			}
		})
	}
}

func TestTeamSubscriptionRefusesUnboundArchiveDigests(t *testing.T) {
	f, _, where := publicSubscriptionFixture(t)
	if _, err := f.service.AcceptFrom(context.Background(), f.orgs["acme"], "plugins", f.signedCatalog(t, 1), where); err != nil {
		t.Fatal(err)
	}
	verified, err := f.service.Subscription("acme", "plugins", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{"", strings.Repeat("b", 64), "sha256:" + strings.Repeat("B", 64), "sha256:" + strings.Repeat("b", 63), "sha512:" + strings.Repeat("b", 64), "sha256:../source"} {
		t.Run(digest, func(t *testing.T) {
			if _, signed, err := f.service.TeamSubscriptionDescriptor("acme", "plugins", verified.Descriptor.CatalogDigest, digest, time.Now()); !errors.Is(err, ErrAbsent) || signed != nil {
				t.Fatalf("unbound archive was signed: %v, %v", signed, err)
			}
		})
	}
	for _, digest := range []string{"", strings.Repeat("e", 64), verified.Descriptor.CatalogDigest + "?other"} {
		t.Run("catalog="+digest, func(t *testing.T) {
			if _, signed, err := f.service.TeamSubscriptionDescriptor("acme", "plugins", digest, "sha256:"+strings.Repeat("b", 64), time.Now()); !errors.Is(err, ErrAbsent) || signed != nil {
				t.Fatalf("archive was bound to another catalog: %v, %v", signed, err)
			}
		})
	}
}

func TestTeamSubscriptionRejectsCatalogDigestMismatchBeforeSigning(t *testing.T) {
	f, _, where := publicSubscriptionFixture(t)
	where.RepositoryVisibility = "private"
	if _, err := f.service.AcceptFrom(context.Background(), f.orgs["acme"], "plugins", f.signedCatalog(t, 1), where); err != nil {
		t.Fatal(err)
	}
	verified, err := f.service.Subscription("acme", "plugins", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrongCatalog := "sha256:" + strings.Repeat("e", 64)
	if wrongCatalog == verified.Descriptor.CatalogDigest {
		t.Fatal("fixture unexpectedly used the test digest")
	}
	if _, envelope, err := f.service.TeamSubscriptionDescriptor("acme", "plugins", wrongCatalog, verified.Descriptor.SourceDigest, time.Now()); !errors.Is(err, ErrAbsent) || envelope != nil {
		t.Fatalf("mismatched catalog digest was signed: %v, %v", envelope, err)
	}
}

func TestSubscriptionDeliveryUsesCurrentSourceRegistration(t *testing.T) {
	for _, visibility := range []string{"public", "private", "internal"} {
		for _, registration := range []string{"acme/skills", "acme/skills@refs/heads/main", "acme/other", "acme/skills@refs/heads/release", ""} {
			t.Run(visibility+"/"+registration, func(t *testing.T) {
				f, _, where := publicSubscriptionFixture(t)
				where.RepositoryVisibility = visibility
				if _, err := f.service.AcceptFrom(context.Background(), f.orgs["acme"], "plugins", f.signedCatalog(t, 1), where); err != nil {
					t.Fatal(err)
				}
				org := f.orgs["acme"]
				org.GitHubRepositories = nil
				if registration != "" {
					org.GitHubRepositories = []string{registration}
				}
				f.orgs["acme"] = org
				registered := registration == "acme/skills" || registration == "acme/skills@refs/heads/main"
				verified, err := f.service.Subscription("acme", "plugins", time.Now())
				if (err == nil) != (visibility == "public" || registered) {
					t.Fatalf("source registration was not respected: %+v, %v", verified, err)
				}
				_, signed, err := f.service.TeamSubscriptionDescriptor("acme", "plugins", verified.Descriptor.CatalogDigest, "sha256:"+strings.Repeat("b", 64), time.Now())
				if (err == nil) != registered || (signed != nil) != registered {
					t.Fatalf("team delivery ignored registration: %v, %v", signed, err)
				}
				if visibility == "public" {
					if _, signed, err := f.service.SubscriptionDescriptor("acme", "plugins", time.Now()); err != nil || signed == nil {
						t.Fatalf("publishing policy changed existing public metadata semantics: %v, %v", signed, err)
					}
				}
			})
		}
	}
}

type subscriptionCurrentDirectory struct {
	StaticDirectory
	current StaticDirectory
}

func (d subscriptionCurrentDirectory) LookupOrgStrong(name string) (Org, bool) {
	return d.current.LookupOrg(name)
}

func TestSubscriptionRefusesCachedDirectoryAfterCurrentRevocation(t *testing.T) {
	for _, change := range []string{"org removed", "wrong org identity", "publishers unavailable", "publisher revoked", "source removed"} {
		t.Run(change, func(t *testing.T) {
			f, _, where := publicSubscriptionFixture(t)
			where.RepositoryVisibility = "private"
			if _, err := f.service.AcceptFrom(context.Background(), f.orgs["acme"], "plugins", f.signedCatalog(t, 1), where); err != nil {
				t.Fatal(err)
			}
			current := StaticDirectory{"acme": f.orgs["acme"]}
			f.service.directory = subscriptionCurrentDirectory{StaticDirectory: f.orgs, current: current}
			verified, err := f.service.Subscription("acme", "plugins", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			org := current["acme"]
			switch change {
			case "wrong org identity":
				org.Name = "other"
			case "publishers unavailable":
				org.Publishers = nil
			case "publisher revoked":
				other, _, _ := attest.GenerateKey()
				org.Publishers = attest.NewTrustedKeys(other)
			case "source removed":
				org.GitHubRepositories = nil
			}
			current["acme"] = org
			if change == "org removed" {
				delete(current, "acme")
			}
			if result, err := f.service.Subscription("acme", "plugins", time.Now()); !errors.Is(err, ErrAbsent) || len(result.Catalog) != 0 {
				t.Fatalf("cached directory authorized a revoked source: %+v, %v", result, err)
			}
			if _, envelope, err := f.service.TeamSubscriptionDescriptor("acme", "plugins", verified.Descriptor.CatalogDigest, "sha256:"+strings.Repeat("b", 64), time.Now()); !errors.Is(err, ErrAbsent) || envelope != nil {
				t.Fatalf("cached directory signed a revoked source: %v, %v", envelope, err)
			}
		})
	}
}
