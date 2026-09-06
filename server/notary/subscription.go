package notary

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/source"
	"github.com/random1st/skilltrust/subscription"
)

// VerifiedSubscription is the exact current catalog and the source identity the
// notary recorded when it accepted those bytes. Visibility is proven publication
// provenance, never a caller's guess about a repository URL. Hosted callers must
// separately authorize the reader before returning any of this information.
type VerifiedSubscription struct {
	Descriptor subscription.Descriptor
	Catalog    []byte
	Visibility string
}

// Subscription verifies the current catalog for hosted delivery. Private and
// internal sources must still be registered for this organisation and ref; a
// removed source must not remain available through its old publication record.
// Unknown legacy visibility cannot establish a confidential delivery policy.
func (s *Service) Subscription(orgName, marketplace string, now time.Time) (VerifiedSubscription, error) {
	return s.readSubscription(orgName, marketplace, now, false)
}

// SubscriptionDescriptor signs configuration for exactly one current catalog.
// The hosted caller must additionally enforce the owner's explicit public consent.
// No caller-supplied source or publisher key can enter the signed descriptor.
func (s *Service) SubscriptionDescriptor(orgName, marketplace string, now time.Time) (subscription.Descriptor, *attest.Envelope, error) {
	verified, err := s.Subscription(orgName, marketplace, now)
	if err != nil || verified.Visibility != "public" {
		return subscription.Descriptor{}, nil, ErrAbsent
	}
	signed, err := subscription.Sign(verified.Descriptor, s.keys...)
	if err != nil {
		return subscription.Descriptor{}, nil, ErrAbsent
	}
	return verified.Descriptor, signed, nil
}

// TeamSubscriptionDescriptor signs one authenticated source delivery. The caller
// supplies only the digest of the archive it built for a previously verified
// catalog. Reading that catalog again prevents a concurrent publish or revocation
// from attaching those source bytes to a different snapshot or identity.
// Hosted callers must enforce current reader admission on every delivery request.
func (s *Service) TeamSubscriptionDescriptor(orgName, marketplace, catalogDigest, sourceDigest string, now time.Time) (subscription.Descriptor, *attest.Envelope, error) {
	verified, err := s.readSubscription(orgName, marketplace, now, true)
	if err != nil || verified.Descriptor.CatalogDigest != catalogDigest {
		return subscription.Descriptor{}, nil, ErrAbsent
	}
	address, err := subscription.SourceURL(orgName, marketplace, catalogDigest)
	if err != nil {
		return subscription.Descriptor{}, nil, ErrAbsent
	}
	descriptor := verified.Descriptor
	descriptor.Access, descriptor.SourceURL, descriptor.SourceDigest = "team", address, sourceDigest
	signed, err := subscription.Sign(descriptor, s.keys...)
	if err != nil {
		return subscription.Descriptor{}, nil, ErrAbsent
	}
	return descriptor, signed, nil
}

func (s *Service) readSubscription(orgName, marketplace string, now time.Time, team bool) (VerifiedSubscription, error) {
	if !ValidName(orgName) || !ValidName(marketplace) {
		return VerifiedSubscription{}, ErrAbsent
	}
	provenance, ok := s.storage.(CatalogProvenanceStorage)
	if !ok {
		return VerifiedSubscription{}, ErrAbsent
	}
	var org Org
	var known bool
	if strong, ok := s.directory.(interface{ LookupOrgStrong(string) (Org, bool) }); ok {
		org, known = strong.LookupOrgStrong(orgName)
	} else {
		org, known = s.directory.LookupOrg(orgName)
	}
	if !known || org.Name != orgName || org.Publishers == nil {
		return VerifiedSubscription{}, ErrAbsent
	}
	body, err := s.storage.GetCatalog(orgName, marketplace)
	if err != nil || len(body) > source.MaxIndexBytes {
		return VerifiedSubscription{}, ErrAbsent
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	where, err := provenance.GetCatalogProvenance(orgName, marketplace, digest)
	if err != nil || where.Organisation != orgName || where.Marketplace != marketplace {
		return VerifiedSubscription{}, ErrAbsent
	}
	switch where.RepositoryVisibility {
	case "public", "private", "internal":
	default:
		return VerifiedSubscription{}, ErrAbsent
	}
	// A public statement retains its old read semantics when an organisation
	// changes its publishing allowlist. Confidential delivery, including a public
	// repository requested in team mode, follows the current registration.
	if (team || where.RepositoryVisibility != "public") && !subscriptionSourceRegistered(org, where) {
		return VerifiedSubscription{}, ErrAbsent
	}
	var envelope attest.Envelope
	if json.Unmarshal(body, &envelope) != nil {
		return VerifiedSubscription{}, ErrAbsent
	}
	state, err := s.storage.LoadState(orgName, marketplace)
	if err != nil {
		return VerifiedSubscription{}, ErrAbsent
	}
	snapshot, publishers, err := catalog.VerifySigners(&envelope, org.Publishers, state, now)
	if err != nil || snapshot.Name != marketplace {
		return VerifiedSubscription{}, ErrAbsent
	}
	var notaries []ed25519.PublicKey
	for _, key := range s.keys {
		notaries = append(notaries, key.Public().(ed25519.PublicKey))
	}
	if _, _, err := catalog.VerifySigners(&envelope, attest.NewTrustedKeys(notaries...), state, now); err != nil {
		return VerifiedSubscription{}, ErrAbsent
	}
	currentNotaries := s.keyIDSet()
	var publicKeys []string
	sort.Strings(publishers)
	for _, id := range publishers {
		if _, sameParty := currentNotaries[id]; sameParty {
			return VerifiedSubscription{}, ErrAbsent
		}
		key, _ := org.Publishers.Lookup(id)
		pem, err := attest.EncodePublicKey(key)
		if err != nil {
			return VerifiedSubscription{}, ErrAbsent
		}
		publicKeys = append(publicKeys, string(pem))
	}
	now = now.UTC()
	expires := now.Add(subscription.Lifetime)
	if snapshot.ValidUntil.Before(expires) {
		expires = snapshot.ValidUntil
	}
	descriptor := subscription.Descriptor{
		Version: 1, Origin: subscription.Origin, Organisation: orgName, Catalog: marketplace,
		Repository: "https://github.com/" + where.Repository + ".git", Ref: where.Ref, Commit: where.Commit,
		CatalogURL:    subscription.Origin + "/v1/catalogs/" + orgName + "/" + marketplace,
		CatalogDigest: digest, PublisherKeys: publicKeys, IssuedAt: now, ExpiresAt: expires,
	}
	if err := subscription.Validate(descriptor, orgName, marketplace, now); err != nil {
		return VerifiedSubscription{}, ErrAbsent
	}
	return VerifiedSubscription{Descriptor: descriptor, Catalog: body, Visibility: where.RepositoryVisibility}, nil
}

func subscriptionSourceRegistered(org Org, where Provenance) bool {
	for _, registration := range org.GitHubRepositories {
		repository, ref, _ := strings.Cut(registration, "@")
		if where.Repository == repository && (ref == "" || where.Ref == ref) {
			return true
		}
	}
	return false
}
