// Package notary countersigns and serves the catalogs organisations publish.
//
// The notary is deliberately not a trust root on its own. It verifies that a catalog
// carries a registered publisher's signature, adds one more signature over the exact same
// payload bytes, and serves the result. A machine that pins both keys and sets a threshold
// of two gets the property this service exists for: neither a stolen publisher key nor a
// compromised notary can publish alone. A machine that pins only the publisher loses
// nothing it had before the notary existed.
package notary

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
)

var (
	// ErrUnknownOrg covers both a name nobody registered and a bad token, on purpose:
	// distinguishing them would confirm to a guesser which organisation names exist.
	ErrUnknownOrg = errors.New("no such organisation, or the token does not match")
	// ErrRefused is a catalog that failed verification — wrong signer, expired, malformed.
	ErrRefused = errors.New("the catalog was refused")
	// ErrRollback is a catalog older than one already accepted.
	ErrRollback = errors.New("an older catalog cannot replace a newer one")
	// ErrAbsent is a marketplace nothing has been published for.
	ErrAbsent = errors.New("nothing has been published under that name")
)

// Org is one organisation the notary countersigns for.
//
// The three tokens are three roles, deliberately not one credential: CI holds Token and
// can publish catalogs but not read the fleet; machines hold IngestToken and can file
// events but not publish; an administrator holds AdminToken and can read what machines
// filed. A leak of any one of them stays the size of its role.
type Org struct {
	Name string
	// The three tokens are held as digests, not plaintext: see Secret. A disabled
	// (zero) Secret closes its endpoint rather than opening it.
	Token Secret
	// IngestToken lets machines file events. Disabled closes the endpoint.
	IngestToken Secret
	// AdminToken lets an administrator read filed events. Disabled closes the endpoint.
	AdminToken Secret
	// GitHubRepositories are the repositories whose Actions jobs may publish with their
	// OIDC token instead of the static token — no long-lived secret in CI. The token
	// replaces only the credential: the catalog must still carry a pinned publisher's
	// signature, so Actions of the right repository with the wrong key still publish
	// nothing.
	//
	// It is a list because an organisation publishes more than one catalog, and those
	// catalogs live in different repositories — its own skills in one, a curated
	// marketplace in another. A single registration made the second one unpublishable
	// except by handing a static token to CI, which is the secret this path exists to
	// avoid. Each entry is "owner/repo", optionally "owner/repo@refs/heads/main" to bind
	// the branch as well.
	GitHubRepositories []string
	// Publishers are the keys allowed to sign this organisation's catalogs. The notary
	// pins them from its own configuration, never from an uploaded catalog — the same
	// rule the client applies, for the same reason: a catalog that could introduce its
	// own signing key could replace itself.
	Publishers *attest.TrustedKeys
	// Machines are the keys whose events the console shows as verified. Nil means every
	// stored event renders as an unverified count — the mailbox still accepts them, but
	// nothing vouches for who filed them.
	Machines *attest.TrustedKeys
}

// Service accepts, countersigns, stores and serves catalogs.
type Service struct {
	storage   Storage
	directory Directory
	// keys are the countersigning keys, first one primary. More than one exists only
	// mid-rotation: every catalog is signed by all of them, so a consumer pinning either
	// the outgoing or the incoming key keeps verifying through the overlap window.
	keys  []ed25519.PrivateKey
	oidc  *OIDCVerifier
	brand string
}

// New wires the default deployment: records under a data directory, organisations from
// the configuration. NewFrom is the seam a different storage or directory plugs into.
func New(dataDir string, key ed25519.PrivateKey, orgs []Org) *Service {
	index := make(StaticDirectory, len(orgs))
	for _, org := range orgs {
		index[org.Name] = org
	}
	return NewFrom(NewFileStorage(dataDir), index, key)
}

func NewFrom(storage Storage, directory Directory, keys ...ed25519.PrivateKey) *Service {
	if len(keys) == 0 {
		panic("notary: a service needs at least one countersigning key")
	}
	return &Service{storage: storage, directory: directory, keys: keys, brand: "SkillTrust"}
}

// WithOIDC enables OIDC publishing for organisations that registered a repository.
func (s *Service) WithOIDC(verifier *OIDCVerifier) *Service {
	s.oidc = verifier
	return s
}

// WithBrand names the deployment on its web pages. The default is the project name;
// a hosted service sets its own. Nothing but presentation hangs on it.
func (s *Service) WithBrand(brand string) *Service {
	if brand != "" {
		s.brand = brand
	}
	return s
}

// AuthorizeOIDC accepts a publish when a GitHub Actions token proves the caller is a
// workflow of the repository this organisation registered.
//
// A registration of "owner/repo@refs/heads/main" binds the branch too: without it, a
// workflow on any branch of the repository can submit. The pinned signature and the
// monotonic sequence still stand behind this check either way — binding the ref narrows
// who can knock, it is not what keeps the door shut.
func (s *Service) AuthorizeOIDC(orgName, token string, now time.Time) (Org, error) {
	org, known := s.directory.LookupOrg(orgName)
	if !known || s.oidc == nil || len(org.GitHubRepositories) == 0 || org.Publishers == nil {
		return Org{}, ErrUnknownOrg
	}
	repository, ref, err := s.oidc.Verify(token, now)
	if err != nil {
		return Org{}, err
	}
	// A repository that matched by name but not by ref is reported as a ref failure, not
	// as "unregistered": the caller is who they claim to be and got the branch wrong, and
	// telling them their repository is unknown would send them to fix the wrong thing.
	var refMismatch error
	for _, registration := range org.GitHubRepositories {
		registered, requiredRef, _ := strings.Cut(registration, "@")
		if repository != registered {
			continue
		}
		if requiredRef == "" || ref == requiredRef {
			return org, nil
		}
		refMismatch = fmt.Errorf("%w: the token was minted on %s, and %s publishes %s only from %s",
			ErrOIDC, ref, orgName, registered, requiredRef)
	}
	if refMismatch != nil {
		return Org{}, refMismatch
	}
	return Org{}, fmt.Errorf("%w: the token belongs to %s, which is not among %s's registered repositories (%s)",
		ErrOIDC, repository, orgName, strings.Join(org.GitHubRepositories, ", "))
}

// KeyID identifies the notary's primary countersigning key, which consumers pin.
func (s *Service) KeyID() string {
	return attest.KeyID(s.keys[0].Public().(ed25519.PublicKey))
}

// keyIDSet indexes every countersigning key id this service currently holds.
func (s *Service) keyIDSet() map[string]struct{} {
	ids := make(map[string]struct{}, len(s.keys))
	for _, key := range s.keys {
		ids[attest.KeyID(key.Public().(ed25519.PublicKey))] = struct{}{}
	}
	return ids
}

// KeySet returns the signed announcement of this notary's current keys. During rotation
// it lists the outgoing and the incoming key and is signed by both, so a consumer pinning
// either can verify it and learn the other; a stranger pinning neither learns nothing
// they can trust, which is the point.
func (s *Service) KeySet(now time.Time) (*attest.Envelope, error) {
	return attest.SignKeySet(s.keys, now)
}

// name constrains org and marketplace path elements. They become directory names, so
// this is the traversal guard, and it is an allowlist rather than a ".." check because
// the set of strings that are safe as a path element is smaller than the set that merely
// lacks dots.
var name = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// ValidName reports whether a string is usable as an organisation or marketplace name.
// A deployment that registers organisations should check before it stores one, so the
// refusal reads as "pick another name" at the point of choosing rather than as a 404
// from every request afterwards.
func ValidName(candidate string) bool { return name.MatchString(candidate) }

// Authorize checks an organisation's publish token in constant time.
func (s *Service) Authorize(orgName, token string) (Org, error) {
	return s.authorize(orgName, token, func(org Org) Secret { return org.Token })
}

// AuthorizeIngest checks the token machines file events with.
func (s *Service) AuthorizeIngest(orgName, token string) (Org, error) {
	return s.authorize(orgName, token, func(org Org) Secret { return org.IngestToken })
}

// AuthorizeAdmin checks the token an administrator reads events with.
func (s *Service) AuthorizeAdmin(orgName, token string) (Org, error) {
	return s.authorize(orgName, token, func(org Org) Secret { return org.AdminToken })
}

func (s *Service) authorize(orgName, token string, expected func(Org) Secret) (Org, error) {
	org, known := s.directory.LookupOrg(orgName)
	// The comparison runs even for an unknown organisation so that the response time
	// does not say which half of the check failed. A disabled secret closes the role
	// rather than matching an absent header.
	match := expected(org).Matches(token)
	if !known || !match || org.Publishers == nil {
		return Org{}, ErrUnknownOrg
	}
	return org, nil
}

// Accept verifies a publisher's catalog, countersigns it, stores it, and returns the
// countersigned envelope — so the pipeline that published it can also commit it back to
// the repository, keeping the git path and the notary path carrying the same bytes.
func (s *Service) Accept(org Org, marketplace string, body []byte) ([]byte, error) {
	if !name.MatchString(marketplace) {
		return nil, fmt.Errorf("%w: %q is not usable as a marketplace name", ErrRefused, marketplace)
	}

	var envelope attest.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%w: not a DSSE envelope: %v", ErrRefused, err)
	}

	// The same verification a consumer runs, including freshness: countersigning an
	// expired catalog would put this service's name on something every client refuses,
	// and rollback protection here stops a compromised pipeline replaying an old catalog
	// to un-revoke something.
	state, err := s.storage.LoadState(org.Name, marketplace)
	if err != nil {
		return nil, err
	}
	snapshot, _, err := catalog.VerifySigners(&envelope, org.Publishers, state, time.Now().UTC())
	if err != nil {
		if errors.Is(err, catalog.ErrRolledBack) {
			return nil, fmt.Errorf("%w: %v", ErrRollback, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	}

	// The signed name must be the marketplace it is being published as. Without this the
	// URL decides where a catalog lands while the signature says nothing about it, so an
	// organisation's own valid catalog for one marketplace can be served as another — a
	// substitution its publisher never approved, carried out with signatures that all
	// verify. The publisher signs which marketplace it is talking about; this is where
	// that claim gets checked.
	if snapshot.Name != marketplace {
		return nil, fmt.Errorf("%w: the catalog is signed for %q and was published as %q",
			ErrRefused, snapshot.Name, marketplace)
	}

	// Drop any signature already claiming this notary's key before signing fresh. Two
	// real cases land here: a CI job re-run submits the countersigned output of its
	// previous run, which should be idempotent rather than a refusal; and an uploader
	// could attach a garbage signature under this notary's key id, which — if kept —
	// would make every threshold-2 machine refuse the whole envelope as a forgery. The
	// payload just verified, so replacing our own entry loses nothing.
	ours := s.keyIDSet()
	kept := envelope.Signatures[:0]
	for _, signature := range envelope.Signatures {
		if _, mine := ours[signature.KeyID]; !mine {
			kept = append(kept, signature)
		}
	}
	envelope.Signatures = kept

	// Every current key signs, not just the primary. Mid-rotation this is what keeps a
	// machine that pinned only the outgoing key — or only the incoming one — verifying.
	for _, key := range s.keys {
		if err := attest.Countersign(&envelope, key); err != nil {
			return nil, err
		}
	}
	countersigned, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := s.storage.PutCatalog(org.Name, marketplace, countersigned); err != nil {
		return nil, err
	}
	if err := s.storage.SaveState(org.Name, marketplace, state, snapshot.Sequence, time.Now().UTC()); err != nil {
		return nil, err
	}
	return countersigned, nil
}

// Serve returns the countersigned catalog as stored. Reading is unauthenticated by
// design: a catalog is a signed public statement, and its integrity comes from the
// signatures inside it, not from who was allowed to download it.
func (s *Service) Serve(orgName, marketplace string) ([]byte, error) {
	if !name.MatchString(orgName) || !name.MatchString(marketplace) {
		return nil, ErrAbsent
	}
	return s.storage.GetCatalog(orgName, marketplace)
}

// writeAtomically stages next to the destination and renames, so a crash mid-write
// cannot leave a truncated catalog where machines fetch from.
func writeAtomically(path string, body []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".catalog-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
