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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/random1st/skilltrust/internal/attest"
	"github.com/random1st/skilltrust/internal/catalog"
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
type Org struct {
	Name  string
	Token string
	// Publishers are the keys allowed to sign this organisation's catalogs. The notary
	// pins them from its own configuration, never from an uploaded catalog — the same
	// rule the client applies, for the same reason: a catalog that could introduce its
	// own signing key could replace itself.
	Publishers *attest.TrustedKeys
}

// Service accepts, countersigns, stores and serves catalogs.
type Service struct {
	dataDir string
	key     ed25519.PrivateKey
	orgs    map[string]Org
}

func New(dataDir string, key ed25519.PrivateKey, orgs []Org) *Service {
	index := make(map[string]Org, len(orgs))
	for _, org := range orgs {
		index[org.Name] = org
	}
	return &Service{dataDir: dataDir, key: key, orgs: index}
}

// KeyID identifies the notary's countersigning key, which consumers pin.
func (s *Service) KeyID() string {
	return attest.KeyID(s.key.Public().(ed25519.PublicKey))
}

// name constrains org and marketplace path elements. They become directory names, so
// this is the traversal guard, and it is an allowlist rather than a ".." check because
// the set of strings that are safe as a path element is smaller than the set that merely
// lacks dots.
var name = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// Authorize checks an organisation's token in constant time.
func (s *Service) Authorize(orgName, token string) (Org, error) {
	org, known := s.orgs[orgName]
	// The comparison runs even for an unknown organisation so that the response time
	// does not say which half of the check failed.
	expected := org.Token
	match := subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
	if !known || !match || expected == "" || org.Publishers == nil {
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
	state, err := catalog.LoadState(s.statePath(org.Name, marketplace))
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

	// Drop any signature already claiming this notary's key before signing fresh. Two
	// real cases land here: a CI job re-run submits the countersigned output of its
	// previous run, which should be idempotent rather than a refusal; and an uploader
	// could attach a garbage signature under this notary's key id, which — if kept —
	// would make every threshold-2 machine refuse the whole envelope as a forgery. The
	// payload just verified, so replacing our own entry loses nothing.
	kept := envelope.Signatures[:0]
	for _, signature := range envelope.Signatures {
		if signature.KeyID != s.KeyID() {
			kept = append(kept, signature)
		}
	}
	envelope.Signatures = kept

	if err := attest.Countersign(&envelope, s.key); err != nil {
		return nil, err
	}
	countersigned, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}

	directory := filepath.Join(s.dataDir, "orgs", org.Name, marketplace)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomically(filepath.Join(directory, "catalog.dsse.json"), countersigned); err != nil {
		return nil, err
	}
	if err := state.Save(s.statePath(org.Name, marketplace), snapshot.Sequence, time.Now().UTC()); err != nil {
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
	body, err := os.ReadFile(filepath.Join(s.dataDir, "orgs", orgName, marketplace, "catalog.dsse.json"))
	if os.IsNotExist(err) {
		return nil, ErrAbsent
	}
	return body, err
}

func (s *Service) statePath(orgName, marketplace string) string {
	return filepath.Join(s.dataDir, "orgs", orgName, marketplace, "sequence.json")
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
