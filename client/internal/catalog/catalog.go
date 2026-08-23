// Package catalog carries an organisation's signed statement about the skills it manages:
// which ones it publishes, at which exact bytes, and which digests may no longer be used.
//
// A signature is a statement about the past — these bytes were approved. Revocation is a
// statement about the present — this digest is no longer allowed *now* — and a claim about
// the present cannot be proved once and cached forever. That is what the sequence number
// and expiry are for, and why an absent or stale catalog is a refusal rather than a shrug.
//
// This is a deliberate strict subset of the TUF data model: a monotonic counter for
// rollback resistance and an expiry for freshness. Adopting full TUF later is additive
// rather than a rewrite, and until there is a public catalog somebody would actually try
// to freeze, the roles and rotation ceremonies are an operational programme rather than a
// feature.
package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"crypto/ed25519"

	"github.com/random1st/skilltrust/client/internal/attest"
)

// PayloadType keeps a catalog signature from being presented as an attestation, and the
// other way round.
const PayloadType = "application/vnd.skilltrust.catalog.v1+json"

// SnapshotVersion is the payload schema version.
const SnapshotVersion = 1

// Managed is one skill the catalog publishes: a name and the exact bytes that name is
// supposed to have right now.
//
// This is what makes central management possible without the client guessing. A machine does
// not decide which skills are managed — the catalog says so, under a signature — and every
// skill outside this list is the user's own business and is never touched or reported on.
// Getting that boundary wrong in either direction is the failure that matters: silence about
// a managed skill hides a compromise, and noise about an unmanaged one gets the tool removed.
type Managed struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	// Version is the version the client installs this under, which is part of the path the
	// installed copy lives at. Without it the tree to verify cannot be named.
	Version string `json:"version,omitempty"`
	// Path is where the skill lives inside the catalog repository, when it is not the
	// conventional skills/<name>.
	Path string `json:"path,omitempty"`
}

// Entry records one revoked artifact. Revocation is keyed by digest so it survives the
// skill being renamed, moved, or copied somewhere else.
type Entry struct {
	Digest    string    `json:"digest"`
	Reason    string    `json:"reason,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Snapshot is the signed revocation state at a point in time.
type Snapshot struct {
	Version int `json:"version"`
	// Sequence must never go backwards. A verifier that has seen N refuses N-1, which is
	// what stops an attacker replaying yesterday's catalog to un-revoke something.
	Sequence   int64     `json:"sequence"`
	IssuedAt   time.Time `json:"issued_at"`
	ValidUntil time.Time `json:"valid_until"`
	// Name identifies the catalog, so a machine subscribed to several can say which one a
	// skill belongs to and which key is allowed to speak for it.
	Name string `json:"name,omitempty"`
	// Skills is what this catalog publishes. Absent means the catalog only revokes, which
	// is the shape every catalog written before central management had.
	Skills  []Managed `json:"skills,omitempty"`
	Revoked []Entry   `json:"revoked"`
}

// Publishes returns the managed entry for a skill name.
func (s *Snapshot) Publishes(name string) (Managed, bool) {
	for _, entry := range s.Skills {
		if entry.Name == name {
			return entry, true
		}
	}
	return Managed{}, false
}

var (
	ErrExpired        = errors.New("catalog has expired")
	ErrRolledBack     = errors.New("catalog sequence went backwards")
	ErrFromFuture     = errors.New("catalog was issued in the future")
	ErrBadSnapshot    = errors.New("catalog payload is not readable")
	ErrUnknownVersion = errors.New("catalog version is not understood by this build")
)

// clockSkew is the tolerance for a catalog issued slightly ahead of local time. Wider
// would let a signer with a fast clock hide an expiry; narrower would break on ordinary
// drift between machines.
const clockSkew = 5 * time.Minute

// IsRevoked reports whether a digest appears in the snapshot.
func (s *Snapshot) IsRevoked(digest string) (Entry, bool) {
	for _, entry := range s.Revoked {
		if entry.Digest == digest {
			return entry, true
		}
	}
	return Entry{}, false
}

// Sign serializes the snapshot and signs those exact bytes.
func Sign(snapshot Snapshot, key ed25519.PrivateKey) (*attest.Envelope, error) {
	snapshot.Version = SnapshotVersion
	if snapshot.Sequence < 1 {
		return nil, errors.New("a catalog needs a sequence number of at least 1")
	}
	if snapshot.ValidUntil.Before(snapshot.IssuedAt) {
		return nil, errors.New("a catalog cannot expire before it was issued")
	}
	snapshot.IssuedAt = snapshot.IssuedAt.UTC().Truncate(time.Second)
	snapshot.ValidUntil = snapshot.ValidUntil.UTC().Truncate(time.Second)
	sort.Slice(snapshot.Revoked, func(i, j int) bool {
		return snapshot.Revoked[i].Digest < snapshot.Revoked[j].Digest
	})

	payload, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	return attest.SignPayload(PayloadType, payload, key), nil
}

// Verify checks the signature, then freshness and rollback against local state.
//
// The three failures are kept distinct on purpose. A bad signature is a forgery; an
// expired catalog means the answer is merely stale; a rolled-back sequence means someone
// is replaying an older answer. Only the first is an attack you can prove, but all three
// must deny, because a revocation check that cannot be trusted has not been performed.
func Verify(
	envelope *attest.Envelope,
	trusted *attest.TrustedKeys,
	state *State,
	now time.Time,
) (*Snapshot, string, error) {
	payload, keyID, err := attest.VerifyPayload(envelope, PayloadType, trusted)
	if err != nil {
		return nil, "", err
	}

	var snapshot Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrBadSnapshot, err)
	}
	if snapshot.Version != SnapshotVersion {
		return nil, "", fmt.Errorf("%w: version %d", ErrUnknownVersion, snapshot.Version)
	}

	if snapshot.IssuedAt.After(now.Add(clockSkew)) {
		return nil, "", fmt.Errorf("%w: issued %s, now %s",
			ErrFromFuture, snapshot.IssuedAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !now.Before(snapshot.ValidUntil) {
		return nil, "", fmt.Errorf("%w: valid until %s, now %s",
			ErrExpired, snapshot.ValidUntil.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if state != nil && snapshot.Sequence < state.Sequence {
		return nil, "", fmt.Errorf("%w: seen %d, offered %d",
			ErrRolledBack, state.Sequence, snapshot.Sequence)
	}

	return &snapshot, keyID, nil
}

// State is the highest catalog sequence this machine has accepted.
//
// It is ordinary local state and an attacker who can write it can reset it — the same
// boundary that lets them edit the skills in the first place. It raises the cost of a
// rollback from "serve an old file" to "also tamper with local state", and it is honest
// about being no more than that.
type State struct {
	Sequence int64     `json:"sequence"`
	SeenAt   time.Time `json:"seen_at"`
}

// LoadState reads the last-seen sequence. A missing file is sequence zero: nothing has
// been seen yet, so nothing can have gone backwards.
func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("%s is not a readable catalog state file: %w", path, err)
	}
	return &state, nil
}

// Save records the accepted sequence, never lowering it.
func (s *State) Save(path string, sequence int64, now time.Time) error {
	if sequence < s.Sequence {
		return fmt.Errorf("%w: refusing to record %d over %d", ErrRolledBack, sequence, s.Sequence)
	}
	s.Sequence = sequence
	s.SeenAt = now.UTC().Truncate(time.Second)

	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// The sequence a machine has seen is often the first thing it records, before anything
	// has created the directory to record it in. Failing there would leave the machine
	// unable to adopt a catalog at all — and, worse, would surface as "this catalog could
	// not be used" rather than as the missing directory it is.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFile(path, append(body, '\n'))
}

// DefaultStatePath sits beside the catalog it tracks.
func DefaultStatePath(catalogPath string) string {
	return catalogPath + ".state"
}

func writeFile(path string, body []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)

	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Open verifies a snapshot's signature and schema without checking freshness or sequence.
//
// It exists for the publisher, and only for the publisher. Expiry is a promise made to
// consumers — after this moment, stop believing me — and enforcing it against the author
// reading their own previous index makes a catalog unrepublishable exactly once it has gone
// stale, which is the moment republishing is most needed. A week of inattention would
// otherwise close the publishing path until somebody deleted the file, and deleting it would
// take every revocation in it along too.
//
// Consumers must keep using Verify. The difference between the two is the entire freshness
// guarantee, so a caller reaching for Open is asserting it is the signer.
func Open(envelope *attest.Envelope, trusted *attest.TrustedKeys) (*Snapshot, string, error) {
	payload, keyID, err := attest.VerifyPayload(envelope, PayloadType, trusted)
	if err != nil {
		return nil, "", err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrBadSnapshot, err)
	}
	if snapshot.Version != SnapshotVersion {
		return nil, "", fmt.Errorf("%w: version %d", ErrUnknownVersion, snapshot.Version)
	}
	return &snapshot, keyID, nil
}
