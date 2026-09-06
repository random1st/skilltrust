package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/source"
)

// save commits only a fully verified subscription. Pins are promoted last, with
// no fallible write afterwards. A failed promotion restores the previous files
// and checkout; ordinary validation failures never reach the trust store.
// Each rename is atomic. This is not a multi-file database transaction on crash:
// interruption before the final pin write can leave an unverifiable cache, which
// fails closed and can be retried without restarting trust discovery.
func (r publicSubscriptionResolver) save(ctx context.Context, baseline publicSubscriptionState, stage string, entry Subscription, subscriptions []Subscription, pins map[string]ed25519.PublicKey, index []byte, sequence int64, now time.Time) error {
	unlock, err := acquireConsumerState(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return r.saveLocked(baseline, stage, entry, subscriptions, pins, index, sequence, now)
}

// saveLocked is used by check/install, whose CLI entry already holds the lock.
func (r publicSubscriptionResolver) saveLocked(baseline publicSubscriptionState, stage string, entry Subscription, subscriptions []Subscription, pins map[string]ed25519.PublicKey, index []byte, sequence int64, now time.Time) error {
	if err := baseline.unchanged(); err != nil {
		return err
	}
	public, created, err := stagePublicSigningKey(stage)
	if err != nil {
		return err
	}
	pins["machine:"+attest.KeyID(public)] = public
	sort.Slice(subscriptions, func(i, j int) bool { return subscriptions[i].Name < subscriptions[j].Name })
	encodedPins := map[string]string{}
	for label, key := range pins {
		pem, err := attest.EncodePublicKey(key)
		if err != nil {
			return err
		}
		encodedPins[label] = string(pem)
	}
	type promotion struct {
		from, to, backup string
		directory, old   bool
		promoted         bool
	}
	changes := []promotion{{from: source.Path(stage, entry.Name), to: source.Path(catalogRoot(), entry.Name), directory: true}}
	if created {
		changes = append(changes,
			promotion{from: filepath.Join(stage, "signer.key"), to: defaultSigningKey()},
			promotion{from: filepath.Join(stage, "signer.pub"), to: defaultPublicKey()})
	}
	for _, file := range []struct {
		path  string
		value any
		bytes []byte
	}{
		{path: indexPath(entry), bytes: index},
		{path: snapshotStatePath(entry), value: catalog.State{Sequence: sequence, SeenAt: now.UTC().Truncate(time.Second)}},
		{path: subscriptionsPath(), value: subscriptions},
		{path: defaultTrustedKeys(), value: struct {
			Version int               `json:"version"`
			Keys    map[string]string `json:"keys"`
		}{Version: 1, Keys: encodedPins}},
	} {
		body := file.bytes
		if file.value != nil {
			var err error
			body, err = json.MarshalIndent(file.value, "", "  ")
			if err != nil {
				return err
			}
			body = append(body, '\n')
		}
		staged := filepath.Join(stage, fmt.Sprintf("state-%d", len(changes)))
		if err := os.WriteFile(staged, body, 0o600); err != nil {
			return err
		}
		changes = append(changes, promotion{from: staged, to: file.path})
	}
	for index := range changes {
		change := &changes[index]
		if err := validatePublicDestination(change.to, change.directory); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(change.to), 0o700); err != nil {
			return err
		}
		change.backup = filepath.Join(stage, fmt.Sprintf("previous-%d", index))
	}
	rollback := func(cause error) error {
		failed := false
		for index := len(changes) - 1; index >= 0; index-- {
			change := &changes[index]
			if change.promoted {
				if err := os.Rename(change.to, change.from); err != nil {
					failed = true
					cause = errors.Join(cause, fmt.Errorf("could not withdraw incomplete subscription file %s: %w", change.to, err))
					continue
				}
			}
			if change.old {
				if err := os.Rename(change.backup, change.to); err != nil {
					failed = true
					cause = errors.Join(cause, fmt.Errorf("could not restore previous subscription file %s: %w", change.to, err))
				}
			}
		}
		if failed {
			return &publicSubscriptionRecoveryError{stage: stage, cause: cause}
		}
		return cause
	}
	for index := range changes {
		change := &changes[index]
		if _, err := os.Lstat(change.to); err == nil {
			if err := r.rename(change.to, change.backup); err != nil {
				return rollback(err)
			}
			change.old = true
		} else if !os.IsNotExist(err) {
			return rollback(err)
		}
		if err := r.rename(change.from, change.to); err != nil {
			return rollback(err)
		}
		change.promoted = true
	}
	return nil
}

type publicSubscriptionRecoveryError struct {
	stage string
	cause error
}

func (e *publicSubscriptionRecoveryError) Error() string {
	return fmt.Sprintf("subscription storage failed: %v; previous files are preserved at %s", e.cause, e.stage)
}

func (e *publicSubscriptionRecoveryError) Unwrap() error { return e.cause }

// The signer is the existing local-check mechanism, not an Axela enrollment.
// Partial, malformed or symlinked identities are preserved for explicit repair.
func stagePublicSigningKey(stage string) (ed25519.PublicKey, bool, error) {
	var present []bool
	for _, path := range []string{defaultSigningKey(), defaultPublicKey()} {
		info, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, false, err
		}
		if err == nil && !info.Mode().IsRegular() {
			return nil, false, fmt.Errorf("the existing machine identity is not a regular file; keep it and repair it explicitly")
		}
		present = append(present, err == nil)
	}
	if present[0] != present[1] {
		return nil, false, fmt.Errorf("the existing machine identity is incomplete; keep it and restore the missing key file")
	}
	if present[0] {
		private, err := attest.LoadPrivateKey(defaultSigningKey())
		if err != nil {
			return nil, false, err
		}
		public, err := attest.LoadPublicKey(defaultPublicKey())
		if err != nil {
			return nil, false, err
		}
		if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
			return nil, false, fmt.Errorf("the existing machine key pair does not match; keep it and repair it explicitly")
		}
		return public, false, nil
	}
	public, private, err := attest.GenerateKey()
	if err != nil {
		return nil, false, err
	}
	if err := attest.WritePrivateKey(filepath.Join(stage, "signer.key"), private); err != nil {
		return nil, false, err
	}
	if err := attest.WritePublicKey(filepath.Join(stage, "signer.pub"), public); err != nil {
		return nil, false, err
	}
	return public, true, nil
}

// Refuse symlinked state destinations and parent directories. A subscription is
// permission to write the owned state tree, not a symlink's unrelated target.
func validatePublicDestination(destination string, directory bool) error {
	root, err := filepath.Abs(Home())
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	for current := absolute; current != root; current = filepath.Dir(current) {
		if filepath.Dir(current) == current {
			return fmt.Errorf("subscription destination is outside its state directory")
		}
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; subscription state must stay inside its own directory", current)
		}
		wantDirectory := current != absolute || directory
		if wantDirectory && !info.IsDir() || !wantDirectory && !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a usable subscription state destination", current)
		}
	}
	return nil
}
