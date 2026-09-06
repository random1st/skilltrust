package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/internal/source"
)

// Network and Git work run outside the state lock. Refuse a stale commit if any
// input changed in that interval, including explicit pin removal or newer checks.
type publicSubscriptionState map[string]string

func readPublicSubscriptionState(ctx context.Context, name string) (publicSubscriptionState, []Subscription, map[string]ed25519.PublicKey, error) {
	unlock, err := acquireConsumerState(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer unlock()
	return readPublicSubscriptionStateLocked(name)
}

// The caller holds the command's consumer-state lock.
func readPublicSubscriptionStateLocked(name string) (publicSubscriptionState, []Subscription, map[string]ed25519.PublicKey, error) {
	baseline := publicSubscriptionState{}
	entry := Subscription{Name: name, CatalogURL: "hosted"}
	for _, path := range []string{subscriptionsPath(), defaultTrustedKeys(), defaultSigningKey(), defaultPublicKey(),
		connectStatePath(), connectCredentialsPath(), pendingConnectPath(),
		indexPath(entry), snapshotStatePath(entry), source.Path(catalogRoot(), name)} {
		digest, err := subscriptionStateDigest(path)
		if err != nil {
			return nil, nil, nil, err
		}
		baseline[path] = digest
	}
	subscriptions, err := loadSubscriptions()
	if err != nil {
		return nil, nil, nil, err
	}
	pins, err := attest.PinnedKeys(defaultTrustedKeys())
	return baseline, subscriptions, pins, err
}

func (baseline publicSubscriptionState) unchanged() error {
	for path, expected := range baseline {
		current, err := subscriptionStateDigest(path)
		if err != nil {
			return err
		}
		if current != expected {
			return fmt.Errorf("local subscription state changed while checking the publisher; no changes were saved. Retry the subscription with the current keys and catalog")
		}
	}
	return nil
}

func subscriptionStateDigest(path string) (string, error) {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return "absent", nil
	} else if err != nil {
		return "", err
	}
	hash := sha256.New()
	err := filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(path, current)
		if err != nil {
			return err
		}
		fmt.Fprintf(hash, "%s\x00%d\x00%d\x00", relative, info.Mode(), info.Size())
		if entry.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(current)
			if err == nil {
				_, err = io.WriteString(hash, target)
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("subscription state contains a non-regular file at %q", current)
		}
		file, err := os.Open(current)
		if err != nil {
			return err
		}
		_, readErr := io.Copy(hash, file)
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		return closeErr
	})
	return fmt.Sprintf("%x", hash.Sum(nil)), err
}
