package notary

import "testing"

func TestSecretMatchesOnlyItsPlaintext(t *testing.T) {
	secret := NewSecret("publish-token")

	if !secret.Matches("publish-token") {
		t.Fatal("the configured token must match")
	}
	for _, wrong := range []string{"", "publish-toke", "publish-tokenn", "PUBLISH-TOKEN"} {
		if secret.Matches(wrong) {
			t.Fatalf("%q must not match", wrong)
		}
	}
}

// A role nobody configured is closed, not open. The empty string is the value an absent
// Authorization header reduces to, so it is the case that matters.
func TestZeroSecretMatchesNothing(t *testing.T) {
	var disabled Secret

	if disabled.Enabled() {
		t.Fatal("the zero secret must report itself disabled")
	}
	for _, presented := range []string{"", "anything", NewSecret("").Digest()} {
		if disabled.Matches(presented) {
			t.Fatalf("a disabled secret matched %q", presented)
		}
	}
	if NewSecret("").Enabled() {
		t.Fatal("an empty plaintext must disable the role, not open it")
	}
}

// A stored digest reconstructs the same check, and the digest of a secret is not itself
// a usable token — presenting it must fail like any other wrong value.
func TestSecretRoundTripsThroughItsDigest(t *testing.T) {
	original := NewSecret("admin-token")

	restored, err := SecretFromDigest(original.Digest())
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Matches("admin-token") {
		t.Fatal("a secret restored from its digest must match the same plaintext")
	}
	if restored.Matches(original.Digest()) {
		t.Fatal("the digest must not work as a token")
	}

	if _, err := SecretFromDigest("not-hex"); err == nil {
		t.Fatal("unparsable stored digests must be an error, not a secret that matches nothing silently")
	}
	if _, err := SecretFromDigest("abcd"); err == nil {
		t.Fatal("a digest of the wrong length must be refused")
	}
	if empty, err := SecretFromDigest(""); err != nil || empty.Enabled() {
		t.Fatal("an absent stored digest is a disabled role")
	}
}
