package enrollment

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/random1st/skilltrust/attest"
)

const PublishingPayloadType = "application/vnd.skilltrust.publishing-setup.v1+json"

// PublishingRequest carries public setup choices and proves possession of the
// publisher key. It cannot authorize registration or publishing: the browser
// owner must consent, and each catalog still needs GitHub OIDC admission.
type PublishingRequest struct {
	Version      int       `json:"version"`
	Audience     string    `json:"audience"`
	Organisation string    `json:"organisation"`
	Repository   string    `json:"repository"`
	PublicKey    string    `json:"public_key"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type PublishingSetup struct {
	Ready      bool     `json:"ready"`
	NotaryKeys []string `json:"notary_keys,omitempty"`
}

var publishingName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func SignPublishing(request PublishingRequest, key ed25519.PrivateKey) (*attest.Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("unusable publisher key")
	}
	request.Version = 1
	public, err := attest.EncodePublicKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	request.PublicKey = string(public)
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return attest.SignPayload(PublishingPayloadType, payload, key), nil
}

func VerifyPublishing(envelope *attest.Envelope, audience string, now time.Time) (*PublishingRequest, string, error) {
	invalid := func() (*PublishingRequest, string, error) {
		return nil, "", fmt.Errorf("start publishing again with skillctl publish")
	}
	if envelope == nil {
		return invalid()
	}
	body, err := json.Marshal(envelope)
	if err != nil || len(body) > MaxBytes {
		return invalid()
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return invalid()
	}
	var request PublishingRequest
	if json.Unmarshal(payload, &request) != nil {
		return invalid()
	}
	key, err := attest.ParsePublicKey([]byte(request.PublicKey))
	if err != nil {
		return invalid()
	}
	if _, _, err = attest.VerifyPayload(envelope, PublishingPayloadType, attest.NewTrustedKeys(key)); err != nil {
		return invalid()
	}
	base, err := BaseURL(request.Audience)
	if err != nil || base != audience || base != request.Audience || request.Version != 1 || !publishingName.MatchString(request.Organisation) || len(request.Repository) == 0 || len(request.Repository) > 256 {
		return invalid()
	}
	if request.IssuedAt.After(now.Add(time.Minute)) || !request.ExpiresAt.After(now) || !request.ExpiresAt.After(request.IssuedAt) || request.ExpiresAt.Sub(request.IssuedAt) > Lifetime {
		return invalid()
	}
	return &request, attest.KeyID(key), nil
}
