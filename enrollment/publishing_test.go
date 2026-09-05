package enrollment

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
)

func TestPublishingProofCannotCrossServiceTimeOrPurpose(t *testing.T) {
	_, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := PublishingRequest{Audience: "https://axela.example", Organisation: "acme", Repository: "acme/skills@refs/heads/main", IssuedAt: now, ExpiresAt: now.Add(Lifetime)}
	envelope, err := SignPublishing(request, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyPublishing(envelope, request.Audience, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		audience string
		now      time.Time
	}{{"https://other.example", now}, {request.Audience, request.ExpiresAt}} {
		if _, _, err := VerifyPublishing(envelope, tc.audience, tc.now); err == nil {
			t.Fatal("accepted an expired or foreign-service proof")
		}
	}
	envelope.PayloadType = PayloadType
	if _, _, err := VerifyPublishing(envelope, request.Audience, now); err == nil {
		t.Fatal("accepted a machine enrollment as publisher setup")
	}
}

func TestPublishingProofRejectsTamperingAndOverlongApproval(t *testing.T) {
	_, key, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := PublishingRequest{Audience: "https://axela.example", Organisation: "acme", Repository: "acme/skills", IssuedAt: now, ExpiresAt: now.Add(Lifetime)}
	envelope, err := SignPublishing(request, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var tampered PublishingRequest
	if err := json.Unmarshal(body, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Repository = "attacker/skills"
	body, err = json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(body)
	if _, _, err := VerifyPublishing(envelope, request.Audience, now); err == nil {
		t.Fatal("accepted unsigned repository change")
	}
	request.ExpiresAt = now.Add(Lifetime + time.Second)
	envelope, err = SignPublishing(request, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyPublishing(envelope, request.Audience, now); err == nil {
		t.Fatal("accepted an overlong browser approval")
	}
}
