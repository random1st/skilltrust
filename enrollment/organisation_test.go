package enrollment

import (
	"strings"
	"testing"
	"time"

	"github.com/random1st/skilltrust/attest"
)

func TestEnrollmentOptionalTeamIsSignedAndValidated(t *testing.T) {
	_, key, _ := attest.GenerateKey()
	now := time.Now().UTC()
	request := Request{Audience: "https://axela.app", Nonce: strings.Repeat("ab", 32), TokenDigest: strings.Repeat("cd", 32), Machine: "Laptop", IssuedAt: now, ExpiresAt: now.Add(Lifetime)}
	for _, org := range []string{"", "acme", "Team_2"} {
		request.Organisation = org
		envelope, err := Sign(request, key)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := Verify(envelope, request.Audience, now)
		if err != nil || got.Organisation != org {
			t.Fatalf("team=%s got=%+v err=%v", org, got, err)
		}
	}
	for _, org := range []string{"../acme", "acme/other", "acme.example", "acme\n", strings.Repeat("a", 65)} {
		request.Organisation = org
		envelope, _ := Sign(request, key)
		if _, _, err := Verify(envelope, request.Audience, now); err == nil {
			t.Errorf("invalid team %q", org)
		}
	}
}

func TestValidOrganisationMatchesWhatVerifyAccepts(t *testing.T) {
	for name, want := range map[string]bool{
		"quandex": true, "random1st": true, "a_b-c": true,
		"": false, "not a team": false, "-leading": false, "тест": false,
	} {
		if got := ValidOrganisation(name); got != want {
			t.Errorf("ValidOrganisation(%q) = %v, want %v", name, got, want)
		}
	}
}
