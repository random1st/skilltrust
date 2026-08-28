// notaryd is the SkillTrust notary: it countersigns the catalogs organisations publish
// from CI and serves them to subscribed machines.
//
// It holds two kinds of secret — its countersigning key and each organisation's publish
// token — and no others. It never sees a publisher's private key, which is the property
// that makes running it tolerable: compromising this service yields the ability to
// countersign, and a machine that requires the publisher's signature too is still safe.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/server/notary"
)

type orgConfig struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	// IngestToken is what machines file events with; AdminToken is what an administrator
	// reads them with. Either may be empty, which disables that endpoint for the
	// organisation rather than opening it.
	IngestToken string `json:"ingest_token"`
	AdminToken  string `json:"admin_token"`
	// GitHubRepository lets that repository's Actions publish with their OIDC token
	// instead of a static secret. Empty keeps OIDC closed for this organisation.
	GitHubRepository string `json:"github_repository"`
	// MachineKeys are paths to PEM public keys of machines whose events the console
	// shows as verified — the same keys `skillctl trust` pins for the CLI.
	MachineKeys []string `json:"machine_keys"`
	// PublisherKeys are paths to PEM public keys allowed to sign this organisation's
	// catalogs — pinned here, in configuration an operator deploys, never learned from
	// an upload.
	PublisherKeys []string `json:"publisher_keys"`
}

type config struct {
	Listen string      `json:"listen"`
	Data   string      `json:"data"`
	Key    string      `json:"key"`
	Orgs   []orgConfig `json:"orgs"`
	// OIDCAudience is what publishing workflows must mint their token for. Defaults to
	// "skilltrust-notary"; set it when one issuer serves several notaries, so a token
	// minted for one cannot be replayed at another.
	OIDCAudience string `json:"oidc_audience"`
	// Brand names this deployment on its web pages; empty means the project name.
	Brand string `json:"brand"`
}

func main() {
	configPath := flag.String("config", "notary.json", "path to the notary configuration")
	flag.Parse()

	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "notaryd: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var conf config
	if err := json.Unmarshal(raw, &conf); err != nil {
		return fmt.Errorf("%s is not readable: %w", configPath, err)
	}
	if conf.Listen == "" || conf.Data == "" || conf.Key == "" {
		return fmt.Errorf("%s must set listen, data and key", configPath)
	}
	if len(conf.Orgs) == 0 {
		return fmt.Errorf("%s registers no organisations; a notary for nobody has nothing to do", configPath)
	}

	key, err := loadOrCreateKey(conf.Key)
	if err != nil {
		return err
	}

	orgs := make([]notary.Org, 0, len(conf.Orgs))
	for _, entry := range conf.Orgs {
		if entry.Token == "" {
			return fmt.Errorf("organisation %q has no token; an empty token would let anyone publish", entry.Name)
		}
		if len(entry.PublisherKeys) == 0 {
			return fmt.Errorf("organisation %q pins no publisher keys; there would be nothing to verify uploads against", entry.Name)
		}
		var publishers []ed25519.PublicKey
		for _, path := range entry.PublisherKeys {
			public, err := attest.LoadPublicKey(path)
			if err != nil {
				return fmt.Errorf("organisation %q: %w", entry.Name, err)
			}
			publishers = append(publishers, public)
		}
		var machines *attest.TrustedKeys
		if len(entry.MachineKeys) > 0 {
			var keys []ed25519.PublicKey
			for _, path := range entry.MachineKeys {
				public, err := attest.LoadPublicKey(path)
				if err != nil {
					return fmt.Errorf("organisation %q machine key: %w", entry.Name, err)
				}
				keys = append(keys, public)
			}
			machines = attest.NewTrustedKeys(keys...)
		}
		orgs = append(orgs, notary.Org{
			Name: entry.Name, Token: notary.NewSecret(entry.Token),
			IngestToken:      notary.NewSecret(entry.IngestToken),
			AdminToken:       notary.NewSecret(entry.AdminToken),
			GitHubRepository: entry.GitHubRepository,
			Publishers:       attest.NewTrustedKeys(publishers...),
			Machines:         machines,
		})
	}

	service := notary.New(conf.Data, key, orgs).WithBrand(conf.Brand)
	for _, org := range orgs {
		if org.GitHubRepository != "" {
			service.WithOIDC(&notary.OIDCVerifier{Audience: conf.OIDCAudience})
			log.Printf("notaryd: OIDC publishing enabled for repositories registered in the config")
			break
		}
	}
	log.Printf("notaryd: countersigning as %s", attest.Fingerprint(service.KeyID()))
	log.Printf("notaryd: %d organisation(s), listening on %s", len(orgs), conf.Listen)

	server := &http.Server{
		Addr:              conf.Listen,
		Handler:           service.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}

// loadOrCreateKey reads the countersigning key, provisioning it on first boot. The
// public half is written beside it because that file is what consumers pin, and an
// operator should not have to extract it from a private key to hand it out.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	key, err := attest.LoadPrivateKey(path)
	if err == nil {
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	public, private, err := attest.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := attest.WritePrivateKey(path, private); err != nil {
		return nil, err
	}
	publicPath := strings.TrimSuffix(path, ".key") + ".pub"
	if err := attest.WritePublicKey(publicPath, public); err != nil {
		return nil, err
	}
	log.Printf("notaryd: new countersigning key %s; consumers pin %s",
		attest.Fingerprint(attest.KeyID(public)), publicPath)
	return private, nil
}
