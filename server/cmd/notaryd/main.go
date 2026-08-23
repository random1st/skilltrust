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

	"github.com/random1st/skilltrust/internal/attest"
	"github.com/random1st/skilltrust/server/notary"
)

type orgConfig struct {
	Name  string `json:"name"`
	Token string `json:"token"`
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
		orgs = append(orgs, notary.Org{
			Name: entry.Name, Token: entry.Token,
			Publishers: attest.NewTrustedKeys(publishers...),
		})
	}

	service := notary.New(conf.Data, key, orgs)
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
