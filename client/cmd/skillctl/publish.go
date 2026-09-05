package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/enrollment"
	"github.com/random1st/skilltrust/internal/marketplace"
)

const publishWorkflow = ".github/workflows/notarize.yml"

// The record stays local. In particular, neither the key path nor the private
// key is part of the public result returned to an agent.
type publishingRecord struct {
	Version         int      `json:"version"`
	Directory       string   `json:"directory"`
	Organisation    string   `json:"organisation"`
	Repository      string   `json:"repository"`
	Branch          string   `json:"branch"`
	ServiceURL      string   `json:"service_url"`
	KeyPath         string   `json:"key_path"`
	PublisherKeyID  string   `json:"publisher_key_id"`
	NotaryKeys      []string `json:"notary_keys"`
	ReviewID        string   `json:"review_id,omitempty"`
	SourceCommit    string   `json:"source_commit,omitempty"`
	SubmittedCommit string   `json:"submitted_commit,omitempty"`
	Renewal         bool     `json:"renewal,omitempty"`
}

type publishingResult struct {
	Status       string              `json:"status"`
	Title        string              `json:"title"`
	NextAction   *nextAction         `json:"next_action,omitempty"`
	ApprovalURL  string              `json:"approval_url,omitempty"`
	Fingerprint  string              `json:"fingerprint,omitempty"`
	DashboardURL string              `json:"dashboard_url,omitempty"`
	ActionsURL   string              `json:"actions_url,omitempty"`
	CatalogURL   string              `json:"catalog_url,omitempty"`
	ReviewID     string              `json:"review_id,omitempty"`
	Files        []string            `json:"files,omitempty"`
	Skills       []catalog.Managed   `json:"skills,omitempty"`
	Unversioned  []string            `json:"unversioned,omitempty"`
	Remote       map[string][]string `json:"remote,omitempty"`
	Partial      []string            `json:"partial,omitempty"`
	Sequence     int64               `json:"sequence,omitempty"`
	ValidUntil   time.Time           `json:"valid_until,omitempty"`
	Commit       string              `json:"commit,omitempty"`
}

type publishOptions struct {
	Directory, Organisation, Branch, ServiceURL, KeyPath, Approve string
	Renew, Submit, Status, NoBrowser                              bool
	Wait                                                          time.Duration
}

func publishingRecordPath(directory string) string {
	return filepath.Join(Home(), "publishing", digestHex([]byte(directory))+".json")
}

func loadPublishingRecord(directory string) (*publishingRecord, error) {
	body, err := os.ReadFile(publishingRecordPath(directory))
	if os.IsNotExist(err) {
		return &publishingRecord{Version: 1, Directory: directory}, nil
	}
	if err != nil {
		return nil, err
	}
	var record publishingRecord
	if json.Unmarshal(body, &record) != nil || record.Version != 1 || record.Directory != directory {
		return nil, fmt.Errorf("the saved publishing setup is unreadable; keep the existing signing key and diagnose the local setup")
	}
	return &record, nil
}

func rememberPublisher(directory, keyPath string, key ed25519.PrivateKey) error {
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	record, err := loadPublishingRecord(directory)
	if err != nil {
		return err
	}
	record.KeyPath, err = filepath.Abs(keyPath)
	if err != nil {
		return err
	}
	record.PublisherKeyID = attest.KeyID(key.Public().(ed25519.PublicKey))
	return saveHomeJSON(publishingRecordPath(directory), record)
}

func publish(opts publishOptions) (out publishingResult, err error) {
	out = publishingResult{Status: "needs_attention", Title: "Publishing needs attention"}
	repository, err := publishingRepository(opts.Directory)
	if err != nil {
		return out, err
	}
	record, err := loadPublishingRecord(repository)
	if err != nil {
		return out, err
	}
	if err := configurePublishing(record, opts); err != nil {
		return out, err
	}
	manifest, err := marketplace.Load(repository)
	if err != nil {
		return out, err
	}
	if !catalogNameOK.MatchString(manifest.Name) {
		return out, fmt.Errorf("give the marketplace a name using letters, numbers, hyphens or underscores")
	}
	keyPath := record.KeyPath
	if keyPath == "" {
		keyPath = defaultSigningKey()
	}
	key, err := attest.LoadPrivateKey(keyPath)
	if os.IsNotExist(err) && record.PublisherKeyID == "" && opts.KeyPath == "" {
		if _, catalogErr := os.Stat(filepath.Join(repository, CatalogFileName)); os.IsNotExist(catalogErr) {
			key, _, _, err = ensureSigningKey("")
		}
	}
	if err != nil {
		return out, fmt.Errorf("the original publisher key is needed; configure its local path with skillctl publish --key (never paste the private key)")
	}
	keyID := attest.KeyID(key.Public().(ed25519.PublicKey))
	if record.PublisherKeyID != "" && record.PublisherKeyID != keyID {
		return out, fmt.Errorf("use the existing publisher key; publishing never rotates it")
	}
	record.KeyPath, err = filepath.Abs(keyPath)
	if err != nil {
		return out, err
	}
	record.PublisherKeyID = keyID
	out.Fingerprint = attest.Fingerprint(keyID)
	var previous *catalog.Snapshot
	previousEnvelope, loadErr := attest.LoadEnvelope(filepath.Join(repository, CatalogFileName))
	if loadErr == nil {
		previous, _, err = catalog.Open(previousEnvelope, attest.NewTrustedKeys(key.Public().(ed25519.PublicKey)))
		if err != nil {
			return out, fmt.Errorf("this catalog was signed by another publisher; use its original signing key")
		}
		if previous.Name != manifest.Name {
			return out, fmt.Errorf("the catalog and marketplace names differ; review the marketplace before publishing")
		}
	} else if !os.IsNotExist(loadErr) {
		return out, loadErr
	}
	if err := saveHomeJSON(publishingRecordPath(repository), record); err != nil {
		return out, err
	}
	out.DashboardURL = record.ServiceURL + "/organisations/" + record.Organisation + "/publishing"
	out.ActionsURL = "https://github.com/" + record.Repository + "/actions/workflows/notarize.yml"
	out.CatalogURL, err = notaryCatalogURL(record.ServiceURL, record.Organisation, manifest.Name)
	if err != nil {
		return out, err
	}
	if opts.Submit {
		return submitPublication(record, opts, out, previousEnvelope, key)
	}
	if opts.Status {
		return publicationStatus(record, out, previousEnvelope, key)
	}
	// A submitted operation is resumed before preparing another sequence. A new
	// renewal after successful verification is an explicit new operation.
	if record.SubmittedCommit != "" {
		head, readErr := publishingGit(repository, nil, "rev-parse", "HEAD")
		if readErr != nil {
			return out, readErr
		}
		if head == record.SubmittedCommit && (!opts.Renew || previous != nil && previous.ValidUntil.After(connectNow().Add(catalog.RenewalWindow))) {
			return publicationStatus(record, out, previousEnvelope, key)
		}
	}
	now := connectNow()
	proof, err := enrollment.SignPublishing(enrollment.PublishingRequest{
		Audience: record.ServiceURL, Organisation: record.Organisation,
		Repository: record.Repository + "@refs/heads/" + record.Branch,
		IssuedAt:   now, ExpiresAt: now.Add(enrollment.Lifetime),
	}, key)
	if err != nil {
		return out, err
	}
	setup, err := publishingSetup(record.ServiceURL, proof)
	if err != nil {
		return out, err
	}
	if !setup.Ready {
		body, err := json.Marshal(proof)
		if err != nil {
			return out, err
		}
		out.Status, out.Title = "approval_pending", "Approve publishing in the browser"
		out.ApprovalURL = record.ServiceURL + "/publish?request=" + url.QueryEscape(base64.RawURLEncoding.EncodeToString(body))
		out.NextAction = &nextAction{"approve_publisher", "owner", "Open the approval link, sign in and confirm this team and repository. Then run skillctl publish again to continue."}
		if !opts.NoBrowser {
			_ = connectOpenBrowser(out.ApprovalURL)
		}
		return out, nil
	}
	if err := acceptPublishingKeys(record, setup.NotaryKeys); err != nil {
		return out, err
	}
	if err := cleanPublishingSources(repository, manifest); err != nil {
		return out, err
	}
	if err := checkPublishingPaths(repository); err != nil {
		return out, err
	}
	workflow := marketplaceWorkflow(workflowActionRef(), record.Branch, out.CatalogURL)
	if _, err := writeGeneratedWorkflow(filepath.Join(repository, publishWorkflow), workflow); err != nil {
		return out, err
	}
	coverage, err := publishingCoverage(repository, workflow)
	if err != nil {
		return out, err
	}
	if len(coverage.Signed) == 0 {
		return out, fmt.Errorf("this marketplace has no local, versioned plugins to publish")
	}
	if opts.Renew && (previous == nil || !reflect.DeepEqual(previous.Skills, coverage.Signed)) {
		return out, fmt.Errorf("the skills changed since the last publication; review a normal skillctl publish instead of renewing their old approval")
	}
	sourceCommit, err := publishingGit(repository, nil, "rev-parse", "HEAD")
	if err != nil {
		return out, err
	}
	// Repeating the same preparation must not keep signing new sequences.
	reuse := previous != nil && record.ReviewID != "" && record.SubmittedCommit == "" && reflect.DeepEqual(previous.Skills, coverage.Signed) && previous.ValidUntil.After(connectNow().Add(catalog.RenewalWindow))
	if opts.Renew {
		reuse = reuse && record.Renewal && record.SubmittedCommit == "" && record.SourceCommit == sourceCommit && record.ReviewID != ""
	}
	if !reuse {
		snapshot := catalog.Snapshot{Name: manifest.Name, Sequence: 1, IssuedAt: connectNow(), ValidUntil: connectNow().Add(7 * 24 * time.Hour), Skills: coverage.Signed}
		if previous != nil {
			snapshot.Sequence, snapshot.Revoked = previous.Sequence+1, previous.Revoked
		}
		previousEnvelope, err = catalog.Sign(snapshot, key)
		if err != nil {
			return out, err
		}
		if err := previousEnvelope.Save(filepath.Join(repository, CatalogFileName)); err != nil {
			return out, err
		}
		previous = &snapshot
	}
	record.SourceCommit, record.SubmittedCommit, record.Renewal = sourceCommit, "", opts.Renew
	record.ReviewID, err = publicationReviewID(record)
	if err != nil {
		return out, err
	}
	if err := saveHomeJSON(publishingRecordPath(repository), record); err != nil {
		return out, err
	}
	out.Status, out.Title = "prepared", "Ready for publication review"
	out.ReviewID, out.Files = record.ReviewID, []string{CatalogFileName, publishWorkflow}
	out.Skills, out.Sequence, out.ValidUntil = previous.Skills, previous.Sequence, previous.ValidUntil
	out.Unversioned, out.Remote, out.Partial = coverage.Unversioned, coverage.Remote, coverage.Partial
	out.NextAction = &nextAction{"review_publication", "publisher", "Review the catalog and workflow diff. After approval, run skillctl publish --submit --approve " + record.ReviewID + ". This commits those two files, pushes this branch and verifies the hosted catalog."}
	return out, nil
}

func acceptPublishingKeys(record *publishingRecord, keys []string) error {
	if len(keys) == 0 {
		return fmt.Errorf("the service returned no notary keys; retry setup")
	}
	ids := []string{}
	for _, encoded := range keys {
		key, err := attest.ParsePublicKey([]byte(encoded))
		if err != nil {
			return fmt.Errorf("the service returned an unreadable notary key")
		}
		if attest.KeyID(key) == record.PublisherKeyID {
			return fmt.Errorf("publisher and notary must use different keys")
		}
		ids = append(ids, attest.KeyID(key))
	}
	if len(record.NotaryKeys) > 0 {
		for _, encoded := range record.NotaryKeys {
			key, err := attest.ParsePublicKey([]byte(encoded))
			if err == nil && slices.Contains(ids, attest.KeyID(key)) {
				return nil
			}
		}
		return fmt.Errorf("the notary keys changed; verify their signed rotation before changing the saved trust")
	}
	record.NotaryKeys = keys
	return nil
}

func publishingSetup(base string, proof *attest.Envelope) (*enrollment.PublishingSetup, error) {
	body, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	response, err := connectHTTPClient(connectTimeout).Post(base+"/v1/publishing/status", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("Axela could not be reached; run skillctl publish again to resume")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Axela could not confirm publishing setup (HTTP %d); retry", response.StatusCode)
	}
	var setup enrollment.PublishingSetup
	if err := json.NewDecoder(io.LimitReader(response.Body, connectMaxResponseBytes)).Decode(&setup); err != nil {
		return nil, fmt.Errorf("Axela returned an unreadable publishing status; retry")
	}
	return &setup, nil
}

func runPublish(args []string) int {
	flags := flag.NewFlagSet("publish", flag.ContinueOnError)
	var opts publishOptions
	flags.StringVar(&opts.Organisation, "org", "", "team name, remembered after first setup")
	flags.StringVar(&opts.Branch, "branch", "", "publishing branch; defaults to the current branch")
	flags.StringVar(&opts.ServiceURL, "notary", "", "Axela service URL; defaults to https://axela.app")
	flags.StringVar(&opts.KeyPath, "key", "", "local path to the original publisher key, remembered for renewal")
	flags.BoolVar(&opts.Renew, "renew", false, "renew unchanged skills using their original signer")
	flags.BoolVar(&opts.Submit, "submit", false, "commit and push the explicitly approved preparation")
	flags.StringVar(&opts.Approve, "approve", "", "review ID returned by the preparation you approved")
	flags.BoolVar(&opts.Status, "status", false, "verify the saved publication without preparing or submitting")
	flags.BoolVar(&opts.NoBrowser, "no-browser", false, "return the browser approval link without opening it")
	flags.DurationVar(&opts.Wait, "wait", 0, "wait up to one minute for the submitted catalog")
	asJSON := flags.Bool("json", false, "return public publishing state as JSON")
	if err := parseArgs(flags, args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitUsage
	}
	if flags.NArg() > 1 || opts.Wait < 0 || opts.Wait > time.Minute || opts.Status && (opts.Submit || opts.Renew) {
		return fail(fmt.Errorf("use one repository, a wait between 0 and 1m, and --status on its own"))
	}
	opts.Directory = flags.Arg(0)
	out, err := publish(opts)
	if err != nil {
		out.Status, out.Title, out.NextAction = "needs_attention", "Publishing needs attention", &nextAction{"retry_publishing", "publisher", err.Error()}
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(out)
	} else {
		fmt.Println(out.Title)
		if out.Fingerprint != "" {
			fmt.Println("Signing code: " + out.Fingerprint)
		}
		if out.NextAction != nil {
			fmt.Println(out.NextAction.Detail)
		}
		if out.ApprovalURL != "" {
			fmt.Println(out.ApprovalURL)
		}
		if out.Sequence > 0 {
			fmt.Printf("Catalog: %d skills, sequence %d, valid until %s\n", len(out.Skills), out.Sequence, out.ValidUntil.Format(time.RFC3339))
		}
		if len(out.Unversioned) > 0 || len(out.Remote) > 0 || len(out.Partial) > 0 {
			fmt.Println("Coverage limitations:")
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"unversioned": out.Unversioned, "remote": out.Remote, "partial": out.Partial})
		}
		if out.ActionsURL != "" {
			fmt.Println(out.ActionsURL)
		}
	}
	if err != nil {
		return exitUsage
	}
	if out.Status == "published" {
		return exitClean
	}
	return exitFindings
}
