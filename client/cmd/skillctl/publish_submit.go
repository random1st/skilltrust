package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/random1st/skilltrust/attest"
	"github.com/random1st/skilltrust/catalog"
	"github.com/random1st/skilltrust/internal/marketplace"
)

var publishingPush = func(record *publishingRecord) error {
	_, err := publishingGit(record.Directory, nil, "push", "origin", record.SubmittedCommit+":refs/heads/"+record.Branch)
	return err
}

func publicationReviewID(record *publishingRecord) (string, error) {
	if err := checkPublishingPaths(record.Directory); err != nil {
		return "", err
	}
	parts := []string{record.SourceCommit, record.Organisation, record.Repository, record.Branch, record.ServiceURL, record.PublisherKeyID}
	parts = append(parts, record.NotaryKeys...)
	for _, name := range []string{CatalogFileName, publishWorkflow} {
		body, err := os.ReadFile(filepath.Join(record.Directory, name))
		if err != nil {
			return "", err
		}
		parts = append(parts, digestHex(body))
	}
	body, err := json.Marshal(parts)
	if err != nil {
		return "", err
	}
	return digestHex(body), nil
}

func submitPublication(record *publishingRecord, opts publishOptions, out publishingResult, envelope *attest.Envelope, key ed25519.PrivateKey) (publishingResult, error) {
	if record.ReviewID == "" || opts.Approve == "" || opts.Approve != record.ReviewID {
		return out, fmt.Errorf("prepare with skillctl publish first, review its changes, then submit with that exact --approve review ID")
	}
	reviewID, err := publicationReviewID(record)
	if err != nil {
		return out, err
	}
	if reviewID != record.ReviewID {
		return out, fmt.Errorf("the prepared files changed after review; run skillctl publish and review the new result before submitting")
	}
	manifest, err := marketplace.Load(record.Directory)
	if err != nil {
		return out, err
	}
	if err := cleanPublishingSources(record.Directory, manifest); err != nil {
		return out, err
	}
	head, err := publishingGit(record.Directory, nil, "rev-parse", "HEAD")
	if err != nil {
		return out, err
	}
	expected := record.SourceCommit
	if record.SubmittedCommit != "" {
		expected = record.SubmittedCommit
	}
	if head != expected {
		return out, fmt.Errorf("the source revision changed after review; prepare and review publication again")
	}
	if _, _, err := catalog.Verify(envelope, attest.NewTrustedKeys(key.Public().(ed25519.PublicKey)), nil, connectNow()); err != nil {
		return out, fmt.Errorf("the reviewed catalog is no longer valid; prepare and review publication again")
	}
	if record.SubmittedCommit == "" {
		if _, err := publishingGit(record.Directory, nil, "add", "--", CatalogFileName, publishWorkflow); err != nil {
			return out, err
		}
		if _, err := publishingGit(record.Directory, nil, "commit", "--only", "-m", "Publish reviewed skill catalog", "-m", "Publish the reviewed catalog and GitHub OIDC workflow together so the hosted catalog is attributable to this revision. The publisher key stays local; GitHub only submits its signed statement. Catalog validity is seven days to bound stale approvals.", "--", CatalogFileName, publishWorkflow); err != nil {
			return out, err
		}
		record.SubmittedCommit, err = publishingGit(record.Directory, nil, "rev-parse", "HEAD")
		if err != nil {
			return out, err
		}
		// Save before push. A failed push resumes this commit instead of creating
		// another signature, commit or remote operation with different bytes.
		if err := saveHomeJSON(publishingRecordPath(record.Directory), record); err != nil {
			return out, err
		}
	}
	if err := verifyPublicationCommit(record, envelope, key); err != nil {
		return out, err
	}
	if err := publishingPush(record); err != nil {
		out.Status, out.Title, out.Commit, out.ReviewID = "submission_pending", "Commit saved; push needs attention", record.SubmittedCommit, record.ReviewID
		out.NextAction = &nextAction{"retry_submission", "publisher", "Check GitHub access, then repeat skillctl publish --submit --approve " + record.ReviewID + ". The saved commit will be reused."}
		return out, nil
	}
	deadline := time.Now().Add(opts.Wait)
	for {
		status, err := publicationStatus(record, out, envelope, key)
		if err != nil || status.Status == "published" || !time.Now().Before(deadline) {
			return status, err
		}
		time.Sleep(min(time.Second, time.Until(deadline)))
	}
}

func verifyPublicationCommit(record *publishingRecord, envelope *attest.Envelope, key ed25519.PrivateKey) error {
	for _, name := range []string{CatalogFileName, publishWorkflow} {
		committed, err := publishingGit(record.Directory, nil, "show", record.SubmittedCommit+":"+name)
		if err != nil {
			return err
		}
		local, err := os.ReadFile(filepath.Join(record.Directory, name))
		if err != nil {
			return err
		}
		// publishingGit strips one trailing newline from command output.
		if committed != trimFinalNewline(string(local)) {
			return fmt.Errorf("Git changed the reviewed publication files during commit; inspect the commit before publishing")
		}
	}
	snapshot, _, err := catalog.Open(envelope, attest.NewTrustedKeys(key.Public().(ed25519.PublicKey)))
	if err != nil {
		return err
	}
	workflow, err := os.ReadFile(filepath.Join(record.Directory, publishWorkflow))
	if err != nil {
		return err
	}
	coverage, err := publishingCoverage(record.Directory, string(workflow))
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(snapshot.Skills, coverage.Signed) {
		return fmt.Errorf("the committed source differs from the approved catalog; prepare and review a new publication")
	}
	return nil
}

func trimFinalNewline(text string) string {
	if len(text) > 0 && text[len(text)-1] == '\n' {
		return text[:len(text)-1]
	}
	return text
}

func publicationStatus(record *publishingRecord, out publishingResult, expected *attest.Envelope, key ed25519.PrivateKey) (publishingResult, error) {
	out.Status, out.Title, out.Commit, out.ReviewID = "publication_pending", "Waiting for the verified catalog", record.SubmittedCommit, record.ReviewID
	out.NextAction = &nextAction{"verify_publication", "publisher", "Check the linked GitHub Actions run, then run skillctl publish --status. If the push failed, repeat --submit with the same approved review ID."}
	if expected == nil || record.ReviewID == "" || len(record.NotaryKeys) == 0 {
		return out, fmt.Errorf("prepare publishing with skillctl publish first")
	}
	reviewID, err := publicationReviewID(record)
	if err != nil || reviewID != record.ReviewID {
		return out, fmt.Errorf("the local publication changed after review; run skillctl publish and review its new result")
	}
	response, err := connectHTTPClient(connectTimeout).Get(out.CatalogURL)
	if err != nil {
		return out, fmt.Errorf("the hosted catalog could not be read; retry skillctl publish --status")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return out, nil
	}
	if response.StatusCode != http.StatusOK {
		return out, fmt.Errorf("the catalog could not be read (HTTP %d); retry", response.StatusCode)
	}
	var hosted attest.Envelope
	if err := json.NewDecoder(io.LimitReader(response.Body, connectMaxResponseBytes)).Decode(&hosted); err != nil {
		return out, fmt.Errorf("the hosted catalog is unreadable; check the publication run")
	}
	if hosted.PayloadType != expected.PayloadType || hosted.Payload != expected.Payload {
		return out, nil
	}
	// A matching payload is insufficient. The publisher and the independently
	// pinned notary must each have signed those exact bytes.
	snapshot, _, err := catalog.Verify(&hosted, attest.NewTrustedKeys(key.Public().(ed25519.PublicKey)), nil, connectNow())
	if err != nil {
		return out, fmt.Errorf("the hosted catalog does not carry a current approval by the original publisher")
	}
	notaries := []ed25519.PublicKey{}
	for _, encoded := range record.NotaryKeys {
		public, err := attest.ParsePublicKey([]byte(encoded))
		if err != nil {
			return out, fmt.Errorf("the saved notary key is unreadable")
		}
		if attest.KeyID(public) == attest.KeyID(key.Public().(ed25519.PublicKey)) {
			return out, fmt.Errorf("publisher and notary must be independent signers")
		}
		notaries = append(notaries, public)
	}
	if _, _, err := catalog.Verify(&hosted, attest.NewTrustedKeys(notaries...), nil, connectNow()); err != nil {
		return out, fmt.Errorf("the exact hosted catalog has not been approved by the pinned notary")
	}
	if len(snapshot.Skills) == 0 {
		return out, fmt.Errorf("the hosted catalog contains no skills")
	}
	out.Status, out.Title, out.NextAction = "published", "Published and verified on Axela", nil
	out.Sequence, out.ValidUntil, out.Skills = snapshot.Sequence, snapshot.ValidUntil, snapshot.Skills
	return out, nil
}
