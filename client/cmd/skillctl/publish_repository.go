package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/random1st/skilltrust/enrollment"
	"github.com/random1st/skilltrust/internal/marketplace"
)

func publishingGit(directory string, environment []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", directory}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	cmd.Env = append(cmd.Env, environment...)
	output, err := cmd.Output()
	if err != nil {
		// Git stderr can contain credential-bearing remote URLs or hook output.
		// The user can diagnose the named native command in their own terminal.
		return "", fmt.Errorf("git %s did not finish successfully; check the repository's Git setup and retry", args[0])
	}
	return strings.TrimSuffix(string(output), "\n"), nil
}

func publishingRepository(directory string) (string, error) {
	if directory == "" {
		directory = "."
	}
	abs, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	root, err := publishingGit(abs, nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("open the Git repository that contains .claude-plugin/marketplace.json")
	}
	return filepath.EvalSymlinks(root)
}

var publishingGitHubName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func publishingGitHubRepository(raw string) (string, error) {
	var name string
	if strings.HasPrefix(raw, "git@github.com:") {
		name = strings.TrimPrefix(raw, "git@github.com:")
	} else {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host != "github.com" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Scheme != "https" && parsed.Scheme != "ssh") ||
			(parsed.User != nil && (parsed.Scheme != "ssh" || parsed.User.String() != "git")) {
			return "", fmt.Errorf("origin must point to a GitHub repository without embedded credentials")
		}
		name = strings.TrimPrefix(parsed.Path, "/")
	}
	name = strings.TrimSuffix(name, ".git")
	if !publishingGitHubName.MatchString(name) {
		return "", fmt.Errorf("origin must name one GitHub owner/repository")
	}
	return name, nil
}

func configurePublishing(record *publishingRecord, opts publishOptions) error {
	choose := func(saved *string, requested, fallback, label string) error {
		if *saved != "" && requested != "" && *saved != requested {
			return fmt.Errorf("%s differs from the saved publishing setup; keep the existing setup or use a separate SKILLTRUST_HOME", label)
		}
		if requested != "" {
			*saved = requested
		}
		if *saved == "" {
			*saved = fallback
		}
		return nil
	}
	if err := choose(&record.Organisation, opts.Organisation, "", "team"); err != nil {
		return err
	}
	if !catalogNameOK.MatchString(record.Organisation) {
		return fmt.Errorf("choose your team name once with skillctl publish --org <team>")
	}
	base := opts.ServiceURL
	var err error
	if base != "" {
		base, err = enrollment.BaseURL(base)
		if err != nil {
			return err
		}
	}
	if err := choose(&record.ServiceURL, base, connectDefaultBaseURL, "service"); err != nil {
		return err
	}
	if _, err := enrollment.BaseURL(record.ServiceURL); err != nil {
		return err
	}
	branch, err := publishingGit(record.Directory, nil, "symbolic-ref", "--short", "HEAD")
	if err != nil {
		return fmt.Errorf("check out the branch you intend to publish")
	}
	if err := choose(&record.Branch, opts.Branch, branch, "branch"); err != nil {
		return err
	}
	if _, err := workflowBranch(record.Branch); err != nil {
		return err
	}
	if record.Branch != branch {
		return fmt.Errorf("check out the saved publishing branch %s, then retry", record.Branch)
	}
	for _, args := range [][]string{{"remote", "get-url", "origin"}, {"remote", "get-url", "--push", "--all", "origin"}} {
		remote, err := publishingGit(record.Directory, nil, args...)
		if err != nil {
			return err
		}
		name, err := publishingGitHubRepository(remote)
		if err != nil {
			return err
		}
		if err := choose(&record.Repository, name, "", "GitHub repository"); err != nil {
			return err
		}
	}
	if opts.KeyPath != "" {
		record.KeyPath, err = filepath.Abs(opts.KeyPath)
	}
	return err
}

// Publication commits only its two generated files. A clean source revision is
// required so the signed bytes are also the bytes a consumer can fetch. Changes
// outside the marketplace's owned plugin roots keep their current staging.
func cleanPublishingSources(repository string, manifest *marketplace.Manifest) error {
	paths := []string{marketplace.ManifestPath}
	for _, entry := range manifest.Plugins {
		if directory, local := entry.LocalPath(repository); local {
			relative, err := filepath.Rel(repository, directory)
			if err != nil || strings.HasPrefix(relative, "..") {
				return fmt.Errorf("plugin sources must stay inside this repository")
			}
			paths = append(paths, filepath.ToSlash(relative))
		}
	}
	for _, command := range [][]string{{"diff", "--name-only", "-z", "HEAD", "--"}, {"ls-files", "--others", "--exclude-standard", "-z", "--"}} {
		output, err := publishingGit(repository, nil, append(command, paths...)...)
		if err != nil {
			return err
		}
		for _, path := range strings.Split(output, "\x00") {
			if path != "" && path != CatalogFileName && path != publishWorkflow {
				return fmt.Errorf("review and commit the skill source changes first (including %s), then run skillctl publish again; the publication will commit only its catalog and workflow", path)
			}
		}
	}
	return nil
}

// Build the exact prospective checkout without editing the real index. The new
// workflow belongs in the digest when the plugin is the repository root. Merely
// writing an untracked workflow and running Plan on the user's checkout would
// omit it, signing a tree that stops matching as soon as it is committed.
func publishingCoverage(repository, workflow string) (*marketplace.Coverage, error) {
	directory, err := os.MkdirTemp("", "skilltrust-publish-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	environment := []string{"GIT_INDEX_FILE=" + filepath.Join(directory, "index")}
	if _, err := publishingGit(repository, environment, "read-tree", "HEAD"); err != nil {
		return nil, err
	}
	checkout := filepath.Join(directory, "checkout")
	if err := os.MkdirAll(checkout, 0o700); err != nil {
		return nil, err
	}
	// Sign repository bytes, not a platform's optional CRLF checkout conversion.
	// The notary reads the GitHub revision on Linux and must see the same bytes.
	if _, err := publishingGit(repository, environment, "-c", "core.autocrlf=false", "-c", "core.eol=lf", "checkout-index", "--all", "--prefix="+checkout+string(os.PathSeparator)); err != nil {
		return nil, err
	}
	if err := checkPublishingPaths(checkout); err != nil {
		return nil, err
	}
	path := filepath.Join(checkout, publishWorkflow)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(workflow), 0o644); err != nil {
		return nil, err
	}
	manifest, err := marketplace.Load(checkout)
	if err != nil {
		return nil, err
	}
	return marketplace.Plan(checkout, manifest)
}

func checkPublishingPaths(repository string) error {
	for _, relative := range []string{CatalogFileName, ".github", ".github/workflows", publishWorkflow} {
		info, err := os.Lstat(filepath.Join(repository, relative))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("publishing files must be inside the repository, without symlinked paths: %s", relative)
		}
	}
	return nil
}
