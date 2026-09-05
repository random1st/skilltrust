// Package source fetches skills from a git repository and pins what it fetched.
//
// This is what makes the tool an installer rather than an observer. Skills previously
// arrived by some other means — a marketplace clone, a symlink, a copy — and skillctl was
// left to audit a tree it had no part in creating. That ordering cannot work: an approval
// signed over bytes that something else is free to replace says nothing the moment the other
// thing runs. Owning the install is what makes the signature mean anything afterwards.
package source

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Directory is where fetched repositories are kept inside the skilltrust home.
const Directory = "sources"

// SkillsSubdirectory is the conventional place a marketplace keeps its skills. A repository
// that does not use it is still scanned from the root, so this is a hint and not a rule.
const SkillsSubdirectory = "skills"

const commandWaitDelay = 250 * time.Millisecond

// Source is a git repository this machine installs skills from.
type Source struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Ref        string `json:"ref,omitempty"`
	Commit     string `json:"commit"`
}

// Path returns where a named source is checked out.
func Path(root, name string) string { return filepath.Join(root, Directory, name) }

// NameFor derives a short name from a repository URL: the last path segment without .git.
func NameFor(repository string) string {
	trimmed := strings.TrimSuffix(strings.TrimRight(repository, "/"), ".git")
	if index := strings.LastIndexAny(trimmed, "/:"); index >= 0 {
		trimmed = trimmed[index+1:]
	}
	return trimmed
}

// Fetch clones the repository, or updates an existing checkout, and reports what it has.
//
// A shallow checkout is deliberate: this needs the tree at one ref, never the history, and
// fetching megabytes of history to read a dozen markdown files is the kind of cost that
// makes people avoid the tool that imposes it.
func Fetch(root, name, repository, ref string) (Source, error) {
	return FetchContext(context.Background(), root, name, repository, ref)
}

// FetchContext is Fetch with a caller-supplied cancellation boundary.
func FetchContext(
	ctx context.Context, root, name, repository, ref string,
) (Source, error) {
	if err := checkArgument(repository); err != nil {
		return Source{}, err
	}
	if err := checkArgument(ref); err != nil {
		return Source{}, err
	}

	directory := Path(root, name)
	if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
		return Source{}, err
	}

	if _, err := os.Stat(filepath.Join(directory, ".git")); err == nil {
		if err := updateContext(ctx, directory, ref); err != nil {
			return Source{}, err
		}
	} else {
		if err := cloneContext(ctx, directory, repository, ref); err != nil {
			return Source{}, err
		}
	}

	commit, err := runContext(ctx, directory, "rev-parse", "HEAD")
	if err != nil {
		return Source{}, err
	}
	return Source{Name: name, Repository: repository, Ref: ref, Commit: commit}, nil
}

// SkillRoot returns the directory within a checkout that holds its skills.
func SkillRoot(root, name string) string {
	directory := Path(root, name)
	if info, err := os.Stat(filepath.Join(directory, SkillsSubdirectory)); err == nil && info.IsDir() {
		return filepath.Join(directory, SkillsSubdirectory)
	}
	return directory
}

func clone(directory, repository, ref string) error {
	return cloneContext(context.Background(), directory, repository, ref)
}

func cloneContext(
	ctx context.Context, directory, repository, ref string,
) error {
	arguments := []string{"clone", "--quiet", "--depth", "1"}
	if ref != "" {
		arguments = append(arguments, "--branch", cloneTarget(ref))
	}
	arguments = append(arguments, "--", repository, directory)

	command := commandContext(ctx, "git", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("cannot clone %s: %w", repository, ctx.Err())
		}
		return fmt.Errorf("cannot clone %s: %w: %s", repository, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// update discards local changes on purpose. A checkout under the skilltrust home is a cache
// of somebody else's repository, not a place to work; keeping edits there would mean the
// installed bytes came from a tree only this machine has ever seen.
func update(directory, ref string) error {
	return updateContext(context.Background(), directory, ref)
}

func updateContext(ctx context.Context, directory, ref string) error {
	target := ref
	if target == "" {
		target = "HEAD"
	}
	if _, err := runContext(ctx, directory, "fetch", "--quiet", "--depth", "1", "origin", target); err != nil {
		return err
	}
	if _, err := runContext(ctx, directory, "reset", "--quiet", "--hard", "FETCH_HEAD"); err != nil {
		return err
	}
	_, err := runContext(ctx, directory, "clean", "-qfd")
	return err
}

func run(directory string, arguments ...string) (string, error) {
	return runContext(context.Background(), directory, arguments...)
}

func runContext(ctx context.Context, directory string, arguments ...string) (string, error) {
	command := commandContext(ctx, "git", append([]string{"-C", directory}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return "", fmt.Errorf("git %s: %w", strings.Join(arguments, " "), ctx.Err())
		}
		return "", fmt.Errorf("git %s: %w: %s",
			strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func commandContext(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	if ctx == nil {
		return exec.Command(name, arguments...)
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.WaitDelay = commandWaitDelay
	return command
}

func cloneTarget(ref string) string {
	if branch, ok := strings.CutPrefix(ref, "refs/heads/"); ok && branch != "" {
		return branch
	}
	return ref
}

// checkArgument refuses a value that git would read as an option rather than as data. A URL
// beginning with a dash is not a URL, and passing it on would let the caller choose git's
// flags — including ones that run commands.
func checkArgument(value string) error {
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%q starts with a dash, which git would read as an option", value)
	}
	return nil
}
