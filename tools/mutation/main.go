// Command mutation runs a small, explicit set of behavioral fault injections in
// an isolated copy. A compiler error or timeout is an error, never a killed
// mutant. The manifest is reviewable, and a changed source anchor fails closed.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type mutant struct {
	ID      string `json:"id"`
	File    string `json:"file"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Package string `json:"package"`
	Run     string `json:"run"`
}
type configuration struct {
	Mutations []mutant `json:"mutations"`
}
type result struct {
	ID          string   `json:"id"`
	Status      string   `json:"status"`
	FailedTests []string `json:"failed_tests,omitempty"`
	Detail      string   `json:"detail,omitempty"`
}
type evidence struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Revision   string    `json:"revision"`
	SourceHash string    `json:"source_sha256"`
	Baseline   bool      `json:"baseline_passed"`
	Results    []result  `json:"results"`
}

func command(ctx context.Context, directory string, environment []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = directory
	cmd.Env = append(os.Environ(), environment...)
	return cmd.CombinedOutput()
}

func main() {
	configPath := flag.String("config", "mutation.json", "reviewed mutation manifest")
	outputPath := flag.String("output", "mutation-results.json", "write JSON evidence")
	flag.Parse()
	if err := run(*configPath, *outputPath); err != nil {
		fmt.Fprintln(os.Stderr, "mutation:", err)
		os.Exit(1)
	}
}

func run(configPath, outputPath string) error {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	root := filepath.Dir(abs)
	body, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	var config configuration
	if err := json.Unmarshal(body, &config); err != nil {
		return err
	}
	if len(config.Mutations) == 0 {
		return fmt.Errorf("the manifest has no mutations")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	revision, err := command(ctx, root, nil, "git", "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("read the repository revision: %w", err)
	}
	proof := evidence{StartedAt: time.Now().UTC(), Revision: strings.TrimSpace(string(revision)), Results: []result{}}
	write := func() error {
		proof.FinishedAt = time.Now().UTC()
		body, err := json.MarshalIndent(proof, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(outputPath, append(body, '\n'), 0o600)
	}
	directory, err := os.MkdirTemp("", "skilltrust-mutations-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	copyRoot := filepath.Join(directory, "repository")
	if err := copyRepository(ctx, root, copyRoot); err != nil {
		return err
	}
	proof.SourceHash, err = sourceHash(copyRoot)
	if err != nil {
		return err
	}
	environment, err := isolatedWorkspace(ctx, root, copyRoot, directory)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, mutation := range config.Mutations {
		if mutation.ID == "" || seen[mutation.ID] || !filepath.IsLocal(mutation.File) || mutation.Before == "" || mutation.Before == mutation.After || !strings.HasPrefix(mutation.Package, "./") || mutation.Run == "" {
			return fmt.Errorf("invalid or duplicate mutation %q", mutation.ID)
		}
		seen[mutation.ID] = true
		body, err := os.ReadFile(filepath.Join(copyRoot, mutation.File))
		if err != nil {
			return err
		}
		if strings.Count(string(body), mutation.Before) != 1 {
			return fmt.Errorf("%s: source anchor must match exactly once", mutation.ID)
		}
	}
	baselines := map[string]bool{}
	for _, mutation := range config.Mutations {
		group := mutation.Package + "\x00" + mutation.Run
		if baselines[group] {
			continue
		}
		baselines[group] = true
		out := test(copyRoot, environment, mutation)
		if out.Status != "survived" {
			proof.Results = append(proof.Results, result{ID: "baseline:" + mutation.ID, Status: "error", Detail: "baseline must pass: " + out.Detail, FailedTests: out.FailedTests})
			_ = write()
			return fmt.Errorf("baseline %s failed; no mutation result is valid", mutation.ID)
		}
		fmt.Println("baseline passed:", mutation.Package, mutation.Run)
	}
	proof.Baseline = true
	failed := false
	for _, mutation := range config.Mutations {
		path := filepath.Join(copyRoot, mutation.File)
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		changed := strings.Replace(string(body), mutation.Before, mutation.After, 1)
		if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
			return err
		}
		out := test(copyRoot, environment, mutation)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return err
		}
		proof.Results = append(proof.Results, out)
		fmt.Printf("%s: %s\n", out.ID, out.Status)
		if out.Status != "killed" {
			failed = true
		}
		if err := write(); err != nil {
			return err
		}
	}
	if failed {
		return fmt.Errorf("a mutation survived or could not be evaluated; see %s", outputPath)
	}
	fmt.Printf("all %d mutations killed by behavioral tests; evidence: %s\n", len(proof.Results), outputPath)
	return write()
}

func test(directory string, environment []string, mutation mutant) result {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	body, err := command(ctx, directory, environment, "go", "test", "-json", "-count=1", mutation.Package, "-run", mutation.Run)
	out := result{ID: mutation.ID}
	if ctx.Err() != nil {
		out.Status, out.Detail = "error", "test timed out"
		return out
	}
	started, failed := testEvents(body)
	if started == 0 {
		out.Status, out.Detail = "error", "no matching tests ran (including build failures): "+string(body)
		return out
	}
	if err == nil {
		out.Status = "survived"
		return out
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || len(failed) == 0 {
		out.Status, out.Detail = "error", "tests did not finish with a behavioral failure"
		return out
	}
	out.Status, out.FailedTests = "killed", failed
	return out
}

func testEvents(body []byte) (int, []string) {
	started := 0
	var failed []string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		var event struct{ Action, Test string }
		if json.Unmarshal(scanner.Bytes(), &event) != nil || event.Test == "" {
			continue
		}
		if event.Action == "run" {
			started++
		}
		if event.Action == "fail" {
			failed = append(failed, event.Test)
		}
	}
	return started, failed
}

func copyRepository(ctx context.Context, source, target string) error {
	paths, err := command(ctx, source, nil, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, path := range strings.Split(string(paths), "\x00") {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		if !filepath.IsLocal(path) {
			return fmt.Errorf("non-local repository path")
		}
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".env") || strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".pem") || base == "REVIEW.md" || base == "mutation-results.json" {
			continue
		}
		blocked := false
		for _, part := range strings.Split(filepath.ToSlash(path), "/") {
			if part == ".git" || part == ".codex" || part == ".diana" {
				blocked = true
			}
		}
		if blocked {
			continue
		}
		info, err := os.Lstat(filepath.Join(source, path))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			continue
		}
		out := filepath.Join(target, path)
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(filepath.Join(source, path))
			if err != nil {
				return err
			}
			if err := os.Symlink(link, out); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(filepath.Join(source, path), out, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	return errors.Join(copyErr, closeErr)
}

// Bind the result to the tested working tree, including uncommitted code and
// tests. The Git revision alone does not identify a development snapshot.
func sourceHash(root string) (string, error) {
	hash := sha256.New()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		var body []byte
		if entry.Type()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			body = []byte(link)
		} else {
			body, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		fmt.Fprintf(hash, "%s\x00%d\x00", filepath.ToSlash(relative), len(body))
		_, _ = hash.Write(body)
		return nil
	})
	return fmt.Sprintf("%x", hash.Sum(nil)), err
}

// Preserve other modules in an explicit development workspace, replacing only
// this repository with its isolated copy. With no workspace the released module
// dependencies in go.mod are used as usual.
func isolatedWorkspace(ctx context.Context, root, copyRoot, directory string) ([]string, error) {
	modules, err := command(ctx, root, nil, "go", "list", "-m", "-json")
	if err != nil {
		return nil, fmt.Errorf("read development modules: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(modules))
	// Go's workspace prefix matching distinguishes /var from /private/var on
	// macOS even though they address the same directory. Use physical paths for
	// every module so the temporary checkout is actually selected.
	realCopy, err := filepath.EvalSymlinks(copyRoot)
	if err != nil {
		return nil, err
	}
	paths := []string{realCopy}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	for {
		var module struct {
			Dir  string
			Main bool
		}
		if err := decoder.Decode(&module); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if !module.Main || module.Dir == "" {
			continue
		}
		real, err := filepath.EvalSymlinks(module.Dir)
		if err != nil {
			return nil, err
		}
		if real != realRoot {
			paths = append(paths, real)
		}
	}
	if len(paths) == 1 {
		return []string{"GOWORK=off"}, nil
	}
	version, err := command(ctx, root, nil, "go", "env", "GOVERSION")
	if err != nil {
		return nil, err
	}
	var body strings.Builder
	fmt.Fprintf(&body, "go %s\nuse (\n", strings.TrimPrefix(strings.TrimSpace(string(version)), "go"))
	for _, path := range paths {
		fmt.Fprintln(&body, strconv.Quote(path))
	}
	body.WriteString(")\n")
	work := filepath.Join(directory, "go.work")
	if err := os.WriteFile(work, []byte(body.String()), 0o600); err != nil {
		return nil, err
	}
	return []string{"GOWORK=" + work}, nil
}
