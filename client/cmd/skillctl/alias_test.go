package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Exercise main, including its actual exit codes, without discovering the host's
// skills or changing the argument vector of other tests in this process.
func TestCLIAliasSubprocess(t *testing.T) {
	if os.Getenv("AXELA_ALIAS_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = os.Args[i+1:]
			doctorRootCandidates = func() []string { return []string{os.Getenv("AXELA_ALIAS_TEST_ROOT")} }
			main()
			t.Fatal("main returned without an exit code")
		}
	}
	t.Fatal("missing child arguments")
}

func runAliasCommand(t *testing.T, name string, args ...string) (string, int) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	command := exec.Command(self, append([]string{"-test.run=^TestCLIAliasSubprocess$", "--", filepath.Join(root, name)}, args...)...)
	command.Env = append(os.Environ(), "AXELA_ALIAS_TEST_PROCESS=1", "AXELA_ALIAS_TEST_ROOT="+filepath.Join(root, "skills"), "SKILLTRUST_HOME="+filepath.Join(root, "state"))
	output, err := command.CombinedOutput()
	code := 0
	if err != nil {
		if failure, ok := err.(*exec.ExitError); ok {
			code = failure.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "state")); !os.IsNotExist(err) {
		t.Fatalf("read-only alias command created state: %v", err)
	}
	return string(output), code
}

func TestCLIAliasUsesInvokedNameAndPreservesLegacy(t *testing.T) {
	for _, name := range []string{"axela", "axela.exe", "skillctl", "skillctl.exe", "custom-tool"} {
		t.Run(name, func(t *testing.T) {
			want := "skillctl"
			if strings.HasPrefix(name, "axela") {
				want = "axela"
			}
			output, code := runAliasCommand(t, name, "version")
			if code != exitClean || !strings.HasPrefix(output, want+" ") {
				t.Fatalf("version: exit %d, %q", code, output)
			}
			for _, args := range [][]string{{"--help"}, {"doctor", "--help"}, nil, {"unknown"}} {
				output, code = runAliasCommand(t, name, args...)
				wantCode := exitClean
				if len(args) == 0 || args[0] == "unknown" {
					wantCode = exitUsage
				}
				if code != wantCode || !strings.Contains(output, want+" doctor") {
					t.Fatalf("%v: exit %d, %q", args, code, output)
				}
				if want == "axela" && strings.Contains(output, "skillctl") {
					t.Fatalf("Axela help changed the command name: %q", output)
				}
			}
		})
	}
}

func TestCLIAliasDoctorKeepsFindingsAndAnExecutableNextCommand(t *testing.T) {
	for _, name := range []string{"axela", "skillctl"} {
		t.Run(name, func(t *testing.T) {
			output, code := runAliasCommand(t, name, "doctor", "--json")
			var result machineStatus
			if err := json.Unmarshal([]byte(output), &result); err != nil {
				t.Fatalf("doctor JSON: %v\n%s", err, output)
			}
			if code != exitFindings || result.Status != "needs_attention" || result.Inventory == nil || result.Inventory.Found != 0 || result.ReportAccepted || result.LastCheck != nil {
				t.Fatalf("alias invented a successful check: exit %d, %+v", code, result)
			}
			if !reflect.DeepEqual(result.NextCommand, []string{name, "subscribe", "--help"}) {
				t.Fatalf("next command: %v", result.NextCommand)
			}
			output, code = runAliasCommand(t, name, "doctor")
			if code != exitFindings || !strings.Contains(output, "Run: "+name+" subscribe --help") {
				t.Fatalf("terminal next command: exit %d, %q", code, output)
			}
		})
	}
}

func TestPluginDoctorUsesExecutableOutsidePATH(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output, code := runAliasCommand(t, "axela", "doctor", "--json", "--absolute-commands")
	var result machineStatus
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("doctor JSON: %v\n%s", err, output)
	}
	if code != exitFindings || !reflect.DeepEqual(result.NextCommand, []string{self, "subscribe", "--help"}) {
		t.Fatalf("plugin next command requires an unrelated PATH installation: exit %d, %+v", code, result.NextCommand)
	}
	output, code = runAliasCommand(t, "axela", "doctor", "--absolute-commands")
	if code != exitFindings || !strings.Contains(output, "Run: "+nextCommandText([]string{self, "subscribe", "--help"})) {
		t.Fatalf("plugin terminal command: exit %d, %q", code, output)
	}
}
