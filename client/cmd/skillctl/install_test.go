package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/random1st/skilltrust/internal/marketplace"
)

func TestDoctorInstallCommandChecksTheNativeResultWithoutAnAccount(t *testing.T) {
	for _, nativeInstalls := range []bool{true, false} {
		t.Run(map[bool]string{true: "installed", false: "native_exit_zero_without_install"}[nativeInstalls], func(t *testing.T) {
			_, client := localStatusFixture(t)
			installed := marketplace.InstalledPath(client, "acme", "deploy-runbook", "1.0.0")
			if err := os.Rename(installed, filepath.Join(t.TempDir(), "uninstalled")); err != nil {
				t.Fatal(err)
			}
			before, code := doctorResult(t, runDoctor, "--json")
			want := []string{commandName(), "install", "--client", "claude"}
			if code != exitFindings || !reflect.DeepEqual(before.NextCommand, want) {
				t.Fatalf("doctor did not offer an executable installation: %+v (exit %d)", before, code)
			}
			var frozen string
			stubNativeInstall(t,
				func(name string) (string, error) { return "/usr/bin/" + name, nil },
				func(_ context.Context, name string, args ...string) ([]byte, error) {
					switch strings.Join(args[:3], " ") {
					case "plugin marketplace add":
						frozen = args[len(args)-1]
					case "plugin marketplace list":
						return nativeMarketplaceList(t, "acme", frozen), nil
					case "plugin install --scope":
						if nativeInstalls {
							copyTree(t, installed, filepath.Join(frozen, "plugins", "deploy-runbook"))
						}
					default:
						t.Fatalf("unexpected native call: %s %v", name, args)
					}
					return nil, nil
				})
			capture(t, func() { code = runInstall(before.NextCommand[2:]) })
			if nativeInstalls && code != exitClean || !nativeInstalls && code != exitFindings {
				t.Fatalf("native installation %t returned an unjustified verdict: %d", nativeInstalls, code)
			}
			after, _ := doctorResult(t, runDoctor, "--json")
			if nativeInstalls && (after.LastCheck == nil || after.LastCheck.Checked != 1 || after.Status != "local_checked") {
				t.Fatalf("installed bytes were not verified: %+v", after)
			}
			if after.ReportAccepted || after.ServiceURL != "" {
				t.Fatalf("local install invented a cloud connection: %+v", after)
			}
			if _, err := os.Stat(connectStatePath()); !os.IsNotExist(err) {
				t.Fatalf("local install created team credentials: %v", err)
			}
		})
	}
}

func TestInstallAgainPreservesAnExistingIntentionalEdit(t *testing.T) {
	_, client := localStatusFixture(t)
	if code := tamperDemoPlugin(client); code != exitClean {
		t.Fatal(code)
	}
	path := filepath.Join(marketplace.InstalledPath(client, "acme", "deploy-runbook", "1.0.0"), "SKILL.md")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stubNativeInstall(t,
		func(name string) (string, error) { t.Fatal("existing edit triggered native lookup"); return "", nil },
		func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("existing edit triggered native installation")
			return nil, nil
		})
	var code int
	capture(t, func() { code = runInstall(nil) })
	if code != exitFindings {
		t.Fatalf("changed bytes looked verified: %d", code)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("re-running install replaced an intentional edit")
	}
	out, _ := doctorResult(t, runDoctor, "--json")
	if !reflect.DeepEqual(out.NextCommand, []string{commandName(), "sync", "--report-only"}) {
		t.Fatalf("changed bytes have no read-only next command: %+v", out)
	}
}

func TestDoctorPublisherActionNeverRunsPublishingOnTheConsumer(t *testing.T) {
	out := statusWithNextCommand(machineStatus{NextAction: &nextAction{Code: "renew_catalog", Actor: "publisher"}})
	if !reflect.DeepEqual(out.NextCommand, []string{commandName(), "doctor"}) {
		t.Fatalf("consumer was asked to sign a publisher's renewal: %v", out.NextCommand)
	}
}
