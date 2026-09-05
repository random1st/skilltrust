package marketplace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/random1st/skilltrust/catalog"
)

func TestMaterializationRequiresAnExactDigestAndSafePathComponents(t *testing.T) {
	for _, invalid := range []string{"digest", "marketplace", "plugin", "version"} {
		t.Run(invalid, func(t *testing.T) {
			root := t.TempDir()
			destination := filepath.Join(root, "snapshot")
			source := filepath.Join(root, "plugin-source")
			if err := os.MkdirAll(source, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte("# Runbook\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			digest, _, err := DigestPlugin(source)
			if err != nil {
				t.Fatal(err)
			}
			name := "acme"
			plugin := catalog.Managed{Name: "runbook", Version: "1.0.0", Digest: digest}
			if err := MaterializeVerifiedMarketplace(filepath.Join(root, "valid-snapshot"), name, plugin, source); err != nil {
				t.Fatalf("valid materialization failed: %v", err)
			}
			switch invalid {
			case "digest":
				plugin.Digest = ""
			case "marketplace":
				name = "../escape"
			case "plugin":
				plugin.Name = "../escape"
			case "version":
				plugin.Version = "../escape"
			}
			if err := MaterializeVerifiedMarketplace(destination, name, plugin, source); err == nil {
				t.Fatal("unsafe materialization was accepted")
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatal("refused materialization wrote an install snapshot")
			}
		})
	}
}
