package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func venvFixture(t *testing.T, root, name string, populated bool) string {
	t.Helper()
	prefix := filepath.Join(root, name)
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "pyvenv.cfg"), []byte("home = /base/python\ninclude-system-site-packages = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if populated {
		metadata := filepath.Join(prefix, "lib/python3.13/site-packages/demo-1.dist-info")
		if err := os.MkdirAll(metadata, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(metadata, "METADATA"), []byte("Metadata-Version: 2.1\nName: demo\nVersion: 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return prefix
}

func TestFindVirtualenvKinds(t *testing.T) {
	root := t.TempDir()
	venvFixture(t, root, "arbitrary-name", false)
	for _, format := range []string{"json", "text"} {
		cmd := New()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"find", "--format", format, root})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if format == "json" {
			var report struct {
				Environments []struct {
					Kind     string `json:"kind"`
					Revision *int   `json:"revision"`
				} `json:"environments"`
			}
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Environments) != 1 || report.Environments[0].Kind != "venv" || report.Environments[0].Revision != nil {
				t.Fatalf("marker-backed virtualenv must have a kind but no conda revision: %s", out.String())
			}
		} else if !strings.Contains(out.String(), "TYPE") || !strings.Contains(out.String(), "venv") || !strings.Contains(out.String(), "arbitrary-name") || strings.Contains(out.String(), "?") {
			t.Fatalf("text output must distinguish a virtualenv without an unknown conda revision: %s", out.String())
		}
	}
}

func TestScanVirtualenvAndEmptyVirtualenv(t *testing.T) {
	root := t.TempDir()
	venvFixture(t, root, "installed", true)
	venvFixture(t, root, "empty", false)
	for _, format := range []string{"json", "text"} {
		cmd := New()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"scan", "--format", format, "--output-dir", t.TempDir(), root})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("empty and installed virtualenvs should scan successfully: %v\n%s", err, out.String())
		}
		if format == "text" {
			if !strings.Contains(out.String(), "2 environments found, 2 SBOMs written") || !strings.Contains(out.String(), "installed  (venv)") || strings.Contains(out.String(), "revision ?") {
				t.Fatalf("virtualenv scan must not claim conda state: %s", out.String())
			}
			continue
		}
		var report struct {
			Status       string `json:"status"`
			Observations []struct {
				Environment struct {
					Kind string `json:"kind"`
				} `json:"environment"`
				Result struct {
					Path   string `json:"path"`
					Conda  int    `json:"conda"`
					Python int    `json:"python_installed"`
				} `json:"result"`
			} `json:"observations"`
		}
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Status != "complete" || len(report.Observations) != 2 {
			t.Fatalf("expected two valid SBOM observations: %s", out.String())
		}
		python := 0
		for _, observation := range report.Observations {
			if observation.Environment.Kind != "venv" || observation.Result.Conda != 0 {
				t.Fatalf("wrong virtualenv scan identity: %s", out.String())
			}
			python += observation.Result.Python
			data, err := os.ReadFile(observation.Result.Path)
			var bom struct {
				Format string `json:"bomFormat"`
			}
			if err != nil || json.Unmarshal(data, &bom) != nil || bom.Format != "CycloneDX" {
				t.Fatalf("expected a CycloneDX SBOM at %s: %v", observation.Result.Path, err)
			}
		}
		if python != 1 {
			t.Fatalf("installed package metadata must be cataloged, while an empty venv stays valid: %s", out.String())
		}
	}
}

func TestMixedEnvironmentLintKeepsCondaFindings(t *testing.T) {
	root := t.TempDir()
	venvFixture(t, root, ".venv", true)
	meta := filepath.Join(root, "conda", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "certifi.json"), []byte(canonicalPrefixRecord("certifi", "2026.7.22", "0")), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := New()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"lint", "--rule", "ENV013", "--format", "json", root})
	err := cmd.Execute()
	if ExitCode(err) != 1 {
		t.Fatalf("mixed virtualenv lint must keep the conda warning without an unsupported issue: %v\n%s", err, out.String())
	}
	var report struct {
		Status   string `json:"status"`
		Findings []struct {
			Rule string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "completed" || len(report.Findings) != 1 || report.Findings[0].Rule != "ENV013" {
		t.Fatalf("virtualenv must not erase supported conda evidence: %s", out.String())
	}
}

func TestLintENV013VirtualenvCertifi(t *testing.T) {
	for _, layout := range []string{"lib/python3.13/site-packages", "Lib/site-packages"} {
		for _, test := range []struct {
			version string
			code    int
		}{
			{"2026.7.22", 1},
			{"2026.10.18rc1", 1},
			{"2026.10.18", 0},
			{"2026.10.18.post1", 0},
		} {
			t.Run(layout+"/"+test.version, func(t *testing.T) {
				root := t.TempDir()
				prefix := venvFixture(t, root, ".venv", false)
				metadata := filepath.Join(prefix, layout, "certifi-"+test.version+".dist-info", "METADATA")
				if err := os.MkdirAll(filepath.Dir(metadata), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(metadata, []byte("Metadata-Version: 2.1\nName: certifi\nVersion: "+test.version+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				output, err := executeLint(t, "--rule", "ENV013", "--format", "json", root)
				if ExitCode(err) != test.code {
					t.Fatalf("virtualenv certifi check: %v\n%s", err, output)
				}
				var report struct {
					Status   string `json:"status"`
					Findings []struct {
						Next     string `json:"next"`
						Evidence struct {
							Paths []string `json:"paths"`
						} `json:"evidence"`
					} `json:"findings"`
				}
				if err := json.Unmarshal([]byte(output), &report); err != nil {
					t.Fatal(err)
				}
				if report.Status != "completed" || len(report.Findings) != test.code {
					t.Fatalf("unexpected virtualenv certificate report: %s", output)
				}
				for _, finding := range report.Findings {
					if len(finding.Evidence.Paths) != 1 || finding.Evidence.Paths[0] != metadata || !strings.Contains(finding.Next, "pip") || !strings.Contains(finding.Next, "certifi>=2026.10.18") || strings.Contains(finding.Next, "conda install") {
						t.Fatalf("virtualenv needs its own metadata path and remediation: %s", output)
					}
				}
			})
		}
	}
}

func TestLintENV013VirtualenvWithoutCertifi(t *testing.T) {
	prefix := venvFixture(t, t.TempDir(), ".venv", true)
	findings, status := lintENV013JSON(t, prefix)
	if len(findings) != 0 || status != "not_applicable" {
		t.Fatalf("virtualenv without local certifi is not applicable: %s %+v", status, findings)
	}
}

func TestLintVirtualenvUnsupportedRulesRemainExplicit(t *testing.T) {
	root := t.TempDir()
	prefix := venvFixture(t, root, ".venv", true)
	cmd := New()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"lint", "--format", "json", prefix})
	err := cmd.Execute()
	if ExitCode(err) != 2 || !strings.Contains(out.String(), "virtualenv lint is not supported") || strings.Contains(out.String(), "no valid conda package metadata") {
		t.Fatalf("unsupported virtualenv rules must be explicit rather than a false pass or conda error: %v\n%s", err, out.String())
	}
	var report struct {
		Status   string            `json:"status"`
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "incomplete" || len(report.Findings) != 0 {
		t.Fatalf("virtualenv must not receive conda-specific findings: %s", out.String())
	}
}
