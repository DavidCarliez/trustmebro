package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type integrationHarness struct {
	binary  string
	shimDir string
	realDir string
	config  string
	home    string
}

func newIntegrationHarness(t *testing.T) *integrationHarness {
	t.Helper()
	root := t.TempDir()
	h := &integrationHarness{
		binary:  filepath.Join(root, "trustmebro"),
		shimDir: filepath.Join(root, "shims"),
		realDir: filepath.Join(root, "real"),
		config:  filepath.Join(root, "config.yaml"),
		home:    filepath.Join(root, "home"),
	}
	for _, dir := range []string{h.shimDir, h.realDir, h.home} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	build := exec.Command("go", "build", "-o", h.binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build integration binary: %v\n%s", err, output)
	}

	for _, name := range []string{"dig", "host", "nslookup"} {
		script := "#!/bin/sh\n" +
			"if [ \"$1\" = overflow.test ]; then dd if=/dev/zero bs=1048576 count=17 2>/dev/null; exit 0; fi\n" +
			"printf 'REAL " + name + ":%s\\n' \"$*\"\n" +
			"printf 'ERR " + name + ":%s\\n' \"$*\" >&2\n" +
			"if [ \"$1\" = rewrite.test ]; then exit 9; fi\n"
		if err := os.WriteFile(filepath.Join(h.realDir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(h.binary, filepath.Join(h.shimDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *integrationHarness) writeConfig(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(h.config, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *integrationHarness) env(extra map[string]string) []string {
	overrides := map[string]string{
		"HOME":                h.home,
		"PATH":                h.shimDir + string(os.PathListSeparator) + h.realDir + string(os.PathListSeparator) + "/usr/bin" + string(os.PathListSeparator) + "/bin",
		"TRUSTMEBRO_CONFIG":   h.config,
		"TRUSTMEBRO_DISABLE":  "",
		"TRUSTMEBRO_REAL_DIR": "",
	}
	for key, value := range extra {
		overrides[key] = value
	}

	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[key]; !replaced {
			env = append(env, item)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}

func runIntegrationCommand(t *testing.T, path string, args []string, env []string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(path, args...)
	cmd.Env = env
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err == nil {
		return out.String(), errOut.String(), 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return out.String(), errOut.String(), exit.ExitCode()
	}
	t.Fatalf("run %s: %v", path, err)
	return "", "", -1
}

func TestShimIntegration(t *testing.T) {
	h := newIntegrationHarness(t)
	validConfig := `default_action: passthrough
log_file: ""
rules:
  - name: spoof
    command: dig
    match: {domain: spoof.test, qtype: TXT}
    records:
      TXT: ['"integration-marker"']
  - name: rewrite
    command: dig
    action: rewrite
    match: {domain: rewrite.test}
    rewrite:
      - find: REAL
        replace: PATCHED
  - name: rewrite overflow
    command: dig
    action: rewrite
    match: {domain: overflow.test}
    rewrite:
      - find: REAL
        replace: PATCHED
`

	t.Run("spoof", func(t *testing.T) {
		h.writeConfig(t, validConfig)
		stdout, stderr, code := runIntegrationCommand(t, filepath.Join(h.shimDir, "dig"), []string{"spoof.test", "TXT", "+short"}, h.env(nil))
		if code != 0 || stdout != "\"integration-marker\"\n" || stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})

	t.Run("passthrough", func(t *testing.T) {
		h.writeConfig(t, validConfig)
		stdout, stderr, code := runIntegrationCommand(t, filepath.Join(h.shimDir, "dig"), []string{"pass.test", "A"}, h.env(nil))
		if code != 0 || !strings.Contains(stdout, "REAL dig:pass.test A") || !strings.Contains(stderr, "ERR dig:pass.test A") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})

	t.Run("rewrite preserves stderr and exit", func(t *testing.T) {
		h.writeConfig(t, validConfig)
		stdout, stderr, code := runIntegrationCommand(t, filepath.Join(h.shimDir, "dig"), []string{"rewrite.test", "A"}, h.env(nil))
		if code != 9 || !strings.Contains(stdout, "PATCHED dig:rewrite.test A") || !strings.Contains(stderr, "ERR dig:rewrite.test A") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})

	t.Run("rewrite rejects oversized output", func(t *testing.T) {
		h.writeConfig(t, validConfig)
		stdout, stderr, code := runIntegrationCommand(t, filepath.Join(h.shimDir, "dig"), []string{"overflow.test", "A"}, h.env(nil))
		if code != 1 || stdout != "" || !strings.Contains(stderr, "exceeded the 16 MiB per-stream limit") {
			t.Fatalf("code=%d stdout_bytes=%d stderr=%q", code, len(stdout), stderr)
		}
	})

	for _, name := range []string{"host", "nslookup"} {
		name := name
		t.Run(name+" no args passes through", func(t *testing.T) {
			h.writeConfig(t, validConfig)
			stdout, stderr, code := runIntegrationCommand(t, filepath.Join(h.shimDir, name), nil, h.env(nil))
			if code != 0 || !strings.Contains(stdout, "REAL "+name+":") || !strings.Contains(stderr, "ERR "+name+":") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}

	t.Run("malformed config fails closed", func(t *testing.T) {
		h.writeConfig(t, "default_action: reject\nrules: [\n")
		stdout, stderr, code := runIntegrationCommand(t, filepath.Join(h.shimDir, "dig"), []string{"pass.test"}, h.env(nil))
		if code != exitConfigError || stdout != "" || !strings.Contains(stderr, "invalid config; command not executed") || strings.Contains(stderr, "ERR dig") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})

	t.Run("unknown field fails closed", func(t *testing.T) {
		h.writeConfig(t, "defaut_action: reject\n")
		stdout, stderr, code := runIntegrationCommand(t, filepath.Join(h.shimDir, "dig"), []string{"pass.test"}, h.env(nil))
		if code != exitConfigError || stdout != "" || !strings.Contains(stderr, "field defaut_action not found") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})

	t.Run("disable bypasses invalid config", func(t *testing.T) {
		h.writeConfig(t, "rules: [\n")
		stdout, stderr, code := runIntegrationCommand(t, filepath.Join(h.shimDir, "dig"), []string{"pass.test"}, h.env(map[string]string{"TRUSTMEBRO_DISABLE": "1"}))
		if code != 0 || !strings.Contains(stdout, "REAL dig:pass.test") || !strings.Contains(stderr, "ERR dig:pass.test") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
}

func TestInstallRejectsShimPathTraversal(t *testing.T) {
	h := newIntegrationHarness(t)
	h.writeConfig(t, "shim_commands:\n  - ../../escaped\nlog_file: \"\"\n")
	installHome := filepath.Join(t.TempDir(), "install-home")
	if err := os.MkdirAll(installHome, 0o700); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runIntegrationCommand(t, h.binary, []string{"install", "--no-rc"}, h.env(map[string]string{"HOME": installHome}))
	if code == 0 || !strings.Contains(stderr, "invalid config; installation aborted") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, path := range []string{
		filepath.Join(installHome, ".local", "share", "escaped"),
		filepath.Join(installHome, ".local", "bin", "trustmebro"),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("unexpected install artifact %s (err=%v)", path, err)
		}
	}
}

func TestInstallRemovesStaleManagedShims(t *testing.T) {
	h := newIntegrationHarness(t)
	installHome := filepath.Join(t.TempDir(), "install-home")
	if err := os.MkdirAll(installHome, 0o700); err != nil {
		t.Fatal(err)
	}
	env := h.env(map[string]string{"HOME": installHome})

	h.writeConfig(t, "shim_commands: [dig, host]\nlog_file: \"\"\n")
	_, stderr, code := runIntegrationCommand(t, h.binary, []string{"install", "--no-rc"}, env)
	if code != 0 {
		t.Fatalf("first install: code=%d stderr=%q", code, stderr)
	}

	installedShimDir := filepath.Join(installHome, shimRel)
	unrelated := filepath.Join(installedShimDir, "unrelated")
	if err := os.Symlink("/bin/true", unrelated); err != nil {
		t.Fatal(err)
	}

	h.writeConfig(t, "shim_commands: [dig]\nlog_file: \"\"\n")
	stdout, stderr, code := runIntegrationCommand(t, h.binary, []string{"install", "--no-rc"}, env)
	if code != 0 {
		t.Fatalf("second install: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "removed stale shim:") {
		t.Fatalf("second install did not report stale shim removal: %q", stdout)
	}
	if _, err := os.Lstat(filepath.Join(installedShimDir, "host")); !os.IsNotExist(err) {
		t.Fatalf("stale host shim still exists (err=%v)", err)
	}
	for _, path := range []string{filepath.Join(installedShimDir, "dig"), unrelated} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("expected %s to remain: %v", path, err)
		}
	}
}

func TestLabInterceptsAbsoluteCommandPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("lab mode currently requires Linux")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("Bubblewrap is not installed")
	}
	probe := exec.Command(bwrap, "--die-with-parent", "--bind", "/", "/", "--", "/bin/true")
	if output, err := probe.CombinedOutput(); err != nil {
		t.Skipf("Bubblewrap namespaces are unavailable: %v (%s)", err, output)
	}

	h := newIntegrationHarness(t)
	h.writeConfig(t, `shim_commands: [dig]
log_file: ""
rules:
  - name: lab spoof
    command: dig
    match: {domain: spoof.test, qtype: TXT}
    records:
      TXT: ['"lab-marker"']
`)
	absoluteDig := filepath.Join(h.realDir, "dig")
	script := `printf 'lab=%s\n' "$TRUSTMEBRO_LAB"
printf 'resolved=%s\n' "$(command -v dig)"
printf device-check >/dev/null
"$1" spoof.test TXT +short
"$1" pass.test A
`
	stdout, stderr, code := runIntegrationCommand(t, h.binary, []string{"lab", "--", "/bin/sh", "-c", script, "sh", absoluteDig}, h.env(nil))
	if code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{
		"lab=1",
		"resolved=/tmp/trustmebro-lab-",
		"\"lab-marker\"",
		"REAL dig:pass.test A",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("lab stdout missing %q: %q", want, stdout)
		}
	}
	if !strings.Contains(stderr, "ERR dig:pass.test A") {
		t.Errorf("lab stderr did not preserve real command stderr: %q", stderr)
	}
	for _, line := range strings.Split(stdout, "\n") {
		resolved, ok := strings.CutPrefix(line, "resolved=")
		if !ok {
			continue
		}
		labRoot := filepath.Dir(filepath.Dir(resolved))
		if _, err := os.Stat(labRoot); !os.IsNotExist(err) {
			t.Errorf("temporary lab root was not removed: %s (err=%v)", labRoot, err)
		}
	}
}

func TestLabPlanShowsAbsoluteShadows(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("lab mode currently requires Linux")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("Bubblewrap is not installed")
	}

	h := newIntegrationHarness(t)
	h.writeConfig(t, "shim_commands: [dig]\nlog_file: \"\"\n")
	stdout, stderr, code := runIntegrationCommand(t, h.binary, []string{"lab", "--plan", "--", "/bin/true"}, h.env(nil))
	if code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{"interception namespace", "dig", filepath.Join(h.realDir, "dig"), "shadow " + filepath.Join(h.realDir, "dig")} {
		if !strings.Contains(stdout, want) {
			t.Errorf("plan missing %q: %q", want, stdout)
		}
	}
}
