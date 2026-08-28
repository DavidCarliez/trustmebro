package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDig(t *testing.T) {
	tests := []struct {
		args   []string
		domain string
		qtype  string
		short  bool
		noall  bool
		xrev   string
	}{
		{[]string{"example.com"}, "example.com", "A", false, false, ""},
		{[]string{"example.com", "TXT"}, "example.com", "TXT", false, false, ""},
		{[]string{"TXT", "example.com"}, "example.com", "TXT", false, false, ""},
		{[]string{"@8.8.8.8", "-t", "MX", "example.com"}, "example.com", "MX", false, false, ""},
		{[]string{"example.com", "+short"}, "example.com", "A", true, false, ""},
		{[]string{"example.com", "TXT", "+noall", "+answer"}, "example.com", "TXT", false, true, ""},
		{[]string{"-x", "1.2.3.4"}, "4.3.2.1.in-addr.arpa", "PTR", false, false, "1.2.3.4"},
		{[]string{"-x1.2.3.4"}, "4.3.2.1.in-addr.arpa", "PTR", false, false, "1.2.3.4"},
		{[]string{"-q", "EXAMPLE.COM.", "TXT"}, "example.com", "TXT", false, false, ""},
		{[]string{"EXAMPLE.COM"}, "example.com", "A", false, false, ""},
		{[]string{"example.com", "AAAA", "+short"}, "example.com", "AAAA", true, false, ""},
		{[]string{"-4", "example.com"}, "example.com", "A", false, false, ""},
		{[]string{"-6", "-p", "5353", "example.com"}, "example.com", "A", false, false, ""},
		{[]string{"-b", "192.0.2.2", "-c", "IN", "example.com", "TXT"}, "example.com", "TXT", false, false, ""},
		{[]string{"-p5353", "example.com"}, "example.com", "A", false, false, ""},
	}
	for _, tt := range tests {
		q := parseDig(tt.args)
		if q == nil {
			t.Fatalf("parseDig(%v) = nil", tt.args)
		}
		if q.Domain != tt.domain || q.QType != tt.qtype || q.Short != tt.short || q.NoAll != tt.noall || q.XRev != tt.xrev {
			t.Errorf("parseDig(%v) = %+v, want domain=%s qtype=%s short=%v noall=%v xrev=%s", tt.args, q, tt.domain, tt.qtype, tt.short, tt.noall, tt.xrev)
		}
	}
}

func TestParseNslookup(t *testing.T) {
	q := parseNslookup([]string{"-type=TXT", "example.com"})
	if q == nil || q.Domain != "example.com" || q.QType != "TXT" {
		t.Fatalf("got %+v", q)
	}
	q = parseNslookup([]string{"example.com"})
	if q == nil || q.QType != "A" {
		t.Fatalf("got %+v", q)
	}
	q = parseNslookup([]string{"example.com", "8.8.8.8", "-q=MX"})
	if q == nil || q.Server != "8.8.8.8" || q.QType != "MX" {
		t.Fatalf("got %+v", q)
	}
	if parseNslookup([]string{"-"}) != nil {
		t.Fatal("interactive nslookup should be unparseable")
	}
	if parseNslookup(nil) != nil {
		t.Fatal("no-arg nslookup should be unparseable")
	}
}

func TestParseHost(t *testing.T) {
	q := parseHost([]string{"-t", "TXT", "example.com"})
	if q == nil || q.Domain != "example.com" || q.QType != "TXT" {
		t.Fatalf("got %+v", q)
	}
	q = parseHost([]string{"-a", "example.com"})
	if q == nil || q.QType != "ANY" {
		t.Fatalf("got %+v", q)
	}
	q = parseHost([]string{"example.com"})
	if q == nil || q.QType != "A" {
		t.Fatalf("got %+v", q)
	}
	q = parseHost([]string{"example.com", "8.8.8.8"})
	if q == nil || q.Domain != "example.com" || q.Server != "8.8.8.8" {
		t.Fatalf("got %+v", q)
	}
	q = parseHost([]string{"-c", "IN", "-p", "5353", "example.com", "8.8.8.8"})
	if q == nil || q.Domain != "example.com" || q.Server != "8.8.8.8" {
		t.Fatalf("got %+v", q)
	}
	if parseHost(nil) != nil {
		t.Fatal("no-arg host should be unparseable")
	}
}

func TestRuleMatch(t *testing.T) {
	// Rules go through LoadConfig so domain_re / args globs are compiled
	// exactly as they are in production.
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(cfgPath, []byte(`
rules:
  - name: r1
    command: dig
    match: { domain: "*.example.com", qtype: "txt" }
  - name: r2
    match: { domain_re: "\\.example\\.com$" }
  - name: r3
    match: { args: ["+sh*"] }
  - name: r4
    command: nslookup
  - name: r5
    match: { qtype: "MX" }
  - name: r6
    match: { domain: "other.*" }
`), 0o644)
	t.Setenv("TRUSTMEBRO_CONFIG", cfgPath)
	cfg, errs := LoadConfig()
	if len(errs) != 0 {
		t.Fatalf("config errors: %v", errs)
	}
	byName := map[string]*Rule{}
	for i := range cfg.Rules {
		byName[cfg.Rules[i].Name] = &cfg.Rules[i]
	}

	q := &Query{Command: "dig", Domain: "marker.example.com", QType: "TXT", RawArgs: []string{"marker.example.com", "TXT", "+short"}}
	for name, want := range map[string]bool{"r1": true, "r2": true, "r3": true, "r4": false, "r5": false, "r6": false} {
		if got := byName[name].matches(q); got != want {
			t.Errorf("rule %s matches = %v, want %v", name, got, want)
		}
	}
}

func TestGlobRegexp(t *testing.T) {
	re, err := globRegexp("*.trustmebro.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, ok := range []string{"a.trustmebro.test", "marker.trustmebro.test"} {
		if !re.MatchString(ok) {
			t.Errorf("%q should match", ok)
		}
	}
	for _, bad := range []string{"trustmebro.test", "a.trustmebro.test.net", "A.trustmebro.testX"} {
		if re.MatchString(bad) {
			t.Errorf("%q should not match", bad)
		}
	}
}

func TestDigGenShort(t *testing.T) {
	r := &Rule{Records: map[string][]string{"TXT": {`"trustmebro-marker-7f3a9"`}}}
	q := &Query{Command: "dig", Domain: "marker.test", QType: "TXT", Short: true}
	out := digGen(q, r)
	if strings.TrimSpace(out) != `"trustmebro-marker-7f3a9"` {
		t.Errorf("short TXT output = %q", out)
	}
}

func TestDigGenFull(t *testing.T) {
	r := &Rule{Records: map[string][]string{"TXT": {`"marker-123"`}}}
	q := &Query{Command: "dig", Domain: "marker.test", QType: "TXT"}
	out := digGen(q, r)
	for _, want := range []string{
		"; <<>> DiG ",
		"status: NOERROR",
		"ANSWER: 1",
		";marker.test.\t\t\tIN\tTXT",
		"marker.test.\t\t300\tIN\tTXT\t\"marker-123\"",
		"MSG SIZE  rcvd:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("full output missing %q:\n%s", want, out)
		}
	}
}

func TestDigGenNoAllAnswer(t *testing.T) {
	r := &Rule{Records: map[string][]string{"A": {"203.0.113.10"}}}
	q := &Query{Command: "dig", Domain: "marker.test", QType: "A", NoAll: true, Answer: true}
	out := digGen(q, r)
	if out != "marker.test.\t\t300\tIN\tA\t203.0.113.10\n" {
		t.Errorf("noall+answer output = %q", out)
	}
}

func TestDigGenNoAllWithoutAnswer(t *testing.T) {
	r := &Rule{Records: map[string][]string{"A": {"203.0.113.10"}}}
	q := &Query{Command: "dig", Domain: "marker.test", QType: "A", NoAll: true}
	if out := digGen(q, r); out != "" {
		t.Errorf("noall output = %q, want empty", out)
	}
}

func TestDigGenReverse(t *testing.T) {
	r := &Rule{Records: map[string][]string{"PTR": {"host.example.net."}}}
	q := &Query{Command: "dig", Domain: "4.3.2.1.in-addr.arpa", QType: "PTR", XRev: "1.2.3.4"}
	out := digGen(q, r)
	if !strings.Contains(out, "PTR\thost.example.net.") {
		t.Errorf("reverse output missing PTR record:\n%s", out)
	}
	if !strings.Contains(out, ";4.3.2.1.in-addr.arpa.\t\t\tIN\tPTR") {
		t.Errorf("reverse output missing question:\n%s", out)
	}
}

func TestNsGen(t *testing.T) {
	r := &Rule{Records: map[string][]string{"TXT": {`"marker"`}}}
	q := &Query{Command: "nslookup", Domain: "marker.test", QType: "TXT"}
	out := nsGen(q, r)
	for _, want := range []string{"Server:", "Non-authoritative answer:", "marker.test\ttext = \"marker\""} {
		if !strings.Contains(out, want) {
			t.Errorf("nslookup output missing %q:\n%s", want, out)
		}
	}
}

func TestHostGen(t *testing.T) {
	r := &Rule{Records: map[string][]string{"A": {"203.0.113.10"}}}
	q := &Query{Command: "host", Domain: "marker.test", QType: "A"}
	out := hostGen(q, r)
	if !strings.Contains(out, "marker.test has address 203.0.113.10") {
		t.Errorf("host output = %q", out)
	}
}

func TestApplyRewrites(t *testing.T) {
	ops := []RewriteOp{
		{Find: "status: NOERROR", Replace: "status: NOERROR\n;; [trustmebro] marker 1"},
		{Regex: `id: \d+`, Replace: "id: 99999"},
	}
	in := ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345\n"
	out := applyRewrites(ops, in)
	for _, want := range []string{"status: NOERROR\n;; [trustmebro] marker 1", "id: 99999"} {
		if !strings.Contains(out, want) {
			t.Errorf("rewrite output missing %q: %q", want, out)
		}
	}
}

func TestLimitedBuffer(t *testing.T) {
	b := newLimitedBuffer(5)
	for _, chunk := range []string{"abc", "def", "ghi"} {
		if n, err := b.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write(%q) = (%d, %v)", chunk, n, err)
		}
	}
	if got := b.String(); got != "abcde" {
		t.Fatalf("buffer = %q, want %q", got, "abcde")
	}
	if !b.exceeded {
		t.Fatal("buffer should report that its limit was exceeded")
	}
}

func TestEnvWithOverride(t *testing.T) {
	env := envWithOverride([]string{
		"PATH=/bin",
		"TRUSTMEBRO_DISABLE=0",
		"TRUSTMEBRO_DISABLE=old",
		"OTHER=value",
	}, "TRUSTMEBRO_DISABLE", "1")

	var values []string
	for _, item := range env {
		if strings.HasPrefix(item, "TRUSTMEBRO_DISABLE=") {
			values = append(values, item)
		}
	}
	if len(values) != 1 || values[0] != "TRUSTMEBRO_DISABLE=1" {
		t.Fatalf("override entries = %v, full environment = %v", values, env)
	}
}

func TestModeFor(t *testing.T) {
	cases := []struct {
		r    *Rule
		want string
	}{
		{&Rule{Action: "rewrite"}, "rewrite"},
		{&Rule{Output: "x"}, "spoof"},
		{&Rule{Records: map[string][]string{"A": {"1.1.1.1"}}}, "spoof"},
		{&Rule{Rewrite: []RewriteOp{{Find: "a", Replace: "b"}}}, "rewrite"},
		{&Rule{}, "passthrough"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := modeFor(c.r); got != c.want {
			t.Errorf("modeFor(%+v) = %q, want %q", c.r, got, c.want)
		}
	}
}

func TestResolveRealSkipsSelf(t *testing.T) {
	// A fake PATH whose first entry contains a symlink to a trustmebro-like
	// binary and whose second entry has the real one.
	dir := t.TempDir()
	shimDir := filepath.Join(dir, "shims")
	realDir := filepath.Join(dir, "real")
	os.MkdirAll(shimDir, 0o755)
	os.MkdirAll(realDir, 0o755)
	real := filepath.Join(realDir, "dig")
	os.WriteFile(real, []byte("#!/bin/sh\nexit 0\n"), 0o755)

	t.Setenv("TRUSTMEBRO_REAL_DIR", "")
	t.Setenv("PATH", shimDir+":"+realDir)

	// A decoy symlink that resolves to something named trustmebro.
	decoy := filepath.Join(dir, "trustmebro")
	os.WriteFile(decoy, []byte("x"), 0o755)
	os.Symlink(decoy, filepath.Join(shimDir, "dig"))

	got := resolveReal("dig")
	if got != real {
		t.Errorf("resolveReal = %q, want %q", got, real)
	}
}

func TestLabResolutionSkipsAnotherTrustmebroInstall(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	realDir := filepath.Join(root, "real")
	currentDir := filepath.Join(root, "current")
	for _, dir := range []string{shimDir, realDir, currentDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	installed := filepath.Join(root, "trustmebro")
	current := filepath.Join(currentDir, "trustmebro")
	real := filepath.Join(realDir, "dig")
	for _, path := range []string{installed, current, real} {
		if err := os.WriteFile(path, []byte("executable"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(installed, filepath.Join(shimDir, "dig")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)

	if got := firstRealPath("dig", current); got != real {
		t.Fatalf("firstRealPath = %q, want %q", got, real)
	}
	paths := labCommandPaths("dig", current)
	foundReal := false
	for _, path := range paths {
		if path == installed {
			t.Fatalf("labCommandPaths included another TrustMeBro install: %v", paths)
		}
		if path == real {
			foundReal = true
		}
	}
	if !foundReal {
		t.Fatalf("labCommandPaths = %v, missing %s", paths, real)
	}
}

func TestReverseDomain(t *testing.T) {
	if got := reverseDomain("1.2.3.4"); got != "4.3.2.1.in-addr.arpa" {
		t.Errorf("v4 = %q", got)
	}
	if got := reverseDomain("2001:db8::1"); !strings.HasSuffix(got, ".ip6.arpa") || strings.Contains(got, "::") {
		t.Errorf("v6 = %q", got)
	}
}

func TestMatchRuleNil(t *testing.T) {
	if got := matchRule(defaultConfig(), nil); got != nil {
		t.Fatalf("matchRule(nil) = %+v, want nil", got)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("defaut_action: reject\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRUSTMEBRO_CONFIG", path)

	_, errs := LoadConfig()
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, "\n"), "field defaut_action not found") {
		t.Fatalf("LoadConfig errors = %v, want unknown-field error", errs)
	}
}

func TestLoadConfigValidatesRulesAndShims(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	config := `shim_commands:
  - ../dig
rules:
  - name: broken
    command: dig
    action: rewite
    exit: 999
    rewrite:
      - find: one
        regex: two
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRUSTMEBRO_CONFIG", path)

	_, errs := LoadConfig()
	joined := strings.Join(errs, "\n")
	for _, want := range []string{
		"must be a plain executable name",
		"action \"rewite\"",
		"exit must be between 0 and 255",
		"must set exactly one of find or regex",
		"cannot be combined",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("LoadConfig errors missing %q:\n%s", want, joined)
		}
	}
}

func TestAppendLogPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "log.jsonl")
	code := 0
	appendLog(path, entry{Cmd: "dig", Mode: "spoof", Exit: &code})

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("log directory mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("log file mode = %o, want 600", got)
	}
}
