package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the trustmebro configuration file (YAML).
type Config struct {
	// DefaultAction is what a shim does when no rule matches:
	// "passthrough" (run the real command) or "reject" (refuse).
	DefaultAction string `yaml:"default_action"`
	// ShimCommands is the set of command names that get shims on install.
	ShimCommands []string `yaml:"shim_commands"`
	// LogFile is the JSONL audit log of intercepted calls; empty disables.
	LogFile string `yaml:"log_file"`
	// Rules are evaluated in order; the first match wins.
	Rules []Rule `yaml:"rules"`
}

// Rule describes one interception. All matchers in Match are ANDed.
// Action is one of "spoof", "rewrite", "passthrough", "reject"; when empty
// it is derived: output/records -> spoof, rewrite -> rewrite, else passthrough.
type Rule struct {
	Name    string              `yaml:"name"`
	Command string              `yaml:"command"` // shim command name; empty or "*" = any
	Match   Match               `yaml:"match"`
	Action  string              `yaml:"action"`
	Output  string              `yaml:"output"`  // fixed stdout for spoof
	Stderr  string              `yaml:"stderr"`  // fixed stderr for spoof
	Exit    *int                `yaml:"exit"`    // fixed exit code for spoof
	Records map[string][]string `yaml:"records"` // answer values per RR type
	Rewrite []RewriteOp         `yaml:"rewrite"` // ordered transforms on real output

	domainRe *regexp.Regexp
	globRe   []*regexp.Regexp
}

// Match is the ANDed set of rule conditions.
type Match struct {
	Domain   string   `yaml:"domain"`    // glob on the parsed domain, case-insensitive
	DomainRe string   `yaml:"domain_re"` // regexp on the parsed domain
	QType    string   `yaml:"qtype"`     // RR type (TXT, A, ...), case-insensitive
	Args     []string `yaml:"args"`      // any raw argv token matching any glob
}

// RewriteOp is one output transform: Find (literal) or Regex (RE2) + Replace.
type RewriteOp struct {
	Find    string `yaml:"find"`
	Regex   string `yaml:"regex"`
	Replace string `yaml:"replace"`

	compiled *regexp.Regexp
}

// configPath returns the config file location (TRUSTMEBRO_CONFIG or XDG default).
func configPath() string {
	if p := os.Getenv("TRUSTMEBRO_CONFIG"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "trustmebro", "config.yaml")
	}
	return "trustmebro.yaml"
}

func defaultConfig() *Config {
	return &Config{
		DefaultAction: "passthrough",
		ShimCommands:  []string{"dig", "nslookup", "host"},
		LogFile:       "~/.local/state/trustmebro/log.jsonl",
	}
}

// LoadConfig reads and validates the config. A missing file yields defaults.
// An existing but invalid file returns errors; shims fail closed on them.
func LoadConfig() (*Config, []string) {
	cfg := defaultConfig()
	var errs []string

	data, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, []string{fmt.Sprintf("read config: %v", err)}
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return cfg, []string{fmt.Sprintf("parse config: %v", err)}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			errs = append(errs, "parse config: multiple YAML documents are not supported")
		} else {
			errs = append(errs, fmt.Sprintf("parse config: %v", err))
		}
	}

	cfg.DefaultAction = strings.ToLower(strings.TrimSpace(cfg.DefaultAction))
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "passthrough"
	}
	if cfg.DefaultAction != "passthrough" && cfg.DefaultAction != "reject" {
		errs = append(errs, fmt.Sprintf("default_action %q must be passthrough or reject", cfg.DefaultAction))
	}
	if len(cfg.ShimCommands) == 0 {
		cfg.ShimCommands = append([]string(nil), defaultConfig().ShimCommands...)
	}

	seenCommands := make(map[string]struct{}, len(cfg.ShimCommands))
	for i, command := range cfg.ShimCommands {
		command = strings.TrimSpace(command)
		cfg.ShimCommands[i] = command
		if !validCommandName(command) {
			errs = append(errs, fmt.Sprintf("shim_commands[%d] %q must be a plain executable name", i, command))
			continue
		}
		if _, exists := seenCommands[command]; exists {
			errs = append(errs, fmt.Sprintf("shim command %q is duplicated", command))
			continue
		}
		seenCommands[command] = struct{}{}
	}

	seenRules := make(map[string]struct{}, len(cfg.Rules))
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		r.Command = strings.TrimSpace(r.Command)
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		r.Match.QType = strings.ToUpper(strings.TrimSpace(r.Match.QType))

		label := fmt.Sprintf("rule[%d]", i)
		if r.Name == "" {
			errs = append(errs, fmt.Sprintf("%s: name is required", label))
		} else {
			label = fmt.Sprintf("rule %q", r.Name)
			if _, exists := seenRules[r.Name]; exists {
				errs = append(errs, fmt.Sprintf("%s: name is duplicated", label))
			}
			seenRules[r.Name] = struct{}{}
		}
		if r.Command != "" && r.Command != "*" && !validCommandName(r.Command) {
			errs = append(errs, fmt.Sprintf("%s: command %q must be a plain executable name or *", label, r.Command))
		}
		if r.Action != "" && !validRuleAction(r.Action) {
			errs = append(errs, fmt.Sprintf("%s: action %q must be spoof, rewrite, passthrough, or reject", label, r.Action))
		}
		if r.Exit != nil && (*r.Exit < 0 || *r.Exit > 255) {
			errs = append(errs, fmt.Sprintf("%s: exit must be between 0 and 255", label))
		}
		if r.Match.QType != "" && normType(r.Match.QType) == "" {
			errs = append(errs, fmt.Sprintf("%s: qtype %q is not supported", label, r.Match.QType))
		}
		if r.Match.DomainRe != "" {
			re, err := regexp.Compile(r.Match.DomainRe)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: domain_re: %v", label, err))
			} else {
				r.domainRe = re
			}
		}
		for _, glob := range r.Match.Args {
			if strings.TrimSpace(glob) == "" {
				errs = append(errs, fmt.Sprintf("%s: args globs cannot be empty", label))
				continue
			}
			re, err := globRegexp(glob)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: args glob %q: %v", label, glob, err))
			} else {
				r.globRe = append(r.globRe, re)
			}
		}

		normalizedRecords := make(map[string][]string, len(r.Records))
		for recordType, values := range r.Records {
			normalized := normType(recordType)
			if normalized == "" {
				errs = append(errs, fmt.Sprintf("%s: record type %q is not supported", label, recordType))
				continue
			}
			if _, exists := normalizedRecords[normalized]; exists {
				errs = append(errs, fmt.Sprintf("%s: record type %q is duplicated after normalization", label, recordType))
				continue
			}
			normalizedRecords[normalized] = values
		}
		r.Records = normalizedRecords

		for j := range r.Rewrite {
			op := &r.Rewrite[j]
			if (op.Find == "") == (op.Regex == "") {
				errs = append(errs, fmt.Sprintf("%s: rewrite[%d] must set exactly one of find or regex", label, j))
				continue
			}
			if op.Regex != "" {
				re, err := regexp.Compile(op.Regex)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s: rewrite[%d] regex: %v", label, j, err))
				} else {
					op.compiled = re
				}
			}
		}

		hasSpoofFields := r.Output != "" || r.Stderr != "" || r.Exit != nil || len(r.Records) > 0
		if len(r.Rewrite) > 0 && hasSpoofFields {
			errs = append(errs, fmt.Sprintf("%s: rewrite operations cannot be combined with output, stderr, exit, or records", label))
		}
		if r.Action == "rewrite" && len(r.Rewrite) == 0 {
			errs = append(errs, fmt.Sprintf("%s: rewrite action requires at least one rewrite operation", label))
		}
		if r.Action != "" && r.Action != "rewrite" && len(r.Rewrite) > 0 {
			errs = append(errs, fmt.Sprintf("%s: rewrite operations require action rewrite or an empty action", label))
		}
	}
	return cfg, errs
}

var commandNamePattern = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)

func validCommandName(name string) bool {
	return name != "" &&
		name != "." &&
		name != ".." &&
		filepath.Base(name) == name &&
		!strings.ContainsAny(name, `/\\`) &&
		commandNamePattern.MatchString(name)
}

func validRuleAction(action string) bool {
	switch action {
	case "spoof", "rewrite", "passthrough", "reject":
		return true
	default:
		return false
	}
}

// globRegexp compiles a case-insensitive glob (* and ?) to an anchored regexp.
func globRegexp(g string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range g {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
