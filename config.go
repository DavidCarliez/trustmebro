package main

import (
	"fmt"
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
	Name    string      `yaml:"name"`
	Command string      `yaml:"command"` // shim command name; empty or "*" = any
	Match   Match       `yaml:"match"`
	Action  string      `yaml:"action"`
	Output  string      `yaml:"output"` // fixed stdout for spoof
	Stderr  string      `yaml:"stderr"` // fixed stderr for spoof
	Exit    *int        `yaml:"exit"`   // fixed exit code for spoof
	Records map[string][]string `yaml:"records"` // answer values per RR type
	Rewrite []RewriteOp `yaml:"rewrite"` // ordered transforms on real output

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

// LoadConfig reads and validates the config. Missing file yields defaults.
// Errors are collected, not fatal, so a broken rule degrades to passthrough
// instead of breaking every shim.
func LoadConfig() (*Config, []string) {
	cfg := defaultConfig()
	var errs []string

	data, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		errs = append(errs, fmt.Sprintf("read config: %v", err))
		return cfg, errs
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		errs = append(errs, fmt.Sprintf("parse config: %v", err))
		return cfg, errs
	}

	cfg.DefaultAction = strings.ToLower(strings.TrimSpace(cfg.DefaultAction))
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "passthrough"
	}
	if cfg.DefaultAction != "passthrough" && cfg.DefaultAction != "reject" {
		errs = append(errs, fmt.Sprintf("default_action %q must be passthrough or reject", cfg.DefaultAction))
		cfg.DefaultAction = "passthrough"
	}
	if len(cfg.ShimCommands) == 0 {
		cfg.ShimCommands = defaultConfig().ShimCommands
	}

	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		if r.Match.DomainRe != "" {
			re, err := regexp.Compile(r.Match.DomainRe)
			if err != nil {
				errs = append(errs, fmt.Sprintf("rule %q: domain_re: %v", r.Name, err))
			} else {
				r.domainRe = re
			}
		}
		for _, g := range r.Match.Args {
			re, err := globRegexp(g)
			if err != nil {
				errs = append(errs, fmt.Sprintf("rule %q: args glob %q: %v", r.Name, g, err))
			} else {
				r.globRe = append(r.globRe, re)
			}
		}
		for _, op := range r.Rewrite {
			if op.Regex != "" {
				if _, err := regexp.Compile(op.Regex); err != nil {
					errs = append(errs, fmt.Sprintf("rule %q: rewrite regex %q: %v", r.Name, op.Regex, err))
				}
			}
		}
	}
	return cfg, errs
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
