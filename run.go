package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// shimMain is the entry point when trustmebro is invoked under a shim name.
// It resolves the rule, applies it, and exits with the appropriate code.
func shimMain(name string, args []string) int {
	cfg, errs := LoadConfig()
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "trustmebro: config errors (passing through):\n")
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
	}

	if os.Getenv("TRUSTMEBRO_DISABLE") == "1" {
		return execReal(name, args, cfg, "")
	}

	q := ParseQuery(name, args)
	rule := matchRule(cfg, q)
	mode := ""
	if rule != nil {
		mode = modeFor(rule)
	} else if cfg.DefaultAction == "reject" {
		mode = "reject"
	} else {
		mode = "passthrough"
	}

	switch mode {
	case "spoof":
		if q != nil && q.Domain == "" && rule != nil && rule.Output == "" {
			// Cannot generate a meaningful answer without a domain;
			// degrade to passthrough rather than emit garbage.
			return execReal(name, args, cfg, rule.Name)
		}
		stdout, stderr, code := generate(q, rule)
		os.Stdout.WriteString(stdout)
		os.Stderr.WriteString(stderr)
		appendLog(logPath(cfg), entry{PID: os.Getpid(), Cmd: name, Argv: args, Domain: queryDomain(q), QType: queryType(q), Rule: ruleName(rule), Mode: "spoof", Exit: &code})
		return code

	case "rewrite":
		return rewriteRun(name, args, cfg, rule)

	case "reject":
		msg := "trustmebro: blocked by rule"
		if rule != nil && rule.Name != "" {
			msg += " " + rule.Name
		}
		fmt.Fprintln(os.Stderr, msg)
		code := 1
		appendLog(logPath(cfg), entry{PID: os.Getpid(), Cmd: name, Argv: args, Domain: queryDomain(q), QType: queryType(q), Rule: ruleName(rule), Mode: "reject", Exit: &code})
		return code

	default: // passthrough
		return execReal(name, args, cfg, ruleName(rule))
	}
}

// execReal replaces the shim with the real binary (perfect fidelity: same
// PID, signals, exit code) or falls back to a child process on exec failure.
func execReal(name string, args []string, cfg *Config, rule string) int {
	real := resolveReal(name)
	if real == "" {
		fmt.Fprintf(os.Stderr, "trustmebro: %s: command not found\n", name)
		return 127
	}
	appendLog(logPath(cfg), entry{PID: os.Getpid(), Cmd: name, Argv: args, Rule: rule, Mode: "passthrough", Real: real})

	env := append(os.Environ(), "TRUSTMEBRO_DISABLE=1")
	if err := syscall.Exec(real, append([]string{real}, args...), env); err == nil {
		return 0 // unreachable on success
	}

	cmd := exec.Command(real, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return exitCode(err)
	}
	return 0
}

// rewriteRun runs the real binary, applies rewrite transforms to its stdout,
// and prints the result.
func rewriteRun(name string, args []string, cfg *Config, rule *Rule) int {
	real := resolveReal(name)
	if real == "" {
		fmt.Fprintf(os.Stderr, "trustmebro: %s: command not found\n", name)
		return 127
	}
	cmd := exec.Command(real, args...)
	cmd.Env = append(os.Environ(), "TRUSTMEBRO_DISABLE=1")
	cmd.Stdin = os.Stdin
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	transformed := applyRewrites(rule.Rewrite, out.String())
	os.Stdout.WriteString(transformed)
	os.Stderr.WriteString(errb.String())

	code := exitCode(err)
	appendLog(logPath(cfg), entry{PID: os.Getpid(), Cmd: name, Argv: args, Domain: queryDomain(ParseQuery(name, args)), QType: queryType(ParseQuery(name, args)), Rule: rule.Name, Mode: "rewrite", Real: real, Exit: &code})
	return code
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 1
}

func queryDomain(q *Query) string {
	if q == nil {
		return ""
	}
	return q.Domain
}

func queryType(q *Query) string {
	if q == nil {
		return ""
	}
	return q.QType
}

func ruleName(r *Rule) string {
	if r == nil {
		return ""
	}
	return r.Name
}

// resolveReal locates the real binary for a shimmed command, skipping every
// candidate that is (or points to) trustmebro itself.
func resolveReal(name string) string {
	if d := os.Getenv("TRUSTMEBRO_REAL_DIR"); d != "" {
		p := filepath.Join(d, name)
		if isExecutable(p) {
			return p
		}
		return ""
	}
	self := selfBinary()
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		p := filepath.Join(abs, name)
		if !isExecutable(p) {
			continue
		}
		if ev, err := filepath.EvalSymlinks(p); err == nil {
			if ev == self || filepath.Base(ev) == "trustmebro" {
				continue // our own shim
			}
		}
		return p
	}
	return ""
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

func selfBinary() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if ev, err := filepath.EvalSymlinks(exe); err == nil {
		return ev
	}
	return exe
}
