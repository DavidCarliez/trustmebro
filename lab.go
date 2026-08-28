package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const labEnvironment = "TRUSTMEBRO_LAB"

type labMapping struct {
	Command string
	Real    string
	Shadows []string
}

type labSpec struct {
	engine  string
	root    string
	shimDir string
	realDir string
	self    string
	maps    []labMapping
}

func cmdLab(args []string) int {
	planOnly := false
	for len(args) > 0 {
		switch args[0] {
		case "--":
			args = args[1:]
			goto parsed
		case "--plan":
			planOnly = true
			args = args[1:]
		case "-h", "--help":
			labUsage()
			return 0
		case "status":
			if len(args) != 1 {
				fmt.Fprintln(os.Stderr, "trustmebro: lab status takes no arguments")
				return 2
			}
			if os.Getenv(labEnvironment) == "1" {
				fmt.Println("TrustMeBro lab is active")
			} else {
				fmt.Println("TrustMeBro lab is not active")
			}
			return 0
		default:
			if strings.HasPrefix(args[0], "-") {
				fmt.Fprintf(os.Stderr, "trustmebro: unknown lab option %q\n", args[0])
				return 2
			}
			goto parsed
		}
	}

parsed:
	if os.Getenv(labEnvironment) == "1" {
		fmt.Fprintln(os.Stderr, "trustmebro: already inside a TrustMeBro lab")
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "trustmebro: lab currently requires Linux and Bubblewrap")
		return 1
	}

	cfg, errs := LoadConfig()
	if len(errs) > 0 {
		fmt.Fprintln(os.Stderr, "trustmebro: invalid config; lab not started:")
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "  %s\n", err)
		}
		return 1
	}

	spec, err := prepareLab(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trustmebro: lab:", err)
		return 1
	}
	defer os.RemoveAll(spec.root)

	command := args
	if len(command) == 0 {
		shell := os.Getenv("SHELL")
		if shell == "" || !isExecutable(shell) {
			shell = "/bin/sh"
		}
		command = []string{shell, "-i"}
	}
	if planOnly {
		printLabPlan(spec, command)
		return 0
	}
	return runLab(spec, command)
}

func labUsage() {
	fmt.Fprint(os.Stdout, `Usage:
  trustmebro lab                       open an interactive lab shell
  trustmebro lab -- <command> [args]   run one command in the lab
  trustmebro lab --plan -- <command>   show mappings without running
  trustmebro lab status                show whether the lab is active

Lab uses a temporary Linux mount namespace to shadow configured command
paths, including absolute paths such as /usr/bin/dig. It reuses the host
filesystem, network, workspace, and credentials; it is not a security sandbox.
`)
}

func prepareLab(cfg *Config) (*labSpec, error) {
	engine, err := findBubblewrap()
	if err != nil {
		return nil, err
	}
	self := selfBinary()
	if self == "" {
		return nil, fmt.Errorf("cannot locate own binary")
	}
	root, err := os.MkdirTemp("", "trustmebro-lab-")
	if err != nil {
		return nil, err
	}
	spec := &labSpec{
		engine:  engine,
		root:    root,
		shimDir: filepath.Join(root, "shims"),
		realDir: filepath.Join(root, "real"),
		self:    self,
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(root)
		}
	}()
	for _, dir := range []string{spec.shimDir, spec.realDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
	}

	for _, command := range cfg.ShimCommands {
		if command == "trustmebro" || command == "trustmebro.exe" {
			return nil, fmt.Errorf("shim command %q conflicts with the TrustMeBro CLI", command)
		}
		if err := os.Symlink(self, filepath.Join(spec.shimDir, command)); err != nil {
			return nil, err
		}

		mapping := labMapping{Command: command}
		mapping.Shadows = labCommandPaths(command, self)
		mapping.Real = firstRealPath(command, self)
		if mapping.Real != "" {
			placeholder := filepath.Join(spec.realDir, command)
			if err := os.WriteFile(placeholder, nil, 0o700); err != nil {
				return nil, err
			}
		}
		spec.maps = append(spec.maps, mapping)
	}
	cleanup = false
	return spec, nil
}

func findBubblewrap() (string, error) {
	for _, name := range []string{"bwrap", "bubblewrap"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("Bubblewrap not found; install bwrap to use lab mode")
}

func labSearchDirs() []string {
	seen := make(map[string]struct{})
	var dirs []string
	add := func(dir string) {
		if dir == "" {
			dir = "."
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return
		}
		abs = filepath.Clean(abs)
		if _, exists := seen[abs]; exists {
			return
		}
		seen[abs] = struct{}{}
		dirs = append(dirs, abs)
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		add(dir)
	}
	for _, dir := range []string{"/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/sbin", "/sbin"} {
		add(dir)
	}
	return dirs
}

func labCommandPaths(command, self string) []string {
	seen := make(map[string]struct{})
	var paths []string
	for _, dir := range labSearchDirs() {
		candidate := filepath.Join(dir, command)
		if !isExecutable(candidate) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil || isTrustmebroBinary(resolved, self) {
			continue
		}
		resolved = filepath.Clean(resolved)
		if _, exists := seen[resolved]; exists {
			continue
		}
		seen[resolved] = struct{}{}
		paths = append(paths, resolved)
	}
	sort.Strings(paths)
	return paths
}

func firstRealPath(command, self string) string {
	for _, dir := range labSearchDirs() {
		candidate := filepath.Join(dir, command)
		if !isExecutable(candidate) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil || isTrustmebroBinary(resolved, self) {
			continue
		}
		return filepath.Clean(resolved)
	}
	return ""
}

func isTrustmebroBinary(path, self string) bool {
	if filepath.Clean(path) == filepath.Clean(self) {
		return true
	}
	base := filepath.Base(path)
	return base == "trustmebro" || base == "trustmebro.exe"
}

func printLabPlan(spec *labSpec, command []string) {
	fmt.Printf("engine:  %s\n", spec.engine)
	fmt.Printf("command: %s\n", strings.Join(command, " "))
	fmt.Println("mode:    interception namespace (not a security sandbox)")
	for _, mapping := range spec.maps {
		real := mapping.Real
		if real == "" {
			real = "not found"
		}
		fmt.Printf("%-12s real=%s\n", mapping.Command, real)
		for _, path := range mapping.Shadows {
			fmt.Printf("  shadow %s\n", path)
		}
	}
}

func runLab(spec *labSpec, command []string) int {
	args := []string{"--die-with-parent", "--bind", "/", "/", "--dev-bind", "/dev", "/dev"}
	for _, mapping := range spec.maps {
		if mapping.Real != "" {
			args = append(args, "--ro-bind", mapping.Real, filepath.Join(spec.realDir, mapping.Command))
		}
	}
	shadowed := make(map[string]struct{})
	for _, mapping := range spec.maps {
		for _, path := range mapping.Shadows {
			if _, exists := shadowed[path]; exists {
				continue
			}
			shadowed[path] = struct{}{}
			args = append(args, "--ro-bind", spec.self, path)
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		args = append(args, "--chdir", cwd)
	}
	args = append(args, "--")
	args = append(args, command...)

	path := spec.shimDir
	if current := os.Getenv("PATH"); current != "" {
		path += string(os.PathListSeparator) + current
	}
	env := envWithOverride(os.Environ(), "PATH", path)
	env = envWithOverride(env, "TRUSTMEBRO_REAL_DIR", spec.realDir)
	env = envWithOverride(env, "TRUSTMEBRO_DISABLE", "0")
	env = envWithOverride(env, labEnvironment, "1")

	cmd := exec.Command(spec.engine, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return exitCode(err)
	}
	return 0
}
