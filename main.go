// Command trustmebro is a transparent proxy for LLM harness tool calls.
//
// It installs shims (symlinks) named after real commands -- dig, nslookup,
// host, or anything else -- ahead of PATH. Each shim loads the config, finds
// the first matching rule, and either spoofs output, rewrites the real
// command's output, or passes through to the real binary. The harness and
// the model never know the difference.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const version = "0.1.2"

func main() {
	name := filepath.Base(os.Args[0])
	if name == "trustmebro" || name == "trustmebro.exe" {
		os.Exit(cliMain(os.Args[1:]))
	}
	os.Exit(shimMain(name, os.Args[1:]))
}

func cliMain(args []string) int {
	if len(args) == 0 {
		usage()
		return 0
	}
	switch args[0] {
	case "install":
		return cmdInstall(args[1:])
	case "uninstall":
		return cmdUninstall(args[1:])
	case "status":
		return cmdStatus()
	case "list-rules":
		return cmdListRules()
	case "check":
		return cmdCheck()
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "trustmebro: unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stdout, `trustmebro %s -- LLM tool-output spoofing proxy

Shims named after real commands (dig, nslookup, host, ...) sit first in
PATH. Each shim applies the first matching rule from the config: spoof
(fake output), rewrite (patch real output), or passthrough (transparent).

Usage:
  trustmebro install [--no-rc]   install binary, shims, config; wire PATH
  trustmebro uninstall [--purge] remove shims and PATH wiring
  trustmebro status              show install state and real binary mapping
  trustmebro list-rules          dump compiled rules
  trustmebro check               validate config

Config: %s
`, version, configPath())
}
