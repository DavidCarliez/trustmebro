# Changelog

All notable changes to TrustMeBro are documented in this file.

## Unreleased

- Add Linux `trustmebro lab` mode for running shells and agent harnesses in a temporary Bubblewrap interception namespace.
- Shadow discovered absolute command paths while preserving the original binaries for passthrough and rewrite actions.

## 0.1.2 - 2026-08-27

- Correctly parse explicit DNS servers and operand-taking options in `host` calls.
- Prevent common `dig` options and their operands from being mistaken for query names.
- Match real `dig` behavior for `+noall` with and without `+answer`.
- Remove stale managed shims when reinstalling after `shim_commands` changes.
- Replace duplicate `TRUSTMEBRO_DISABLE` entries before executing real commands.
- Limit rewrite-mode capture to 16 MiB per output stream to prevent unbounded memory use.

## 0.1.1 - 2026-08-26

- Reject unknown configuration fields, unsafe shim names, invalid actions, and malformed rules.
- Fail closed when an installed shim encounters an invalid configuration.
- Add integration coverage for spoof, rewrite, passthrough, and invalid-configuration behavior.

## 0.1.0 - 2026-08-25

- Initial release.
