SHELL := bash

# Parallelism for dependency builds within one nix invocation (nix's own default is 1).
# Serializing the VM tests does NOT depend on this: run-tests builds one test per
# invocation, so at most one VM runs regardless. Override (e.g. MAX_JOBS=1) on
# RAM-constrained machines.
MAX_JOBS := auto

NIX_BUILD := nix-build --max-jobs $(MAX_JOBS)
# No flakes, so no experimental features are needed anywhere here (SPEC.md §10.3).
NIX_EVAL := nix-instantiate --eval

.PHONY: all build test lint ci-lint run-tests list-tests clean

# Everything CI runs, in the order that fails fastest.
all: ci-lint build run-tests

# The package. doCheck runs the whole Rust suite inside the sandbox, so this covers
# `cargo test` too.
build:
	$(NIX_BUILD) nix -A package --no-out-link

# The Rust suite outside nix, for a fast local loop.
test:
	cargo test

# Uses whatever toolchain is on PATH — fine locally.
lint:
	cargo clippy --all-targets -- -D warnings

# Lint with the SAME toolchain the package is built with. CI uses this rather than
# `nix-shell -p clippy`, which would take the installer's channel: a nixpkgs bump
# there could introduce new lints and turn CI red with nothing having changed here.
# Bumping nix/pkgs.nix can still do that, but then it is a reviewed change.
ci-lint:
	nix-shell --pure \
	  -E 'let pkgs = import ./nix/pkgs.nix { }; in pkgs.mkShell { packages = [ pkgs.cargo pkgs.clippy pkgs.rustc pkgs.gnumake ]; }' \
	  --run 'make lint'

# The VM test names, straight from nix/tests. Cheap: attrNames does not force the
# derivations, so no NixOS machine is evaluated here.
list-tests:
	@$(NIX_EVAL) --json --strict -E 'builtins.attrNames (import ./nix {}).tests' \
	  | tr -d '[]"' | tr ',' '\n'

# Evaluating every VM test in one nix process is the thing to avoid: each NixOS
# machine eval costs 1-2 GiB and the Boehm-GC evaluator never returns heap to the
# OS, so a combined eval grows without bound and has OOMed CI runners in sibling
# repos. `nix-build nix` (the top level) does exactly that, since it gates the
# package on every test. So CI uses this target instead: list the names cheaply,
# then eval+run each test strictly one at a time in its own short-lived nix
# process. Memory stays bounded by one eval plus one VM, however many tests exist.
run-tests:
	set -euo pipefail; \
	names=$$($(MAKE) --no-print-directory list-tests); \
	echo "tests:" $$names; \
	for name in $$names; do \
		echo "=== test: $$name"; \
		$(NIX_BUILD) nix -A "tests.$$name" --no-out-link; \
	done; \
	echo "=== all VM tests passed"

clean:
	cargo clean
