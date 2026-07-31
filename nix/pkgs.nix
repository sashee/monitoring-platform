# The ONE place a channel is fetched. Everything else (./package.nix, ./module.nix,
# ./tests) takes `pkgs` explicitly with no defaults, so a consuming system's nixpkgs
# is the only one in the deployment path (SPEC.md §11.1).
#
# Extracted from ./default.nix so the pin is shared by the convenience build, the
# Makefile's test listing, and the CI lint toolchain — a lint running against a
# different nixpkgs than the build would go red on unrelated new clippy lints.
{ ... }@args:
import (fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-26.05") (
  {
    config = { };
    overlays = [ ];
  }
  // args
)
