# Convenience entrypoint for `nix-build nix`. The ONLY place a channel is fetched —
# everything else (./package.nix, ./module.nix, ./tests) takes pkgs explicitly, so a
# consuming system's nixpkgs is the only one in the deployment path (SPEC.md §11.1).
#
# Building this builds the package AND runs the NixOS VM tests:
#   nix-build nix                        # package + tests
#   nix-build nix -A package             # package only (skip the VM tests)
#   nix-build nix -A tests.platform      # the shared-VM cases
#   nix-build nix -A tests.restart       # one isolated case
#
# There is deliberately no flake. The package is a callPackage function, the module is
# a plain NixOS module and the tests take pkgs as an argument, so none of them needs
# one; a flake would add a second pinned nixpkgs that the target system does not use,
# working against the very property the tests exist to check.
{
  pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-26.05") {
    config = { };
    overlays = [ ];
  },
}:
let
  package = pkgs.callPackage ./package.nix { };
  tests = import ./tests { inherit pkgs; };
in
pkgs.symlinkJoin {
  name = "monitoring-platform-checked";
  paths = [ package ];
  # Interpolating each VM-test derivation's store path registers it as a build input,
  # so building this requires every test to pass.
  postBuild = ''
    : ${pkgs.lib.concatStringsSep " " (map (t: "${t}") (builtins.attrValues tests))}
  '';
  passthru = { inherit package tests; };
}
