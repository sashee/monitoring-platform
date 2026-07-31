# Convenience entrypoint for `nix-build nix`. The channel pin lives in ./pkgs.nix,
# which is the only place one is fetched — everything else (./package.nix,
# ./module.nix, ./tests) takes pkgs explicitly, so a consuming system's nixpkgs is the
# only one in the deployment path (SPEC.md §11.1).
#
#   nix-build nix                        # package + tests
#   nix-build nix -A package             # package only (skip the VM tests)
#   nix-build nix -A tests.platform      # the shared-VM cases
#   nix-build nix -A tests.restart       # one isolated case
#
# Prefer `make run-tests` over the bare top level in CI: this derivation gates the
# package on *every* test, which means one nix process evaluates every NixOS machine
# at once. See the comment on the Makefile's run-tests target.
#
# There is deliberately no flake. The package is a callPackage function, the module is
# a plain NixOS module and the tests take pkgs as an argument, so none of them needs
# one; a flake would add a second pinned nixpkgs that the target system does not use,
# working against the very property the tests exist to check.
{
  pkgs ? import ./pkgs.nix { },
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
