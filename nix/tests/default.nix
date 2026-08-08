# Repo-specific test entry: assembles a minimal NixOS machine and runs the generic
# harness (./lib.nix) against it. Inputs are required (no fetchTarball) so this never
# fetches a channel — ../default.nix supplies them.
#
#   nix-build nix -A tests.platform      # all lightweight cases (one VM)
#   nix-build nix -A tests.restart       # an isolated case
#
# This is the WEAKER run, and deliberately so. The machine here is synthetic, so it
# validates the sandbox against whatever channel ../default.nix pins. A target system
# testing the service against its OWN configuration imports ./lib.nix directly with
# its real host module, which is the run that actually decides whether the hardening
# in ../module.nix is correct for the systemd it will run under (SPEC.md §11.1).
{
  pkgs,
  stateVersion ? pkgs.lib.trivial.release,
}:
let
  # The bare minimum: the service module plus a state version. Everything the tests
  # need beyond this (client users, curl, sqlite) is added by ./lib.nix, so it is
  # added on a consumer's real machine too.
  testMachine =
    { ... }:
    {
      imports = [ ../module.nix ];
      system.stateVersion = stateVersion;
    };

  # NixOS VM tests require the `kvm` system feature by default; a free aarch64 CI
  # runner has no /dev/kvm. Drop the *requirement* so tests schedule on a KVM-less
  # builder — QEMU's accel=kvm:tcg still uses KVM where present (x86) and falls back
  # to TCG where absent. Mirrors sashee/nixos-test's dropKvm.
  dropKvm =
    t:
    t.overrideTestDerivation (old: {
      requiredSystemFeatures = builtins.filter (f: f != "kvm") old.requiredSystemFeatures;
    });
in
builtins.mapAttrs (_: dropKvm) (
  # `collector` is deliberately not passed: the harness defaults it on and imports the collector
  # module itself, so this repo's assembly is exactly what a consumer's looks like. Passing it here
  # would let the default rot untested — which is how the consumer repo ended up with no collector
  # coverage in the first place.
  import ./lib.nix {
    inherit pkgs stateVersion;
    machineModules = [ testMachine ];
  }
)
