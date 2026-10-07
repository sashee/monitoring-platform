# Passkeys in a real browser (SPEC §14.10): ./browser/passkeys.py, run against the release package with
# Chromium's own WebAuthn behind a virtual authenticator.
#
#   nix-build nix -A tests.browser-passkeys
#
# One of `tests` (../default.nix), so `make run-tests` builds it alongside the VM tests, on both architectures.
# A plain sandboxed build rather than a NixOS VM: the receiver is a single binary, socat stands in for the
# tunnel shim, and Chromium runs headless — none of it needs a machine. Not in the package's own checkPhase,
# which the host runs on every deploy: a browser is no part of installing the receiver.
{ pkgs, package }:
let
  python = pkgs.python3.withPackages (p: [ p.playwright ]);
in
pkgs.runCommand "monitoring-platform-browser-passkeys"
  {
    nativeBuildInputs = [
      python
      pkgs.chromium
      pkgs.socat
    ];
    MP_BIN = "${package}/bin/monitoring-platform";
    # Chromium looks for fonts even headless; without a config it warns on every start.
    FONTCONFIG_FILE = pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; };
  }
  ''
    export HOME="$TMPDIR"
    python ${./browser/passkeys.py}
    touch "$out"
  ''
