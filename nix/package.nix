# The package. Takes its inputs from the CALLER's package set with no defaults and
# no channel fetching, so the target system's nixpkgs decides every version — see
# SPEC.md §11.1 for why that is the point rather than an accident.
#
#   pkgs.callPackage ./nix/package.nix { }
{
  lib,
  rustPlatform,
  # rusqlite is built with its `bundled` feature, so SQLite is compiled from the
  # vendored C source: no system sqlite, no pkg-config, and no protoc either
  # (opentelemetry-proto ships pre-generated prost types). Only a C compiler.
  stdenv,
}:
rustPlatform.buildRustPackage {
  pname = "monitoring-platform";
  version = "0.1.0";

  src =
    let
      # Keep the store path stable against edits to docs and nix files: only the
      # Rust sources and manifests affect the build.
      keep = [ "Cargo.toml" "Cargo.lock" "src" "tests" "examples" "crates" ];
    in
    lib.cleanSourceWith {
      src = lib.cleanSource ../.;
      filter =
        path: _type:
        let
          rel = lib.removePrefix (toString ../. + "/") (toString path);
          root = builtins.head (lib.splitString "/" rel);
        in
        builtins.elem root keep;
    };

  # Committed lock file, so there is no vendor hash to keep in sync.
  cargoLock.lockFile = ../Cargo.lock;

  # Explicit because the workspace has a root package: without --workspace, cargo's
  # default member selection is that package alone, so mp-collector would silently
  # be neither built nor tested and the derivation would still succeed.
  cargoBuildFlags = [ "--workspace" ];
  cargoTestFlags = [ "--workspace" ];

  # The end-to-end tests spawn the binary and bind unix sockets under TMPDIR; they
  # need no network and no /dev/kvm, so they run in the sandbox as-is.
  doCheck = true;

  meta = {
    description = "OTLP/HTTP receiver storing device measurements in SQLite";
    longDescription = ''
      Accepts OpenTelemetry Events over OTLP/HTTP with protobuf encoding on a unix
      domain socket, maps each LogRecord to a measurement, and stores it in SQLite.
      Also serves a small JSON read API. See SPEC.md.
    '';
    mainProgram = "monitoring-platform";
    platforms = lib.platforms.linux;
    # The unix-socket transport and systemd integration are Linux-only by design.
    broken = !stdenv.hostPlatform.isLinux;
  };
}
