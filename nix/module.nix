# NixOS module. Generates the unit specified in SPEC.md §9.2.
#
# A hand-written .service file is not the deliverable: on NixOS units come from
# systemd.services.<name>, and a raw unit carried in via systemd.packages cannot be
# typechecked, overridden, or referenced by other options (SPEC.md §9.3).
#
#   imports = [ "${monitoring-platform}/nix/module.nix" ];
#   services.monitoring-platform.enable = true;
{ config, lib, pkgs, ... }:
let
  cfg = config.services.monitoring-platform;
  name = "monitoring-platform";
in
{
  options.services.monitoring-platform = {
    enable = lib.mkEnableOption "the monitoring platform OTLP receiver";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = ''
        The package to run. Defaults to building from this repository with the
        target system's own nixpkgs, which is deliberate: the deployed binary is
        built with the toolchain the host actually has.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = name;
      description = "System user the service runs as.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = name;
      description = ''
        Group owning the socket. A local client must be a member of this group to
        reach the receiver, since access is gated by the runtime directory's mode.
      '';
    };

    socketPath = lib.mkOption {
      type = lib.types.path;
      default = "/run/${name}/${name}.sock";
      description = ''
        Unix socket to listen on. Defaults to a path inside the systemd-provisioned
        RuntimeDirectory; override only to run a second instance alongside.
      '';
    };

    databasePath = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/${name}/measurements.db";
      description = "SQLite database file, inside the systemd StateDirectory.";
    };

    maxBodyBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 4 * 1024 * 1024;
      description = "Maximum wire request body, in bytes.";
    };

    maxDecompressedBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 32 * 1024 * 1024;
      description = ''
        Maximum decompressed request body, in bytes. Independent of maxBodyBytes on
        purpose: a small gzip payload can expand without bound, so the wire limit
        alone does not bound memory (SPEC.md §4.2).
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      example = "monitoring_platform=debug";
      description = "Value for the tracing env-filter.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${cfg.user} = lib.mkIf (cfg.user == name) {
      isSystemUser = true;
      group = cfg.group;
      description = "Monitoring platform service user";
    };
    users.groups.${cfg.group} = lib.mkIf (cfg.group == name) { };

    systemd.services.${name} = {
      description = "Monitoring platform OTLP receiver";
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        # Readiness is reported with sd_notify once migrations have run and the
        # socket is accepting. Under Type=simple systemd would consider the service
        # started at fork, letting a dependent unit race the bind().
        Type = "notify";
        ExecStart = lib.escapeShellArgs [
          (lib.getExe cfg.package)
          "serve"
          "--socket"
          cfg.socketPath
          "--db"
          cfg.databasePath
          "--max-body-bytes"
          (toString cfg.maxBodyBytes)
          "--max-decompressed-bytes"
          (toString cfg.maxDecompressedBytes)
          "--log-level"
          cfg.logLevel
        ];

        Restart = "on-failure";
        RestartSec = "1s";
        # A too-new schema version and an occupied socket path are both permanent
        # startup failures. The rate limit is what turns an endless restart loop
        # into a failed unit that reports the reason.
        StartLimitBurst = 5;
        StartLimitIntervalSec = 10;

        User = cfg.user;
        Group = cfg.group;

        StateDirectory = name;
        StateDirectoryMode = "0700";
        # 0750 and group-owned is the ACTUAL access control for the socket: between
        # bind() and the binary's chmod the socket carries 0777 & ~umask, so the
        # directory is what gates connections at every instant (SPEC.md §8.1).
        RuntimeDirectory = name;
        RuntimeDirectoryMode = "0750";

        # SIGTERM is systemd's default stop signal and is what the graceful path
        # listens for, so no KillSignal override; the default TimeoutStopSec is
        # ample for draining the writer and checkpointing WAL.

        # Hardening.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        CapabilityBoundingSet = [ "" ];
        SystemCallFilter = [ "@system-service" ];
        SystemCallArchitectures = "native";
        # Enforces the local-only property in the kernel rather than by convention.
        # THIS is the line to change when the iroh transport lands (it needs AF_INET
        # and AF_INET6) — restrictive now so enabling network access is a visible,
        # reviewed edit rather than something that silently starts working.
        RestrictAddressFamilies = [ "AF_UNIX" ];
      };
    };
  };
}
