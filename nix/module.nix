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

    clockGate = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Refuse to start until the system clock is verifiably synchronized (SPEC.md §9.4).

          On by default because the failure it prevents is silent: a device with no RTC that
          has not yet reached an NTP server stamps every measurement near the Unix epoch, and
          nothing downstream can tell those rows from correct ones. Turning this off is
          reasonable only where the clock is guaranteed by other means. Note that a host with
          no reachable time source will never start the service — that is the intent, and
          nix/tests gives its VMs a real NTP server rather than switching this off.
        '';
      };

      thresholdMicros = lib.mkOption {
        type = lib.types.ints.positive;
        default = 5000000;
        description = ''
          Maximum kernel clock error (`maxerror` from adjtimex(2)) to accept, in microseconds.

          Do not tighten this to 1 s without also setting `maxpoll 9` on the host's NTP daemon.
          `maxerror` grows continuously between successful updates at the kernel's 500 ppm
          tolerance — 500 µs per second of wall time — so with chrony's default `maxpoll 10`
          (~1024 s) it routinely reaches ~0.5 s while everything is perfectly healthy.
        '';
      };

      pollIntervalSecs = lib.mkOption {
        type = lib.types.ints.positive;
        default = 5;
        description = "Seconds between clock polls.";
      };

      maxPolls = lib.mkOption {
        type = lib.types.ints.positive;
        default = 60;
        description = ''
          Polls to take before giving up and failing the unit. 60 × 5 s ≈ 5 min.

          The wait is bounded by counting polls rather than by a wall-clock deadline, because
          every wall-clock source derives from the very clock being waited on: the first
          successful sync steps it and a deadline computed from it jumps unpredictably.
        '';
      };

      consecutive = lib.mkOption {
        type = lib.types.ints.positive;
        default = 3;
        description = ''
          Consecutive good polls required before starting, as hysteresis against the sawtooth
          described on `thresholdMicros`.
        '';
      };
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

      # A [Unit] setting, NOT serviceConfig: systemd parses the file happily and then
      # drops it with "Unknown key 'StartLimitIntervalSec' in section [Service],
      # ignoring", so putting it below would silently do nothing. nix/tests/cases/
      # hardening.nix now greps the journal for exactly that warning.
      #
      # The start rate limiter is deliberately disabled (SPEC.md §9.2, §9.4). It used to turn a
      # permanent startup failure — a schema newer than the binary (§6.2), an occupied socket
      # (§8.1) — into a failed unit that reports the reason. Fail-closed clock gating trades
      # that away: a Pi that boots without a network legitimately fails for hours, and a
      # limiter would give up permanently during exactly the outage it must survive. The cost
      # is that a genuinely permanent failure now loops at RestartSec intervals instead of
      # stopping and saying so; the journal still names the reason on every attempt.
      startLimitIntervalSec = 0;

      serviceConfig = {
        # Readiness is reported with sd_notify once migrations have run and the
        # socket is accepting. Under Type=simple systemd would consider the service
        # started at fork, letting a dependent unit race the bind().
        Type = "notify";

        # Fail-closed: no `-` prefix, so the gate's exit 1 fails the unit rather than being
        # ignored. This re-runs on every restart, so the clock is rechecked on each retry and
        # on crash-loop recovery — intended, not an accident of ExecStartPre semantics.
        #
        # Note `systemctl start monitoring-platform` will block for up to the wait budget on a
        # cold boot, and `systemctl is-system-running` reports `starting` meanwhile. Harmless
        # unless something downstream polls for `running`.
        ExecStartPre = lib.mkIf cfg.clockGate.enable (lib.escapeShellArgs [
          (lib.getExe cfg.package)
          "wait-for-clock"
          "--threshold-micros"
          (toString cfg.clockGate.thresholdMicros)
          "--poll-interval-secs"
          (toString cfg.clockGate.pollIntervalSecs)
          "--max-polls"
          (toString cfg.clockGate.maxPolls)
          "--consecutive"
          (toString cfg.clockGate.consecutive)
          "--log-level"
          cfg.logLevel
        ]);

        # Derived, not a round number: it must exceed the gate's OWN bound, or systemd kills the
        # wait mid-flight and produces an accidental failure instead of the deliberate one. The
        # default 90 s would do exactly that. Deriving it means raising maxPolls cannot silently
        # reintroduce the bug.
        TimeoutStartSec =
          if cfg.clockGate.enable then
            cfg.clockGate.maxPolls * cfg.clockGate.pollIntervalSecs + 120
          else
            90;

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

        # Restart= covers ExecStartPre= failures too, so the clock gate keeps retrying rather
        # than needing an operator once the network comes back. The rate limiter that would
        # otherwise stop those retries is disabled at the unit level above, not here.
        Restart = "on-failure";
        RestartSec = "60s";

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
        # NOT ProtectClock: the clock gate must *read* the kernel's error estimate with
        # adjtimex(2), and systemd.exec(5) is explicit that this option cannot allow that —
        # "the system calls are blocked altogether, the filter does not take into account that
        # some of the calls can be used to read the clock state with some parameter
        # combinations". It kills with SIGSYS, including in ExecStartPre, which shares this
        # sandbox.
        #
        # Dropping it costs nothing the service actually relied on: CapabilityBoundingSet=[""]
        # plus NoNewPrivileges means CAP_SYS_TIME is unavailable, so the service still cannot
        # set the clock — only read the estimate — and PrivateDevices=true already withholds
        # /dev/rtc*, which is the other half of what ProtectClock provided.
        ProtectClock = false;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        CapabilityBoundingSet = [ "" ];
        # @clock is not part of @system-service, so adjtimex(2) needs naming explicitly for the
        # gate above. It grants reading the clock, not setting it: the capability set is empty,
        # so clock_settime/settimeofday still fail with EPERM.
        SystemCallFilter = [ "@system-service" "@clock" ];
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
