# NixOS module for the clock-correcting collector.
# See collector-clock-correction-design.md §7.
#
#   imports = [ "${monitoring-platform}/nix/collector-module.nix" ];
#   services.mp-collector.enable = true;
#
# This unit is deliberately the INVERSE of the receiver's (SPEC.md §9.4, nix/module.nix). The
# receiver fails closed on a bad clock and refuses to start until NTP has been reached; the
# collector must be running BEFORE anything can step the clock, and never refuses. The two are
# coherent only because they are different processes with different jobs — and the ordering here
# (Before= the time daemons) is flatly incompatible with the receiver's gate, which is why they
# cannot be the same unit.
{ config, lib, pkgs, ... }:
let
  cfg = config.services.mp-collector;
  name = "mp-collector";
  # Whether the forward target needs the network. Read off the option rather than made
  # configurable separately, so RestrictAddressFamilies below cannot drift from where the data
  # actually goes.
  forwardsOverTcp = lib.hasPrefix "http://" cfg.forwardTo || lib.hasPrefix "https://" cfg.forwardTo;

  # Everything on the host that is in a position to step the clock. Listed rather than detected:
  # a daemon that is not installed simply has no unit, and ordering before a unit that does not
  # exist is a no-op, so naming all of them costs nothing and misses none.
  timeDaemons = [
    "chronyd.service"
    "systemd-timesyncd.service"
    "ntpd.service"
    "openntpd.service"
    "ntpd-rs.service"
  ];
in
{
  options.services.mp-collector = {
    enable = lib.mkEnableOption "the on-host OTLP clock-correcting collector";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = ''
        The package to run. The collector ships in the same derivation as the
        receiver, so this is the same default as services.monitoring-platform.package.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = name;
      description = "System user the collector runs as.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = name;
      description = ''
        Group owning the collector's socket. An instrumented application must be a
        member of this group to reach it, since access is gated by the runtime
        directory's mode.
      '';
    };

    socketPath = lib.mkOption {
      type = lib.types.path;
      default = "/run/${name}/${name}.sock";
      description = ''
        Where applications send OTLP. Created by the socket unit before any client
        can connect, so a client blocks rather than failing.
      '';
    };

    forwardTo = lib.mkOption {
      type = lib.types.str;
      default = "/run/monitoring-platform/monitoring-platform.sock";
      example = "http://collector.internal:4318/v1/logs";
      description = ''
        Where corrected batches go: a unix socket path, or an http:// URL.

        https:// is refused at startup rather than silently downgraded; TLS is out of
        scope for this stack (SPEC.md §2). Setting an http:// URL also widens
        RestrictAddressFamilies= to permit TCP, which is a visible consequence of this
        option rather than a separate switch that could be forgotten.
      '';
    };

    bufferTimeoutSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 300;
      description = ''
        How long to hold telemetry waiting for a clock that has never been set this
        boot, before shipping it marked `mp.clock.uncertain`. Matches the receiver's
        own clock-gate budget. A Pi that boots with no network may never synchronize,
        and holding its data indefinitely is worse than shipping it flagged.
      '';
    };

    forwardTimeoutSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 30;
      description = ''
        How long one delivery attempt may take before it is abandoned and retried.

        Deliberately generous: this bounds a *hung* transport, not a slow one, and
        `retryMaxSecs` rather than this option is what keeps an unreachable receiver from
        stalling the collector. A timeout short enough to fire on a receiver that is
        merely slow to write would make the collector re-send batches that already
        landed, forever.

        It matters most when something stands between the collector and the receiver — a
        tunnel or a proxy — because such a socket accepts whether or not its far end is
        reachable, so an unreachable receiver arrives as silence rather than as a
        refused connection, and silence has no other detector.
      '';
    };

    retryMaxSecs = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 10;
      description = ''
        Ceiling for the exponential backoff between failed delivery attempts, whose floor
        is the grace period. This is the longest a batch can wait *after* the receiver
        comes back, so it bounds what an ordinary restart of the receiver costs.

        0 retries on every flush cycle, which is the behaviour from before the backoff
        existed. Reasonable for a purely local hop; on anything slower it means a dead
        target is retried as fast as batches arrive.
      '';
    };

    clockThresholdMicros = lib.mkOption {
      type = lib.types.ints.positive;
      default = 5000000;
      description = ''
        Maximum kernel clock error (`maxerror` from adjtimex(2)) to accept, in
        microseconds. The same value and the same reasoning as
        services.monitoring-platform.clockGate.thresholdMicros: `maxerror` grows at
        500 ppm between updates, so with chrony's default `maxpoll 10` it reaches
        ~0.5 s in healthy operation and a tighter threshold flaps.
      '';
    };

    forwardToGroup = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default =
        if cfg.forwardTo == "/run/monitoring-platform/monitoring-platform.sock" then
          "monitoring-platform"
        else
          null;
      defaultText = lib.literalExpression ''"monitoring-platform" when forwardTo is its default'';
      description = ''
        Group to join in order to reach a unix `forwardTo` socket.

        Not optional in practice and not merely tidy: the receiver's socket lives inside a
        0750 group-owned RuntimeDirectory (SPEC.md §8.1), which is the actual access
        control. Without this membership every flush fails with a permission error and the
        collector buffers forever — visible in the journal, but only after the fact.

        Defaulted rather than required so the common case (both services from this
        repository, on one host) needs no configuration; set it explicitly when forwarding
        to some other unix socket, or to null when forwarding over TCP.
      '';
    };

    healthIntervalSecs = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 60;
      description = ''
        Seconds between the collector's own health events (design §9), or 0 to disable them.

        These are ordinary measurements and land in the same table as everything else,
        which is the point of them: "no daemon has disciplined this device's clock since
        boot" is a work item, where "every timestamp from this device is three days old"
        is a mystery. It also means they show up in row counts, so a test asserting an
        exact number wants 0 here.
      '';
    };

    journalBackfill = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Reconstruct pre-collector offset history from journald at startup (design §4.2).

        A soft dependency: with applications ordered after the collector there are no
        application records from before it started, so this only matters for processes
        outside the unit ordering — containers, manually launched binaries. Turning it
        off removes the systemd-journal group membership below.
      '';
    };

    orderBeforeTimeDaemons = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Start the collector before anything that can step the clock.

        This is what eliminates the unknown-epoch case: the only offset change left
        before the collector exists is the kernel's initial set from fake-hwclock,
        which happens before userspace and therefore before any application timestamp.
        Turning it off means a step during early boot can go unobserved, and records
        stamped in that window resolve to `passthrough` instead of being corrected.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      example = "mp_collector=debug";
      description = "Value for the tracing env-filter.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # A supplementary group that does not exist is not a warning: systemd refuses to start the
        # unit with "Failed to determine supplementary groups", and nothing before that point
        # notices. The realistic way in is a host that enables the collector but not the receiver,
        # where the default below still names the receiver's group.
        assertion = cfg.forwardToGroup == null || config.users.groups ? ${cfg.forwardToGroup};
        message = ''
          services.mp-collector.forwardToGroup is "${toString cfg.forwardToGroup}", which is not
          a group on this host, so systemd would refuse to start the unit.

          It defaults to "monitoring-platform" whenever forwardTo is the receiver's own socket,
          because that socket's access control is the mode on its containing runtime directory
          (SPEC.md §8.1) and the collector has to be in the group to reach it. If the receiver
          runs elsewhere, set forwardToGroup to whichever group owns the socket you are
          forwarding to, or to null if it needs no group.
        '';
      }
      {
        assertion = !(lib.hasPrefix "https://" cfg.forwardTo);
        message = ''
          services.mp-collector.forwardTo is an https:// URL, which the collector
          refuses at startup: TLS is out of scope (SPEC.md §2). Use a unix socket, or
          http:// if the hop is genuinely local.
        '';
      }
    ];

    users.users.${cfg.user} = lib.mkIf (cfg.user == name) {
      isSystemUser = true;
      group = cfg.group;
      description = "OTLP clock-correcting collector service user";
    };
    users.groups.${cfg.group} = lib.mkIf (cfg.group == name) { };

    # The socket unit is what removes the startup ordering race entirely. It creates the endpoint
    # before any client can connect, so an application that starts first blocks on connect()
    # rather than failing — no retry loop needed in the application.
    systemd.sockets.${name} = {
      description = "OTLP collector socket";
      wantedBy = [ "sockets.target" ];

      # The socket needs the same early treatment as the service, or the ordering below is
      # vacuous: with default dependencies the socket is After=sysinit.target, systemd-timesyncd
      # is *part of* sysinit.target, and a service that must wait for its own socket therefore
      # cannot possibly precede it.
      unitConfig = lib.mkIf cfg.orderBeforeTimeDaemons {
        DefaultDependencies = false;
        # Put back by hand what DefaultDependencies=no removed. Without these the socket is not
        # ordered against shutdown at all and gets torn down at an arbitrary point in it.
        Conflicts = [ "shutdown.target" ];
        Before = [ "shutdown.target" ] ++ timeDaemons;
      };

      socketConfig = {
        ListenStream = cfg.socketPath;
        SocketUser = cfg.user;
        SocketGroup = cfg.group;
        SocketMode = "0660";
        # The service is started eagerly below, NOT lazily on first connect. Lazy activation
        # guarantees the socket exists but not that the process is running, and a collector that
        # is not running observes no clock steps — which is the one thing it is for.
        Accept = false;
      };
    };

    systemd.services.${name} = {
      description = "OTLP collector with retroactive clock correction";
      # Eagerly, so the process is up before anything can step the clock. Both units are enabled:
      # the socket creates the endpoint early, the service receives the listening fd through it.
      wantedBy = [ "multi-user.target" ];
      requires = [ "${name}.socket" ];
      after = [ "${name}.socket" ];

      # Ordering before the time daemons means the collector is running before anything is in a
      # position to step the clock. That in turn is what eliminates the unknown-epoch case: the
      # only remaining offset change is the kernel's initial set from fake-hwclock, which happens
      # before userspace and therefore before any application timestamp exists.
      before = lib.optionals cfg.orderBeforeTimeDaemons timeDaemons;

      # DefaultDependencies=no is unavoidable here rather than merely convenient: systemd-timesyncd
      # is part of sysinit.target, and a unit with default dependencies is ordered *after*
      # sysinit.target, so it cannot precede timesyncd at all.
      #
      # What it silently removes is the shutdown ordering, and not putting that back is the classic
      # way to have a unit killed at an arbitrary point during shutdown — here, mid-flush, with the
      # buffer still holding records. `local-fs.target` goes back too, because StateDirectory=
      # below lives under /var/lib. The design doc's §7 snippet has none of these three lines.
      unitConfig = lib.mkIf cfg.orderBeforeTimeDaemons {
        DefaultDependencies = false;
        Conflicts = [ "shutdown.target" ];
        Before = [ "shutdown.target" ];
        After = [ "local-fs.target" ];
        RequiresMountsFor = [ "/var/lib" ];
      };

      serviceConfig = {
        # Readiness is reported with sd_notify once the offset history is loaded and the step
        # watch is armed. Under Type=simple systemd would consider the collector started at fork,
        # letting an application unit ordered after it race the very thing that ordering exists
        # to guarantee.
        Type = "notify";

        ExecStart = lib.escapeShellArgs (
          [
            "${cfg.package}/bin/mp-collector"
            "--socket"
            cfg.socketPath
            "--forward-to"
            cfg.forwardTo
            "--buffer-timeout-secs"
            (toString cfg.bufferTimeoutSecs)
            "--forward-timeout-secs"
            (toString cfg.forwardTimeoutSecs)
            "--retry-max-secs"
            (toString cfg.retryMaxSecs)
            "--health-interval-secs"
            (toString cfg.healthIntervalSecs)
            "--clock-threshold-micros"
            (toString cfg.clockThresholdMicros)
            "--journal-backfill"
            (lib.boolToString cfg.journalBackfill)
            "--log-level"
            cfg.logLevel
          ]
        );

        # No ExecStartPre clock gate, deliberately. The receiver's unit has one (SPEC.md §9.4) and
        # this must not: a collector that waits for the clock is a collector that is not running
        # while the clock is wrong, which is the entire window it exists to cover.

        Restart = "on-failure";
        RestartSec = "5s";

        User = cfg.user;
        Group = cfg.group;

        # Holds the epoch table (epochs.json) and the spool. Both are keyed by boot_id, so
        # surviving a reboot is safe: stale entries are recognised and retired rather than reused.
        StateDirectory = name;
        StateDirectoryMode = "0700";
        RuntimeDirectory = name;
        RuntimeDirectoryMode = "0750";
        # **Load-bearing, and the failure it prevents is silent.** The socket unit creates
        # /run/mp-collector/mp-collector.sock and owns it for the life of the boot; the service's
        # RuntimeDirectory= claims the same directory and, by default, *deletes it when the service
        # stops*. The socket file goes with it. The service then restarts, inherits the listening
        # descriptor through LISTEN_FDS, and reports itself healthy — while every client connecting
        # to the path gets ECONNREFUSED, because the inode the descriptor refers to is no longer
        # linked anywhere.
        #
        # That is not a corner case: Restart=on-failure reaches it, and so does any `systemctl
        # restart`. Preserving the directory keeps the socket unit's file valid across the
        # service's whole lifetime. Caught by nix/tests/cases/collector-step.nix.
        RuntimeDirectoryPreserve = "yes";

        # Two memberships, each present only when something needs it:
        #   - the journal, for the §4.2 backfill;
        #   - the receiver's group, without which the forwarding socket is simply unreachable.
        SupplementaryGroups =
          lib.optionals cfg.journalBackfill [ "systemd-journal" ]
          ++ lib.optional (cfg.forwardToGroup != null) cfg.forwardToGroup;

        # Hardening, mirroring nix/module.nix with three deliberate differences, each below.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        CapabilityBoundingSet = [ "" ];
        SystemCallArchitectures = "native";

        # DIFFERENCE 1: NOT ProtectClock=yes. adjtimex(2) must be readable for sync detection, and
        # systemd.exec(5) is explicit that this option cannot allow a read — it blocks the calls
        # outright and kills with SIGSYS. Costs nothing: CapabilityBoundingSet=[""] plus
        # NoNewPrivileges means CAP_SYS_TIME is unavailable, so the collector still cannot *set*
        # the clock, and PrivateDevices=true already withholds /dev/rtc*.
        ProtectClock = false;
        # @clock is not part of @system-service, so adjtimex(2) and timerfd_create(2) against
        # CLOCK_REALTIME need naming explicitly.
        SystemCallFilter = [ "@system-service" "@clock" ];

        # DIFFERENCE 2: NOT ProtectProc="invisible", which the receiver does set.
        #
        # Frame resolution reads /proc/PID/stat for the *sending* process to get its start time
        # (design §5.1), and those processes belong to other users. `invisible` hides them, the
        # read fails, the lower bound of the [sender_started, received] window collapses to zero,
        # and every record silently degrades toward `passthrough`. Nothing would report this
        # except a rise in the passthrough counter, which is exactly the kind of quiet failure
        # this design is built to avoid.
        ProtectProc = "default";

        # DIFFERENCE 3: the address families follow the forward target. AF_UNIX only unless the
        # data actually leaves the host, so enabling network egress is a visible consequence of
        # setting a URL rather than a permission granted up front.
        RestrictAddressFamilies =
          [ "AF_UNIX" ] ++ lib.optionals forwardsOverTcp [ "AF_INET" "AF_INET6" ];
      };
    };
  };
}
