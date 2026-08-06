# Generic NixOS-VM test harness for the monitoring platform.
#
# The machine under test is an INPUT — this file knows nothing about how the
# machine is assembled. That is the whole point: the hardening in module.nix
# (RestrictAddressFamilies, SystemCallFilter, ProtectSystem=strict) can only be
# validated against the systemd the target actually runs, because sandbox semantics
# are version-dependent. A VM built from this repo's own pinned channel would
# validate them against a systemd nobody deploys (SPEC.md §11.1).
#
# An external repo tests the service against its OWN configuration by importing
# this file with its real host module:
#
#   import "${monitoring-platform}/nix/tests/lib.nix" {
#     inherit pkgs;
#     machineModules = [ self.nixosModules.common-desktop ];
#   }
#   # => { platform = <shared VM>; <isolated-case> = <own VM>; ... }
#
# Two execution models (a case picks one):
#   - lightweight (default): a subtest on ONE shared VM, booted once.
#   - isolated (`isolate = true`): its own VM, with optional extra `machineModules`
#     layered on the base machine (for cases that must change configuration).
#
# Every test is a two-node network: the machine under test plus ./ntp-node.nix. The
# §9.4 clock gate refuses to start the service until the kernel's clock error estimate
# is small, and a VM with no time source never gets there — so the harness supplies a
# real NTP server rather than switching the gate off, which would leave the production
# configuration untested in precisely the tests meant to validate it.
{
  pkgs,
  machineModules,
  # The client group. A member can reach the socket; a non-member must not.
  clientUser ? "mp-client",
  # Applied to the helper node too, so the two cannot drift.
  stateVersion ? pkgs.lib.trivial.release,
}:
let
  lib = pkgs.lib;
  mkCert = import ./test-cert.nix { inherit pkgs; };

  # Layered onto the machine under test. The service module creates its own user
  # and group; this adds an unprivileged account IN that group plus one outside it,
  # so the socket's access control is testable rather than assumed.
  testClients =
    { config, ... }:
    {
      services.monitoring-platform.enable = true;

      # A VM boots far slower than a real host — several minutes under aarch64 TCG — and the
      # gate blocks the boot until the clock is good, so the production 300 s budget has
      # already proved too tight there once. Raising it is close to free: the gate returns as
      # soon as three consecutive polls are good, so a healthy boot is unaffected and only the
      # give-up path lengthens. 120 polls x 5 s = 600 s, which keeps the derived
      # TimeoutStartSec (720 s) inside the test driver's 900 s wait_for_unit default.
      #
      # mkDefault so clock-gate can still force it down: that case needs a short budget,
      # because watching the gate give up is the point of it.
      services.monitoring-platform.clockGate.maxPolls = lib.mkDefault 120;

      users.users.${clientUser} = {
        isNormalUser = true;
        extraGroups = [ config.services.monitoring-platform.group ];
      };
      users.users.mp-outsider = {
        isNormalUser = true;
      };

      # curl for the HTTP-over-unix-socket probes, sqlite for inspecting rows
      # independently of the read API, and the package itself for mp-make-sample.
      environment.systemPackages = [
        pkgs.curl
        pkgs.sqlite
        config.services.monitoring-platform.package
      ];
    };

  ntpServer = "ntp-server";

  # Daemons that disable systemd-timesyncd themselves. Naming them is the whole point of
  # the list: if the machine already runs one, timesyncd must be left ALONE. Writing
  # `mkForce true` next to their `mkForce false` is not a merge, it is an evaluation
  # error — which is what a machine running ntpd or openntpd used to hit here.
  ntpDaemons = [
    "chrony"
    "ntp"
    "openntpd"
    "ntpd-rs"
  ];
  daemonsOn = machine: lib.filter (d: machine.services.${d}.enable) ntpDaemons;

  # The server names a chrony machine dials. Read off `services.chrony.servers` rather than
  # guessed, so the certificate's SANs, the /etc/hosts override and the helper's addresses
  # are all derived from the same value chronyd itself uses and cannot drift from one another.
  serversOf = machine: lib.optionals machine.services.chrony.enable machine.services.chrony.servers;

  # ...those it dials over NTS specifically, which are the ones the certificate must name.
  ntsNamesOf = machine: lib.optionals machine.services.chrony.enableNTS (serversOf machine);

  # One helper address per server name, and the reason the names cannot simply all point at
  # the helper's single address.
  #
  # chrony allocates a source slot per `server` line and resolves each slot's name
  # separately. A slot whose name resolves to an address another slot already holds is
  # REFUSED — NSR_AlreadyInUse in chrony's ntp_sources.c — and left permanently unresolved;
  # `chronyc activity` counts it under "sources with unknown address". So N names on one
  # address yield exactly ONE usable source. That is invisible at chrony's default
  # `minsources 1` and fatal above it: the machine can never select a source, `maxerror`
  # stays at the kernel's 16 s unsynchronized ceiling, the §9.4 gate never opens, and every
  # case fails on a timeout. A fleet that sets `minsources 2` is the ordinary case, not an
  # exotic one, so the harness has to support it.
  #
  # Distinct addresses on the SAME chronyd are enough — it binds every address and the
  # helper sets `allow all` — so this needs no extra nodes. One helper VM per name would be
  # unaffordable under aarch64 TCG.
  aliasAddressesFor =
    ntpNode: machine:
    let
      # Derived from the helper's own address rather than a hardcoded subnet. Safe to read
      # here while also extending that same node's address list: the test framework computes
      # primaryIPAddress from its own local binding, not from the merged
      # networking.interfaces (nixos/lib/testing/network.nix), so this cannot recurse.
      prefix = lib.concatStringsSep "." (
        lib.take 3 (lib.splitString "." ntpNode.networking.primaryIPAddress)
      );
    in
    # Based at .200: the framework numbers nodes from 1 upwards and this harness has two, so
    # an alias can never collide with a node's own address.
    lib.imap0 (i: _: "${prefix}.${toString (200 + i)}") (serversOf machine);

  ntsCertFor = machine: mkCert {
    name = "mp-nts";
    sans = ntsNamesOf machine;
  };

  # Gives the machine under test a time source without touching how it keeps time.
  #
  # For chrony the configuration is left completely unmodified — the real server names,
  # over NTS-KE, validating a real certificate. Only two things are injected: the names
  # resolve to the helper node, and the helper's CA is trusted. That way the production
  # config is what runs, rather than a local-NTP substitute nobody deploys.
  timeClient =
    { config, nodes, ... }:
    let
      running = daemonsOn config;
      unwirable = lib.subtractLists [ "chrony" ] running;
      ntsNames = ntsNamesOf config;
    in
    {
      # No daemon of its own — the case for this repo's synthetic machine. qemu-vm.nix
      # disables timesyncd on every test node at normal priority, so restoring it needs
      # mkForce rather than a plain `true`.
      services.timesyncd = lib.mkIf (running == [ ]) {
        enable = lib.mkForce true;
        servers = lib.mkForce [ ntpServer ];
        # The nixos pool is unreachable from a test net; without this the client would keep
        # retrying it and take much longer to settle on the one server that does answer.
        fallbackServers = lib.mkForce [ ];

        # Cap the retry backoff. Two VMs booting under aarch64 TCG are slow enough that the
        # helper's chronyd is not listening until ~2 minutes in (udev alone took 30 s in CI),
        # so timesyncd's first attempts miss. Its poll interval then doubles from 32 s toward
        # PollIntervalMaxSec (2048 s by default), which turned one missed attempt into first
        # contact at t=469 s — past the clock gate's budget, failing the boot and cancelling
        # every unit that Requires= the service. 16 s is the lowest PollIntervalMinSec systemd
        # accepts, and the max must exceed the min, so these are the tightest legal values.
        #
        # Only needed on this branch: the chrony branch leaves the machine's own configuration
        # alone, and nixpkgs' `iburst` default already makes chrony retry promptly.
        extraConfig = ''
          PollIntervalMinSec=16
          PollIntervalMaxSec=32
        '';
      };

      # Resolution, not configuration: chronyd still dials exactly what the host config
      # told it to. One name per address, never several on one — see aliasAddressesFor.
      networking.hosts = lib.mkIf config.services.chrony.enable (
        lib.listToAttrs (
          lib.zipListsWith (address: name: lib.nameValuePair address [ name ])
            (aliasAddressesFor nodes.ntp config)
            (serversOf config)
        )
      );

      # A list, so this adds to whatever CAs the consumer already injects.
      security.pki.certificateFiles = lib.mkIf (ntsNames != [ ]) [ (ntsCertFor config).caFile ];

      assertions = [
        {
          assertion = unwirable == [ ];
          message =
            "monitoring-platform test harness: the machine under test runs "
            + "${lib.concatStringsSep ", " unwirable}, which this harness cannot point at its "
            + "test NTP server — so the §9.4 clock gate would never open and every case would "
            + "fail on a five-minute timeout. Only chrony (with or without NTS) and "
            + "systemd-timesyncd are wired up. Extend ntpDaemons handling in "
            + "nix/tests/lib.nix, or disable services.monitoring-platform.clockGate for tests.";
        }
      ];
    };

  # The helper node, built to match whatever the machine expects to talk to: a plain NTP
  # server, or a real NTS one when the machine is an NTS client. `mkCert` is pure, so the
  # certificate here is the same store path as the CA trusted above.
  timeSourceNode =
    { nodes, ... }:
    let
      ntsNames = ntsNamesOf nodes.machine;
    in
    {
      imports = [
        (import ./ntp-node.nix {
          hostName = ntpServer;
          inherit stateVersion;
          # The other half of timeClient's one-name-per-address mapping. Both sides call the
          # same function on the same server list, so they cannot drift apart.
          extraAddresses = aliasAddressesFor nodes.ntp nodes.machine;
          nts =
            if ntsNames == [ ] then
              null
            else
              {
                inherit (ntsCertFor nodes.machine) certFile keyFile;
              };
        })
      ];
    };

  # Python preamble. Exposes the paths and helpers every case uses, so a case body
  # is only its assertions.
  #
  # `waitForService` is an opt-out because one case — clock-gate — asserts that the
  # unit does NOT come up, so waiting for it here would hang instead of failing.
  preamble =
    { waitForService }:
    ''
      import json

      SOCKET = "/run/monitoring-platform/monitoring-platform.sock"
      DB = "/var/lib/monitoring-platform/measurements.db"
      CLIENT = "${clientUser}"

      # Two nodes, so the driver no longer auto-starts on first use.
      start_all()

      machine.wait_for_unit("multi-user.target")
    ''
    + lib.optionalString waitForService ''
      # Type=notify, so `active` means migrations ran AND the socket is accepting.
      # Anything asserted after this point cannot be racing startup. This also waits out
      # the §9.4 clock gate, which needs the ntp node up and a few consecutive good polls.
      machine.wait_for_unit("monitoring-platform.service")
    ''
    + ''

      def curl_raw(args, user=CLIENT, succeed=True):
          # No --fail-with-body: for probes that inspect the status themselves via -w.
          # Run as a group member by default: the socket is only reachable through a
          # 0750 group-owned directory, so root-only probes would not prove access
          # works for the clients that matter.
          cmd = f"su - {user} -c " + repr(f"curl -sS --unix-socket {SOCKET} {args}")
          return (machine.succeed if succeed else machine.fail)(cmd)

      def curl(args, user=CLIENT, succeed=True):
          # --fail-with-body, so a 4xx/5xx is a non-zero exit and therefore a test
          # failure unless succeed=False.
          cmd = f"su - {user} -c " + repr(f"curl -sS --fail-with-body --unix-socket {SOCKET} {args}")
          return (machine.succeed if succeed else machine.fail)(cmd)

      def get_json(path, user=CLIENT):
          return json.loads(curl(f"http://localhost{path}", user=user))

      def post_protobuf(local_file, extra=""):
          return curl(
              f"-X POST -H 'Content-Type: application/x-protobuf' {extra} "
              f"--data-binary @{local_file} http://localhost/v1/logs"
          )

      def row_count():
          # Read-only, via a separate connection, so this is independent of the API.
          out = machine.succeed(f"sqlite3 'file:{DB}?mode=ro' 'select count(*) from measurement;'")
          return int(out.strip())

      def sample_batch(dest="/tmp/sample-logs.pb"):
          # Generated by a binary from the package under test, so the payload is built
          # by the same code the service parses — no hand-encoded protobuf in the test.
          machine.succeed(f"mp-make-sample {dest}")
          return dest

      # The gate's own check, run out of band with a one-shot budget so it answers
      # immediately instead of waiting: the same daemon-agnostic adjtimex(2) read the service
      # gates on (SPEC.md §9.4), at the same default threshold. Lets a case assert on the
      # clock without knowing which NTP client the machine under test runs.
      CLOCK_OK = "monitoring-platform wait-for-clock --max-polls 1 --consecutive 1"

      def time_sync_unit():
          # Which client keeps the machine's time is the MACHINE's property, not the
          # harness's: timeClient in ../lib.nix only enables timesyncd when the machine
          # brings no daemon of its own, so a consumer's real host module usually means
          # chrony instead. Asked of systemd at runtime because a case's testScript is a
          # static string with no access to the evaluated machine configuration.
          for unit in ["chronyd.service", "systemd-timesyncd.service"]:
              state = machine.succeed(f"systemctl show {unit} -p LoadState --value").strip()
              if state == "loaded":
                  return unit
          raise Exception("the machine under test runs no time-sync client this harness drives")
    '';

  # One VM test on the base machine plus any per-case modules and helper nodes.
  mkTest =
    {
      name,
      testScript,
      extraModules ? [ ],
      ntpNodeModules ? [ ],
      waitForService ? true,
    }:
    pkgs.testers.runNixOSTest {
      inherit name;
      # Don't pin nixpkgs.* read-only on the nodes, so a consumer's machineModules
      # may set nixpkgs.config / overlays without a types.unique collision.
      node.pkgsReadOnly = false;
      nodes = {
        machine = {
          imports = machineModules ++ [ testClients timeClient ] ++ extraModules;
        };
        # Layered onto, never replaced: a case that needs the time source to behave
        # differently (clock-gate holds chronyd down) still gets the same node otherwise.
        ntp = {
          imports = [ timeSourceNode ] ++ ntpNodeModules;
        };
      };
      testScript = preamble { inherit waitForService; } + testScript;
    };

  # Each case is
  #   { testScript; isolate ? false; machineModules ? []; ntpNodeModules ? [];
  #     waitForService ? true; }
  # and is independent of how the machine under test was built. `ntpNodeModules` and
  # `waitForService` only apply to isolated cases — a lightweight case shares one VM with
  # the others, so it can neither reconfigure the time source nor skip the readiness wait.
  cases = {
    readiness = import ./cases/readiness.nix { inherit pkgs; };
    ingest = import ./cases/ingest.nix { inherit pkgs; };
    socket-access = import ./cases/socket-access.nix { inherit pkgs; };
    hardening = import ./cases/hardening.nix { inherit pkgs; };
    restart = import ./cases/restart.nix { inherit pkgs; };
    ordering = import ./cases/ordering.nix { inherit pkgs; };
    crash-recovery = import ./cases/crash-recovery.nix { inherit pkgs; };
    clock-gate = import ./cases/clock-gate.nix { inherit pkgs; };
    clock-gate-nts = import ./cases/clock-gate-nts.nix { inherit pkgs; };
    clock-gate-minsources = import ./cases/clock-gate-minsources.nix { inherit pkgs; };
  };

  isolated = lib.filterAttrs (_: c: c.isolate or false) cases;
  shared = lib.filterAttrs (_: c: !(c.isolate or false)) cases;

  # Wrap a lightweight case as an indented `with subtest(...)` block.
  subtestBlock =
    name: case:
    ''with subtest("${name}"):'' + "\n    " + builtins.replaceStrings [ "\n" ] [ "\n    " ] case.testScript;
  sharedBody = lib.concatStringsSep "\n\n" (lib.mapAttrsToList subtestBlock shared);

  isolatedTests = lib.mapAttrs (
    name: c:
    mkTest {
      name = "monitoring-platform-${name}";
      testScript = c.testScript;
      extraModules = c.machineModules or [ ];
      ntpNodeModules = c.ntpNodeModules or [ ];
      waitForService = c.waitForService or true;
    }
  ) isolated;
in
# `platform` is the reserved key for the shared VM running all lightweight cases as
# subtests; plus one entry per isolated case.
isolatedTests
// lib.optionalAttrs (shared != { }) {
  platform = mkTest {
    name = "monitoring-platform";
    testScript = sharedBody;
  };
}
