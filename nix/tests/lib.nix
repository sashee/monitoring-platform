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
# Because that machine is the consumer's real one, it usually runs a PRODUCER of its
# own — the point of the receiver is that something writes to it. Those rows arrive on
# the same socket, into the same table, at times this file does not control. So every
# assertion here is scoped to the batches the harness itself posted, keyed on the
# resource attribute mp-make-sample stamps (SAMPLE_DEVICE_ID below); `row_count` and
# `sample_rows` are the only sanctioned ways to count, and a case must not reach past
# them to a bare `select count(*)`.
#
# This is not hypothetical. sashee/nixos-test runs the suite against a Raspberry Pi 5
# config whose systemMetrics timer posts host metrics every 15 minutes; unscoped, its
# aarch64 crash-recovery job failed with "read API returned 12 of 6 rows" when a host
# batch landed in the 375 ms between the sqlite count and the read-API call. x86 only
# escaped because the case finishes before the timer's first fire. See
# ./cases/foreign-producer.nix, which pins the property directly.
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
  # Also exercise the clock-correcting collector (nix/collector-module.nix).
  #
  # Opt-in, and off by default, because an unknown option is an evaluation error however it is
  # guarded: a consumer whose machineModules import only the receiver's module must keep working
  # unchanged. Turning this on requires importing ../collector-module.nix into the machine, which
  # is what nix/tests/default.nix does.
  collector ? false,
}:
let
  lib = pkgs.lib;
  mkCert = import ./test-cert.nix { inherit pkgs; };

  # Only ever added to the module list when `collector` is set, so the options it names need not
  # exist otherwise.
  collectorClients =
    { config, ... }:
    {
      services.mp-collector.enable = true;
      # OFF by default across the harness. The health event is a real measurement and lands in
      # the same table as everything else, so leaving it on would inject a row into every case
      # on a sixty-second timer — which broke `crash-recovery`'s exact count the first time this
      # module was wired in. A case that wants to test §9 turns it back on for its own VM.
      services.mp-collector.healthIntervalSecs = lib.mkDefault 0;
      # The client posts through the collector, so it needs to reach that socket too.
      users.users.${clientUser}.extraGroups = [ config.services.mp-collector.group ];
      environment.systemPackages = [ config.services.mp-collector.package ];
    };

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
      import shlex

      SOCKET = "/run/monitoring-platform/monitoring-platform.sock"
      DB = "/var/lib/monitoring-platform/measurements.db"
      CLIENT = "${clientUser}"
      COLLECTOR = "/run/mp-collector/mp-collector.sock"
      COLLECTOR_STATE = "/var/lib/mp-collector"

      # What distinguishes this harness's rows from any producer the machine under test
      # runs of its own (see the header). mp-make-sample stamps device.id as a resource
      # attribute; otlp/convert.rs flattens it into the attributes column under the
      # resource.attributes. prefix, and the read API exposes it as attr.<that key>.
      # The literal is pinned on the Rust side by a unit test in otlp/test_support.rs,
      # so it cannot drift out from under this file silently.
      SAMPLE_DEVICE_ID = "dev-7"
      SAMPLE_ATTR = "resource.attributes.device.id"

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

      # `su -c` runs its argument through a second shell, so a command reaches a shell
      # TWICE and has to survive both. shlex.quote rather than repr for the outer level:
      # repr is Python quoting that merely resembles shell quoting, and switches to
      # double quotes when the string contains one — which would start interpolating.
      def _as_user(user, command):
          return f"su - {user} -c " + shlex.quote(command)

      def curl_raw(args, user=CLIENT, succeed=True):
          # No --fail-with-body: for probes that inspect the status themselves via -w.
          # Run as a group member by default: the socket is only reachable through a
          # 0750 group-owned directory, so root-only probes would not prove access
          # works for the clients that matter.
          cmd = _as_user(user, f"curl -sS --unix-socket {SOCKET} {args}")
          return (machine.succeed if succeed else machine.fail)(cmd)

      def curl(args, user=CLIENT, succeed=True):
          # --fail-with-body, so a 4xx/5xx is a non-zero exit and therefore a test
          # failure unless succeed=False.
          cmd = _as_user(user, f"curl -sS --fail-with-body --unix-socket {SOCKET} {args}")
          return (machine.succeed if succeed else machine.fail)(cmd)

      def get_json(path, user=CLIENT):
          # The URL is quoted for that inner shell, because `&` between query parameters
          # is otherwise a background operator: it truncates the URL at the first
          # parameter and runs the rest as a command. That failed SILENTLY for as long as
          # the trailing fragment happened to look like a variable assignment — a
          # `?type=gps&limit=100` was requesting type=gps with no limit at all, and still
          # exiting 0.
          return json.loads(curl(shlex.quote(f"http://localhost{path}"), user=user))

      def post_protobuf(local_file, extra=""):
          return curl(
              f"-X POST -H 'Content-Type: application/x-protobuf' {extra} "
              f"--data-binary @{local_file} http://localhost/v1/logs"
          )

      def row_count(device_id=SAMPLE_DEVICE_ID):
          # Read-only, via a separate connection, so this is independent of the API.
          #
          # Scoped to one writer by default, because the machine under test may be
          # running a producer of its own (see the header). device_id=None counts every
          # row regardless of origin — only foreign-producer.nix has a use for that.
          #
          # Quoting matters more than it looks: a wrong JSON path makes json_extract
          # return NULL rather than raise, so a typo here reads as "zero rows" instead
          # of as an error. shlex.quote rather than hand-nested quotes for that reason.
          if device_id is None:
              sql = "select count(*) from measurement;"
          else:
              sql = (
                  "select count(*) from measurement where "
                  f"json_extract(attributes, '$.\"{SAMPLE_ATTR}\"') = '{device_id}';"
              )
          out = machine.succeed(
              "sqlite3 " + shlex.quote(f"file:{DB}?mode=ro") + " " + shlex.quote(sql)
          )
          return int(out.strip())

      def sample_rows(extra=""):
          # The read-API counterpart of row_count: only the rows this harness posted.
          # limit=100 comfortably exceeds any case's batch count, so a case never has to
          # pick one — and cannot accidentally cap itself the way an earlier limit=10
          # compared against a growing count did.
          q = f"limit=100&attr.{SAMPLE_ATTR}={SAMPLE_DEVICE_ID}"
          if extra:
              q += f"&{extra}"
          return get_json(f"/v1/measurements?{q}")["measurements"]

      def sample_scope(device_id=SAMPLE_DEVICE_ID):
          # The SQL predicate row_count scopes on, for the collector cases that need a
          # `where` of their own and would otherwise reach past the helpers to a bare
          # count (see the header). Returns a bare condition, to be `and`-ed in.
          return f"""json_extract(attributes, '$.\"{SAMPLE_ATTR}\"') = '{device_id}'"""

      def collector_health():
          # The collector answers JSON on its own socket: clock state, epoch count, buffer depth.
          out = machine.succeed(
              f"curl -sS --fail-with-body --unix-socket {COLLECTOR} http://localhost/healthz"
          )
          return json.loads(out)

      def post_through_collector(user=CLIENT, succeed=True, device_id=SAMPLE_DEVICE_ID):
          # ONE process both stamps and sends, which is the whole point. Frame resolution bounds
          # an event by [sender_started, received], so a batch written to a file and posted later
          # by curl is correctly classified `passthrough` — curl started after those timestamps
          # were taken. Testing the correction path needs a sender that produced them.
          #
          # The collector corrects the batch in place (correct.rs) rather than rebuilding it, so
          # device.id survives the hop and these rows stay scoped like every other.
          cmd = _as_user(user, f"mp-make-sample --device-id {device_id} --post {COLLECTOR}")
          return (machine.succeed if succeed else machine.fail)(cmd)

      def clock_attributes(kind):
          # The mp.clock.* attributes as they landed in the receiver's database. Read straight
          # out of SQLite rather than through the read API, so this is independent of both.
          #
          # Scoped like row_count: `limit 1` over an unscoped table hands back whichever writer
          # was most recent, so a foreign producer would not just add noise here — it would make
          # every assertion below read the wrong row.
          sql = (
              f"select attributes from measurement where type = '{kind}' "
              f"and {sample_scope()} order by processed_time desc limit 1;"
          )
          out = machine.succeed(
              "sqlite3 " + shlex.quote(f"file:{DB}?mode=ro") + " " + shlex.quote(sql)
          ).strip()
          if not out:
              raise Exception(f"no {kind} measurement was stored")
          return {
              k.removeprefix("record.attributes.mp.clock."): v
              for k, v in json.loads(out).items()
              if k.startswith("record.attributes.mp.clock.")
          }

      def sample_batch(dest="/tmp/sample-logs.pb", device_id=SAMPLE_DEVICE_ID):
          # Generated by a binary from the package under test, so the payload is built
          # by the same code the service parses — no hand-encoded protobuf in the test.
          # device_id is what lets a case impersonate a second, foreign writer.
          machine.succeed(f"mp-make-sample --device-id {device_id} {dest}")
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
          imports =
            machineModules
            ++ [ testClients timeClient ]
            ++ lib.optional collector collectorClients
            ++ extraModules;
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
    foreign-producer = import ./cases/foreign-producer.nix { inherit pkgs; };
    clock-gate = import ./cases/clock-gate.nix { inherit pkgs; };
    clock-gate-nts = import ./cases/clock-gate-nts.nix { inherit pkgs; };
    clock-gate-minsources = import ./cases/clock-gate-minsources.nix { inherit pkgs; };
  }
  // lib.optionalAttrs collector {
    collector = import ./cases/collector.nix { inherit pkgs; };
    collector-clock = import ./cases/collector-clock.nix { inherit pkgs; };
    collector-step = import ./cases/collector-step.nix { inherit pkgs; };
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
