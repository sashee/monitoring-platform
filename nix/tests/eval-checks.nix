# Does the harness EVALUATE against a machine that already keeps time its own way?
#
# ./lib.nix has to give the machine under test a reachable time source without fighting
# whatever it already runs, and getting that wrong is not a test failure — it is an
# evaluation error, which no VM test can reach because the VM never gets built. That is
# precisely how a version of this harness that wrote `services.timesyncd.enable = mkForce
# true` next to ntpd's own `mkForce false` shipped: this repo's synthetic machine runs no
# daemon, so nothing here noticed, and only a consumer importing ./lib.nix with a real
# host module would have hit it.
#
# Each entry is a machine module; building this derivation forces every one of them
# through the harness. No VM boots, so it costs seconds rather than minutes.
#
#   nix-build nix -A evalChecks --no-out-link
#
# Deliberately NOT part of `make run-tests`: see the Makefile on why several NixOS machine
# evaluations must not share one nix process. `make eval-checks` runs each in its own.
{
  pkgs,
  stateVersion ? pkgs.lib.trivial.release,
  # Evaluate a single machine instead of all of them, so `make eval-checks` can give each
  # its own short-lived nix process. Six NixOS evaluations in one process is the memory
  # profile the Makefile exists to avoid.
  only ? null,
}:
let
  lib = pkgs.lib;

  # Every daemon ./lib.nix knows about, plus the two shapes that actually matter: no
  # daemon at all (this repo's synthetic machine) and chrony with NTS (the fleet's).
  machines = {
    no-daemon = { };
    chrony = {
      services.chrony.enable = true;
    };
    chrony-nts = {
      services.chrony = {
        enable = true;
        enableNTS = true;
        servers = [ "time1.example.test" ];
      };
    };
    # These three the harness cannot wire, so it must fail with its own assertion message
    # rather than an option collision. Asserted below by matching the message.
    #
    # Keyed by the services.<name> option, not a friendly label: the check below requires
    # the refusal to name the daemon, and that only means something if the name here is
    # the one an operator would grep for.
    ntp = {
      services.ntp.enable = true;
    };
    openntpd = {
      services.openntpd.enable = true;
    };
    ntpd-rs = {
      services.ntpd-rs.enable = true;
    };

    # A consumer that imports the collector module ITSELF, on top of the harness's own import.
    #
    # Every other shape here is already the opposite case — `harnessFor` gives them only
    # ../module.nix, so they prove the harness's import is sufficient. This one covers the risk
    # that flipping `collector` on by default introduced: a consumer that was already importing
    # the module now gets it twice. NixOS keys modules by path and deduplicates, so this must
    # evaluate; if it ever stops, the option declarations are colliding and every such consumer
    # breaks at once.
    collector-preimported = {
      imports = [ ../collector-module.nix ];
    };
  };

  wirable = [
    "no-daemon"
    "chrony"
    "chrony-nts"
    "collector-preimported"
  ];

  # `collector` is deliberately NOT passed: the harness defaults it on and imports the collector
  # module itself, and that default is exactly what a consumer gets. Passing it here would test a
  # configuration nobody deploys and leave the real one unevaluated.
  #
  # Note what that makes every shape below: a consumer whose own modules mention only the
  # receiver, which is the shape the consumer repo actually has.
  harnessFor =
    machine:
    import ./lib.nix {
      inherit pkgs stateVersion;
      machineModules = [
        (
          { ... }:
          # `imports` is merged rather than overwritten, so a shape can bring its own modules —
          # `//` alone would silently drop them, which for a shape whose entire point is an extra
          # import would make the check vacuous.
          (builtins.removeAttrs machine [ "imports" ])
          // {
            imports = [ ../module.nix ] ++ (machine.imports or [ ]);
            system.stateVersion = stateVersion;
          }
        )
      ];
    };

  # Forcing the toplevel drvPath is what actually runs the module system over the merged
  # configuration; anything shallower would not reach the option merge that used to break.
  #
  # unsafeDiscardStringContext is load-bearing: a .drv path carries string context, so
  # interpolating it into the check below would register the whole NixOS system as a build
  # input and *build* six of them. The point here is to evaluate, not to realise — the VM
  # tests are what build systems.
  evaluate =
    name: machine:
    builtins.unsafeDiscardStringContext
      (harnessFor machine).platform.nodes.machine.system.build.toplevel.drvPath;

  selected = if only == null then lib.attrNames machines else [ only ];
  select = names: lib.filter (n: lib.elem n selected) names;

  ok = lib.genAttrs (select wirable) (name: evaluate name machines.${name});

  # The unwirable ones must be refused BY OUR ASSERTION. Checked by reading
  # config.assertions rather than by tryEval on the whole evaluation: tryEval reports only
  # success/failure, so an option collision — precisely the bug this file exists to catch —
  # would look identical to a clean, well-explained refusal.
  rejects = lib.genAttrs (select (lib.subtractLists wirable (lib.attrNames machines))) (
    name:
    let
      failing = lib.filter (a: !a.assertion) (harnessFor machines.${name}).platform.nodes.machine.assertions;
      ours = lib.filter (a: lib.hasInfix "cannot point at its test NTP server" a.message) failing;
    in
    if ours == [ ] then
      throw (
        "nix/tests/lib.nix must refuse a machine running ${name} with its own assertion — "
        + "it cannot point that daemon at the test NTP server, so the clock gate would never "
        + "open. Failing assertions found: ${toString (map (a: a.message) failing)}"
      )
    else if !(lib.hasInfix name (lib.head ours).message) then
      throw "the refusal for ${name} does not name the daemon: ${(lib.head ours).message}"
    else
      "rejected by our own assertion"
  );
in
pkgs.runCommand "monitoring-platform-eval-checks${lib.optionalString (only != null) "-${only}"}"
  {
    passthru = {
      inherit ok rejects;
      names = lib.attrNames machines;
    };
  }
  ''
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (n: d: "echo 'ok: ${n} -> ${d}'") ok)}
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (n: v: "echo '${v}: ${n}'") rejects)}
    touch $out
  ''
