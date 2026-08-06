# The gate opens for a machine that requires more than one selectable NTP source.
#
# `minsources 2` is ordinary fleet configuration — it is what stops a single lying server
# from steering the clock — and it is the one chrony setting the harness's own wiring can
# break. ../lib.nix has to impersonate the machine's real server names, and the obvious way
# to do that is to point them all at the helper node's address; chrony then refuses every
# source slot after the first (NSR_AlreadyInUse: one slot per `server` line, but no two slots
# on one address) and leaves the rest unresolved forever. One usable source cannot satisfy
# `minsources 2`, so `maxerror` never leaves the kernel's 16 s unsynchronized ceiling, the
# §9.4 gate never opens, and every case in the suite fails on a timeout.
#
# clock-gate-nts does not catch that: it leaves minsources at chrony's default of 1, where
# one usable source is enough and the bug is invisible. Nor can nix/tests/eval-checks.nix,
# which only evaluates — the failure is purely at runtime.
#
# So this case asserts on the source table, not just on the gate opening. A regression to
# one-address-for-all names fails on `chronyc activity` naming the unresolved sources, rather
# than as an opaque wait_for_unit timeout with nothing in it to read.
{ pkgs }:
{
  isolate = true;

  # The source table is checked BEFORE the service is waited for, so a regression fails on a
  # named subtest with the unresolved sources in the message rather than on a bare readiness
  # timeout with nothing to read. The readiness wait still happens — just explicitly, below,
  # after the informative assertion.
  #
  # It does not make a regression fail FAST: the preamble's multi-user.target wait already
  # absorbs the gate's whole budget, because a target complements its Wants= with After=
  # (systemd.target(5)) and so orders itself after this service. Only the diagnosis improves.
  waitForService = false;

  machineModules = [
    (
      { lib, ... }:
      {
        services.chrony = {
          enable = true;
          # NTS as well, because that is the combination the fleet runs and the one where a
          # per-name address is least obviously safe: every name has to validate against the
          # single certificate the helper serves, whichever address it was reached on.
          enableNTS = true;
          # mkForce because `servers` is a list and therefore merges — against a consumer's
          # real host module these two would otherwise be appended to that machine's own,
          # and the count this case reasons about would no longer be two.
          servers = lib.mkForce [
            "time1.example.test"
            "time2.example.test"
          ];
          # The point of the case. `extraConfig` is lines, so this appends rather than
          # replaces, which is exactly how a consumer's own module sets it.
          extraConfig = "minsources 2";
        };
      }
    )
  ];

  testScript = ''
    ntp.wait_for_unit("chronyd.service")

    with subtest("minsources 2 really reached chronyd"):
        # Read back from the generated config: if the option stopped taking effect, every
        # assertion below would pass on chrony's default of 1 and prove nothing.
        conf = machine.succeed("systemctl cat chronyd.service | grep -o '/nix/store/[^ ]*chrony.conf'")
        conf = machine.succeed(f"cat {conf.strip()}")
        assert "minsources 2" in conf, f"minsources did not reach chronyd:\n{conf}"

    with subtest("every server name became a distinct usable source"):
        # The regression guard. wait_until_succeeds rather than succeed: chronyd resolves the
        # names shortly after start even with iburst, so a single read can legitimately land
        # before the second name is resolved. What must never happen is it staying that way.
        machine.wait_until_succeeds(
            "chronyc activity | grep -q '^0 sources with unknown address'", timeout=180
        )

        activity = machine.succeed("chronyc activity")
        machine.log(activity)
        online = int(
            next(l for l in activity.splitlines() if l.endswith("sources online")).split()[0]
        )
        # At least minsources actually online, so "resolved" is not mistaken for "usable".
        assert online >= 2, f"fewer than minsources sources are online:\n{activity}"

    with subtest("chrony selected a source, so the gate opened"):
        # The readiness wait the preamble skipped for this case. Reaching past it means the
        # boot gate opened with minsources 2 in force, which needs two selectable sources.
        machine.wait_for_unit("monitoring-platform.service")

        journal = machine.succeed("journalctl -u monitoring-platform.service --no-pager")
        assert "clock synchronized" in journal, f"the gate did not report opening:\n{journal}"

        sources = machine.succeed("chronyc -n sources")
        machine.log(sources)
        assert "^*" in sources or "^+" in sources, (
            f"chrony has no selected source, so the clock was set by something else:\n{sources}"
        )
        # Not asserted: the absence of "Can't synchronise: not enough selectable sources" in
        # chronyd's journal. That is the symptom of the bug this case guards, but chronyd also
        # logs it legitimately in the seconds before the second source comes online, so it is
        # a state to check, not a message to grep.

    with subtest("a gated service is a working service"):
        post_protobuf(sample_batch("/tmp/minsources.pb"))
        assert row_count() == 3
        assert get_json("/healthz")["status"] == "ok"
  '';
}
