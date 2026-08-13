# The boot gate is fail-closed, and both directions are driven by a REAL time source.
#
# Every other case runs with the gate satisfied by ../ntp-node.nix, which proves it opens
# but never that it closes. This case takes the same node and holds chronyd down at boot,
# so "no working NTP" is the machine's genuine state — the kernel parks `maxerror` at its
# 16 s unsynchronized ceiling with nothing faking it, which is exactly the Raspberry Pi
# cold-boot case the gate exists for. Starting chronyd is then what flips it.
#
# The threshold under test is the production default (5 s), deliberately: a client that has
# just synchronized drives `maxerror` far below it, and it then grows at only 500 µs/s, so a
# freshly-synced node has hours of headroom and this needs no relaxed threshold to pass.
#
# Nothing here is specific to one NTP client. Which one the machine runs depends on the
# machine under test — timesyncd for this repo's synthetic one, chrony for a consumer's real
# host module — so the transition is driven through `time_sync_unit()` and observed through
# the gate's own daemon-agnostic check rather than through timesyncd's marker file.
#
# Isolated because it must watch the unit fail and restart, which would perturb every
# lightweight case sharing a VM.
{ pkgs }:
{
  isolate = true;

  # The whole point: assert the unit does NOT come up. The shared preamble's readiness
  # wait would hang here rather than fail.
  waitForService = false;

  machineModules = [
    (
      { lib, ... }:
      {
        services.monitoring-platform.clockGate = {
          # Production threshold and hysteresis (3 consecutive good polls); only the budget
          # is shortened, so a closed gate gives up in ~10 s instead of the production
          # 5 min. 5 polls rather than exactly 3 leaves slack, so an open gate does not have
          # to succeed on precisely its last attempt.
          maxPolls = 5;
          pollIntervalSecs = 2;
        };

        # The retry INTERVAL is not what this case is about — that a retry happens at all
        # is. 60 s of real waiting per cycle would only make the test slow.
        systemd.services.monitoring-platform.serviceConfig.RestartSec = lib.mkForce "2s";
      }
    )
  ];

  # Layered onto the harness's own time source rather than replacing it, so the node stays
  # identical to every other test's except for the one property this case needs: chronyd
  # is not started at boot, which is what makes "no working NTP" the machine's genuine
  # state instead of a simulated one.
  ntpNodeModules = [
    ({ lib, ... }: { systemd.services.chronyd.wantedBy = lib.mkForce [ ]; })
  ];

  testScript = ''
    UNIT = time_sync_unit()

    ntp.wait_for_unit("multi-user.target")

    with subtest("the gate is actually wired in"):
        # Read back from systemd rather than trusting the module: a renamed option would
        # otherwise leave the service ungated and every assertion below vacuous.
        pre = machine.succeed(
            "systemctl show monitoring-platform.service -p ExecStartPre --value"
        )
        assert "wait-for-clock" in pre, f"no clock gate on the unit: {pre!r}"
        # No "-" prefix, i.e. ignore_errors must be off, or a failed gate would be skipped
        # over and the service would start with a clock nobody checked.
        assert "ignore_errors=no" in pre, f"the gate's failure is being ignored: {pre!r}"

        # TimeoutStartSec must exceed the gate's own budget, or systemd kills the wait
        # mid-flight and the failure is accidental rather than deliberate. Asserted
        # behaviourally below — the journal must carry the gate's own verdict and not
        # systemd's "Start operation timed out" — rather than by parsing the duration,
        # which systemctl renders as prose ("2min 10s").

    def nrestarts():
        return int(
            machine.succeed(
                "systemctl show monitoring-platform.service -p NRestarts --value"
            ).strip()
        )

    with subtest("no working NTP: the unit does not start"):
        # Nothing here fakes a bad clock — the helper's chronyd is simply not running, so the
        # kernel's estimate sits at its unsynchronized ceiling. Asserted with the gate's own
        # check, which holds whichever client the machine keeps time with.
        machine.fail(CLOCK_OK)

        # Wait on the gate's own verdict rather than on unit state: the boot-time start job
        # is already in flight, so polling `is-active` could catch it mid-wait and prove
        # nothing. The message is the deterministic edge.
        machine.wait_until_succeeds(
            "journalctl -u monitoring-platform.service --no-pager | grep -q 'refusing to start'",
            timeout=120,
        )
        machine.fail("systemctl is-active --quiet monitoring-platform.service")

        # Reported, not just refused: the operator needs the measured number to tell "no NTP
        # yet" from "the threshold is set too tight".
        journal = machine.succeed("journalctl -u monitoring-platform.service --no-pager")
        assert "clock_error_us" in journal, f"the clock error was not logged:\n{journal}"

        # The gate reached its own conclusion rather than being cut short: TimeoutStartSec
        # is derived from the poll budget precisely so systemd does not kill the wait.
        assert "Start operation timed out" not in journal, (
            f"systemd killed the gate mid-wait; TimeoutStartSec is too short:\n{journal}"
        )

        # And the gate really did block startup rather than the service failing later:
        # nothing bound the socket and no database was created.
        machine.fail(f"test -e {SOCKET}")
        machine.fail(f"test -e {DB}")

    with subtest("Restart=on-failure retries an ExecStartPre failure"):
        # The property the whole fail-closed design leans on: a Pi that boots without a
        # network must keep retrying rather than needing an operator. Also proves
        # StartLimitIntervalSec=0 is not quietly giving up after a handful of attempts.
        # RestartSec is forced to 2 s on this machine, so a cycle is seconds not a minute.
        before = nrestarts()
        machine.wait_until_succeeds(
            f"test $(systemctl show monitoring-platform.service -p NRestarts --value) -gt {before}",
            timeout=120,
        )
        # Sampled with wait_until_succeeds rather than asserted outright: the unit cycles
        # through `activating` between attempts, so a bare read can land mid-flight.
        machine.wait_until_succeeds(
            "test \"$(systemctl show monitoring-platform.service -p Result --value)\" = exit-code",
            timeout=120,
        )

    with subtest("NTP comes up: the gate opens and the service starts"):
        ntp.succeed("systemctl start chronyd.service")
        ntp.wait_for_unit("chronyd.service")

        # Restart the machine's own client rather than waiting out its backoff: a fresh start
        # re-polls immediately — timesyncd clears its RuntimeDirectory marker, chrony bursts
        # again — instead of drifting toward maxpoll after the attempts that missed while the
        # helper was down. A clean edge trigger either way.
        machine.succeed(f"systemctl restart {UNIT}")
        machine.wait_until_succeeds(CLOCK_OK, timeout=180)

        # Don't wait out RestartSec=60; drive the retry directly.
        machine.succeed("systemctl restart monitoring-platform.service", timeout=120)
        machine.wait_for_unit("monitoring-platform.service")

        # The receiver refuses unauthenticated requests, and this case skipped the preamble's
        # readiness wait, so the key is issued here instead (SPEC.md §13).
        authenticate()

        journal = machine.succeed("journalctl -u monitoring-platform.service --no-pager")
        assert "clock synchronized" in journal, f"the gate did not report opening:\n{journal}"

    with subtest("a gated service is a working service"):
        # The gate must not have left anything half-initialised: full ingest round trip.
        post_protobuf(sample_batch("/tmp/gated.pb"))
        assert row_count() == 3
        assert get_json("/healthz")["status"] == "ok"

        # adjtimex(2) ran inside the unit's sandbox, so a filter that still blocked @clock
        # would have shown up as a SIGSYS kill rather than a clean start.
        journal = machine.succeed("journalctl -u monitoring-platform.service --no-pager")
        for marker in ["seccomp", "SIGSYS", "signal=SYS"]:
            assert marker not in journal, (
                f"found {marker!r} in the journal — the sandbox is denying the clock read:\n"
                f"{journal}"
            )
  '';
}
