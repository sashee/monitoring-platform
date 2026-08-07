# The cases that need the clock to actually misbehave (design §4.3, §4.6, §8.1, §8.4).
#
# Isolated, because all three change the machine's relationship with time: one holds the time
# source down at boot, one steps the clock out from under a running collector, and one plants a
# previous boot's spool. Any of them would perturb every lightweight case sharing a VM.
#
# Nothing here simulates a *reading*. The unsynchronized state is the machine's genuine one —
# chronyd is simply not started, exactly as in `clock-gate` — and the step is a real
# `clock_settime`, so the `TFD_TIMER_CANCEL_ON_SET` path runs for real rather than being asserted
# about. That is the one thing the Rust tests structurally cannot reach.
#
# Numeric conditions are polled with the driver's own `retry` rather than with a shell pipeline.
# A `''`-quoted Nix string does not process `\"`, so an embedded `python3 -c '...["k"]...'` arrives
# at the shell with its backslashes intact and fails to parse — silently, as a command that never
# succeeds, which is indistinguishable from the condition never becoming true.
{ pkgs }:
{
  isolate = true;

  # The receiver's own gate would refuse to start on this machine, and the collector is the thing
  # under test. Waiting for the receiver here would hang before the first assertion.
  waitForService = false;

  machineModules = [
    (
      { lib, ... }:
      {
        # Short enough to watch the timeout fire, instead of waiting out the production five
        # minutes. The behaviour under test is that it fires at all and ships marked.
        services.mp-collector.bufferTimeoutSecs = 20;

        # §9 self-metrics on, and often. The harness turns them off everywhere else because they
        # are real rows on a timer and would perturb any case counting them — which is exactly how
        # `crash-recovery` failed the first time the collector was wired in. This case owns its
        # own VM, so it is the one that can afford to check they exist.
        services.mp-collector.healthIntervalSecs = lib.mkForce 5;

        # The receiver must be able to come up *after* the clock is fixed, without an operator.
        systemd.services.monitoring-platform.serviceConfig.RestartSec = lib.mkForce "2s";
        services.monitoring-platform.clockGate = {
          maxPolls = 5;
          pollIntervalSecs = 2;
        };
      }
    )
  ];

  # Layered onto the harness's own time source rather than replacing it, so "no working NTP" is
  # the machine's genuine state and starting chronyd is what changes it.
  ntpNodeModules = [
    ({ lib, ... }: { systemd.services.chronyd.wantedBy = lib.mkForce [ ]; })
  ];

  testScript = ''
    UNIT = time_sync_unit()
    ntp.wait_for_unit("multi-user.target")

    def buffered():
        return collector_health()["buffer"]["records"]

    def uncertain_rows():
        out = machine.succeed(
            f"""sqlite3 'file:{DB}?mode=ro' "select count(*) from measurement """
            f"""where attributes like '%mp.clock.uncertain%';" """
        )
        return int(out.strip())

    with subtest("the collector starts even though the clock is unusable"):
        # The inverse of SPEC.md §9.4, and the reason these are two units. The receiver refuses to
        # start here; the collector MUST start, because the window it exists to cover is exactly
        # the one where the clock is wrong.
        machine.wait_for_unit("mp-collector.service")
        machine.fail(CLOCK_OK)
        machine.fail("systemctl is-active --quiet monitoring-platform.service")

        health = collector_health()
        assert not health["clock"]["ever_synchronized"], (
            f"nothing has disciplined this clock, so nothing may claim it is good: {health}"
        )
        # The §9 signal that separates "no time daemon is running here" — a configuration problem
        # an operator can fix — from "the network is down", which is a different conversation.
        # Readable at this point only because it is on /healthz: no health event has been emitted
        # yet, and none can be until the clock is good.
        assert health["clock"]["disciplined"] is False, health

    with subtest("the pre-collector window was reconstructed from journald"):
        # §4.2. There is no persisted table on a first boot, so the backfill is necessarily where
        # the starting history came from — which the startup log line names explicitly. Worth
        # asserting rather than assuming: a backfill that silently found nothing is
        # indistinguishable from one that worked, right up until a record fails to resolve.
        journal = machine.succeed("journalctl -u mp-collector.service --no-pager")
        assert "reconstructed offset history from journald" in journal, (
            f"the journald backfill produced no history:\n{journal}"
        )
        assert collector_health()["clock"]["epochs"] >= 1, collector_health()

    with subtest("records are held rather than shipped with a timestamp nobody can vouch for"):
        post_through_collector()
        retry(lambda _: buffered() > 0, timeout_seconds=30)

    with subtest("the timeout ships them marked rather than dropping them"):
        # §8.1. A Pi that boots with no network may never synchronize. Holding its telemetry
        # forever is worse than shipping it flagged, and dropping it is worse still. The receiver
        # is still down, so the flush lands in the retry queue rather than the database — which is
        # the other half of "not dropped".
        retry(lambda _: buffered() == 0, timeout_seconds=120)
        journal = machine.succeed("journalctl -u mp-collector.service --no-pager")
        assert "forwarding failed" in journal, (
            f"the flush should be visibly retrying, not silently discarding:\n{journal}"
        )

    with subtest("NTP arrives: the gate opens and the buffer is released"):
        ntp.succeed("systemctl start chronyd.service")
        ntp.wait_for_unit("chronyd.service")
        machine.succeed(f"systemctl restart {UNIT}")
        machine.wait_until_succeeds(CLOCK_OK, timeout=180)
        retry(lambda _: collector_health()["clock"]["ever_synchronized"], timeout_seconds=120)

        # And the receiver can now start, so there is somewhere for the data to land.
        machine.succeed("systemctl restart monitoring-platform.service", timeout=120)
        machine.wait_for_unit("monitoring-platform.service")

        assert collector_health()["clock"]["disciplined"] is True, (
            f"chrony is running now: {collector_health()}"
        )

    with subtest("what was held arrives marked uncertain rather than silently wrong"):
        # The whole point of the timeout path: the data is preserved AND labelled, so a query can
        # tell it apart from a timestamp the collector could actually vouch for.
        retry(lambda _: uncertain_rows() > 0, timeout_seconds=180)

        attrs = clock_attributes("heart_rate")
        assert attrs["uncertain"] is True, f"the held record lost its marking: {attrs}"
        assert attrs["corrected"] is False, (
            f"nothing had disciplined the clock, so nothing may claim a correction: {attrs}"
        )

    with subtest("a real clock step is observed"):
        # The `TFD_TIMER_CANCEL_ON_SET` path, for real: it needs something to actually call
        # clock_settime, which needs privilege, so no Rust test can reach it.
        #
        # Observation only. Whether a step *corrects* a held record is `collector-step`'s job, and
        # it cannot be checked here: the collector is already synchronized by this point, so §8.2
        # ships anything posted now within the grace window — while the clock still reads 2019 —
        # and a 2019 timestamp is the correct output. An assertion to the contrary lived here and
        # passed only because earlier subtests had already put sane rows in the table.
        before = collector_health()["clock"]["steps"]

        # Stop the daemon first, or it steps the clock back mid-test and the epoch count moves
        # under the assertions.
        machine.succeed(f"systemctl stop {UNIT}")
        machine.succeed("date -s '2019-01-01 00:00:00'")
        retry(lambda _: collector_health()["clock"]["steps"] > before, timeout_seconds=60)

        health = collector_health()
        assert health["clock"]["epochs"] >= 2, (
            f"a step must open a new epoch, or nothing from before it can be resolved: {health}"
        )

        machine.succeed(f"systemctl start {UNIT}")
        machine.wait_until_succeeds(CLOCK_OK, timeout=180)

    with subtest("the collector reports its own clock health as a measurement"):
        # §9. Emitted through the collector's own forwarder, so it lands in the same table as
        # everything else and needs no second transport — and so a self-metric cannot be the one
        # thing still working when the real path is broken.
        def latest_health():
            # Newest by ROWID, or None if none has arrived yet — not by processed_time. That
            # column is the receiver's wall clock at ingest, and the subtest above deliberately
            # steps that clock back to 2019, so it is not a sequence here: a row ingested during
            # the 2019 window sorts below rows that arrived before it. `measurement` is a rowid
            # table on purpose (src/store/schema.rs, the v2 migration), so rowid IS arrival order.
            out = machine.succeed(
                f"""sqlite3 'file:{DB}?mode=ro' "select body from measurement """
                f"""where type = 'mp.collector.health' order by rowid desc limit 1;" """
            ).strip()
            return json.loads(out) if out else None

        def post_recovery_health(_last_try):
            # Both halves, or this waits for the wrong thing. Polling for *a* health row is not
            # enough — several are emitted before the step above, and the first to land naturally
            # reports zero steps. Neither is polling for a step: emission is gated on
            # ever_synchronized rather than on the clock being good right now, so the reading
            # taken inside the 2019 window is a legitimate row that already carries the step
            # count, and stopping there leaves the assertions below reading a snapshot from a
            # moment when the clock was known-bad.
            reported = latest_health()
            return (
                reported is not None
                and reported["clock.steps"] >= 1
                and reported["clock.disciplined"] is True
            )

        retry(post_recovery_health, timeout_seconds=120)

        reported = latest_health()
        assert reported["clock.disciplined"] is True, f"NTP is up by now: {reported}"
        assert reported["clock.seconds_since_last_step"] != [None], (
            f"a step has happened, so this is no longer null: {reported}"
        )
        for key in ["clock.max_error_micros", "resolved.exact", "buffer.records"]:
            assert key in reported, f"§9 asks for {key}, which is missing: {reported}"

    with subtest("a previous boot's spool ships uncorrected rather than in boottime"):
        # §8.4. Boottime values from another boot describe a machine that no longer exists, so
        # there is nothing to project them with. Planted rather than produced by an actual reboot:
        # the guard is keyed on boot_id, so a directory named after a different one exercises the
        # same path in seconds instead of the minutes a VM reboot costs under TCG.
        machine.succeed("systemctl stop mp-collector.service")
        stale = f"{COLLECTOR_STATE}/spool/00000000-0000-0000-0000-000000000000"
        machine.succeed(f"mkdir -p {stale}")
        machine.succeed(f"mp-make-sample {stale}/00000000000000000000.pb")
        machine.succeed(f"chown -R mp-collector:mp-collector {COLLECTOR_STATE}")
        machine.succeed("systemctl start mp-collector.service")
        machine.wait_for_unit("mp-collector.service")

        machine.wait_until_succeeds(f"test ! -d {stale}", timeout=120)
        journal = machine.succeed("journalctl -u mp-collector.service --no-pager")
        assert "retiring the spool of a previous boot" in journal, (
            f"the boot_id guard did not fire:\n{journal}"
        )
  '';
}
