# The design's central case: records held while the clock is untrusted, then **released and
# corrected by a real clock step** (§4.3, §4.6, §6.2).
#
# Nothing else reaches this. `collector-clock` covers the other end of the buffer — the timeout
# firing when NTP never arrives — and the Rust end-to-end tests cover correction, but through a
# seeded epoch table rather than a live `clock_settime`. Here the step is real, the buffering is
# real, and the record crossing between them is the thing the collector exists to do.
#
# **A separate VM from `collector-clock` because the two need opposite buffer timeouts.** That case
# must watch the timeout fire, so it sets a short one; this case must not let it fire at all, or
# the flush that ships the record is the timeout rather than the step and the test silently proves
# the wrong thing. Rewriting the unit mid-test to dodge that would be less readable than a second
# VM, which costs about two minutes.
{ pkgs }:
{
  isolate = true;

  # The receiver's §9.4 gate refuses to start while the clock is bad, which is most of this case.
  waitForService = false;

  machineModules = [
    (
      { lib, ... }:
      {
        # Ten minutes. The point is that the timeout does NOT fire: every flush here has to be
        # caused by the clock becoming trustworthy, so that a record shipped uncorrected fails the
        # test instead of quietly passing through the §8.1 path.
        services.mp-collector.bufferTimeoutSecs = 600;

        systemd.services.monitoring-platform.serviceConfig.RestartSec = lib.mkForce "2s";
        services.monitoring-platform.clockGate = {
          maxPolls = 5;
          pollIntervalSecs = 2;
        };
      }
    )
  ];

  ntpNodeModules = [
    ({ lib, ... }: { systemd.services.chronyd.wantedBy = lib.mkForce [ ]; })
  ];

  testScript = ''
    UNIT = time_sync_unit()
    ntp.wait_for_unit("multi-user.target")

    STALE = "2019-01-01 00:00:00"
    # Any bound between the faked clock and the present separates the two frames; 2024 is well
    # clear of both and does not need updating as the real date moves.
    CUTOFF = "2024-01-01"

    def count_rows(kind, comparison):
        # The receiver's own §9.4 gate keeps it from starting while the clock is bad, so for most
        # of this case the database does not exist yet. That is "no rows", not an error — but the
        # absence has to be handled explicitly rather than by swallowing sqlite3's exit code,
        # which would also hide a genuinely broken query.
        #
        # Scoped on the harness's device.id too: the cutoff comparison is about WHERE in time
        # a row landed, which says nothing about who wrote it, so a foreign producer's rows
        # would be counted as this case's evidence either side of the line.
        sql = (
            f"select count(*) from measurement where type = '{kind}' "
            f"and event_time {comparison} strftime('%s','{CUTOFF}') * 1000000000 "
            f"and {sample_scope()};"
        )
        out = machine.succeed(
            f"""if [ -e {DB} ]; then """
            + "sqlite3 " + shlex.quote(f"file:{DB}?mode=ro") + " " + shlex.quote(sql)
            + "; else echo 0; fi"
        )
        return int(out.strip())

    def rows_since_cutoff(kind):
        return count_rows(kind, ">")

    def rows_before_cutoff(kind):
        return count_rows(kind, "<=")

    with subtest("the collector is running before anything can step the clock"):
        # The ordering §7 exists for. Asserted at runtime rather than from the unit file, because
        # what matters is that it actually happened on this boot.
        machine.wait_for_unit("mp-collector.service")

        # Before a single batch goes through the collector: this issues the key and restarts the
        # collector to load it, and a restart discards anything already in its outbox.
        authenticate()
        assert not collector_health()["clock"]["ever_synchronized"], collector_health()

    with subtest("nothing is disciplining the clock, and that is visible"):
        # The §9 signal that separates a configuration problem from a network outage. Readable here
        # precisely because it is on /healthz: no health event has been emitted, and none can be
        # until the clock is good.
        assert collector_health()["clock"]["disciplined"] is False, collector_health()

    with subtest("a record stamped by a wrong clock is held, not shipped"):
        machine.succeed(f"date -s '{STALE}'")
        post_through_collector()

        retry(lambda _: collector_health()["buffer"]["records"] > 0, timeout_seconds=30)
        assert rows_before_cutoff("heart_rate") == 0, (
            "a record from the wrong frame reached the database instead of being held"
        )

    with subtest("the step releases the buffer and corrects what was held"):
        # chrony finds the clock seven years out and steps it. The collector's cancel-on-set
        # timerfd sees that, opens an epoch, and the held record — resolved at receipt against the
        # *stale* epoch — is projected through the new one.
        before = collector_health()["clock"]["steps"]
        ntp.succeed("systemctl start chronyd.service")
        ntp.wait_for_unit("chronyd.service")
        machine.succeed(f"systemctl restart {UNIT}")

        retry(lambda _: collector_health()["clock"]["steps"] > before, timeout_seconds=180)
        machine.wait_until_succeeds(CLOCK_OK, timeout=180)
        retry(lambda _: collector_health()["buffer"]["records"] == 0, timeout_seconds=120)

        # The receiver can start now that its own gate opens, giving the flush somewhere to land.
        machine.succeed("systemctl restart monitoring-platform.service", timeout=120)
        machine.wait_for_unit("monitoring-platform.service")
        retry(lambda _: rows_since_cutoff("heart_rate") > 0, timeout_seconds=180)

    with subtest("and it is corrected cleanly, not marked as a guess"):
        # **Stamped by exception** (design §9.1): a record corrected against a synchronized clock,
        # with no ambiguity, carries no clock attributes at all. So the empty set is the assertion,
        # and it is a strong one — it says at once that the correction applied, that the resolution
        # did not degrade to `passthrough`, and that nothing is `uncertain`.
        #
        # That last one is the distinction this whole case exists to draw: `uncertain` would mean
        # the timeout shipped the record, which is the §8.1 path and proves nothing about the step.
        attrs = clock_attributes("heart_rate")
        assert attrs == {}, f"the held record was not corrected cleanly by the step: {attrs}"

        # And the correction itself is asserted where it now lives: on the timestamp. A 2019 stamp
        # that comes out the far side of the cutoff moved by seven years, which is the magnitude
        # `correction_ns` used to carry — measured on the row instead of trusted from a label.
        assert rows_before_cutoff("heart_rate") == 0, (
            "the held record kept its 2019 timestamp; the correction did not reach the database"
        )

    with subtest("history survives a restart across a step"):
        # A step landing while the collector is down is the one gap the persisted table cannot
        # know about, which is why the live reading is appended on every start whatever the
        # source. Without that, everything stamped before the restart resolves against an offset
        # the machine no longer uses.
        machine.succeed(f"systemctl stop {UNIT}")
        machine.succeed("systemctl stop mp-collector.service")
        machine.succeed(f"date -s '{STALE}'")
        machine.succeed("systemctl start mp-collector.service")
        machine.wait_for_unit("mp-collector.service")

        # The socket must still be *reachable*, not merely present. RuntimeDirectory= deletes the
        # directory when the service stops, taking the socket unit's file with it; the restarted
        # service then inherits a descriptor whose inode is unlinked, reports itself healthy, and
        # refuses every connection. RuntimeDirectoryPreserve=yes is what stops that, and this is
        # the assertion that would notice if it were dropped.
        machine.succeed(f"test -S {COLLECTOR}")

        health = collector_health()
        assert health["clock"]["epochs"] >= 2, (
            f"the persisted history and the new reading should both be present: {health}"
        )

        journal = machine.succeed("journalctl -u mp-collector.service --no-pager")
        assert "resumed offset history from disk" in journal, (
            f"the epoch table was not persisted across the restart:\n{journal}"
        )

        # And it still works: put the clock back and a fresh record lands correctly.
        machine.succeed(f"systemctl start {UNIT}")
        machine.wait_until_succeeds(CLOCK_OK, timeout=180)
        before = rows_since_cutoff("gps")
        post_through_collector()
        retry(lambda _: rows_since_cutoff("gps") > before, timeout_seconds=180)
  '';
}
