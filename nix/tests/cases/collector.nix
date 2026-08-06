# The collector on a machine whose clock is already good (design §3, §5, §7).
#
# Lightweight, because none of this needs the clock to misbehave: it is the wiring, the sandbox,
# and the two dispositions that do not depend on a step — a record the sender produced, and a
# record it merely relayed. `collector-clock` covers the cases that need a bad clock.
#
# The sandbox assertions are the ones worth having here. Three of the receiver's hardening
# settings had to change for the collector, and every one of them fails *silently* if it regresses:
# a blocked adjtimex(2) kills with SIGSYS, and a hidden /proc quietly turns every record into a
# passthrough with nothing in the journal to say so.
{ pkgs }:
{
  testScript = ''
    with subtest("the units are wired the way the design requires"):
        # Socket activation, so an application that starts first blocks on connect() rather than
        # failing. Read back from systemd rather than trusted from the module.
        machine.wait_for_unit("mp-collector.socket")
        machine.wait_for_unit("mp-collector.service")
        assert machine.succeed(
            "systemctl show mp-collector.socket -p Accept --value"
        ).strip() == "no", "Accept=yes would spawn one process per connection"

        # Eager, not lazy: a collector that is not running observes no clock steps, which is the
        # one thing it exists to do. Lazy activation guarantees the socket, not the process.
        wanted = machine.succeed("systemctl show mp-collector.service -p WantedBy --value")
        assert "multi-user.target" in wanted, f"the service is not started eagerly: {wanted!r}"

        # Before anything that can step the clock. This is what eliminates the unknown-epoch case.
        before = machine.succeed("systemctl show mp-collector.service -p Before --value")
        assert "systemd-timesyncd.service" in before or "chronyd.service" in before, (
            f"the collector is not ordered before any time daemon: {before!r}"
        )

        # DefaultDependencies=no removes shutdown ordering, and putting it back is manual.
        # Without it the collector is killed at an arbitrary point during shutdown, mid-flush.
        conflicts = machine.succeed("systemctl show mp-collector.service -p Conflicts --value")
        assert "shutdown.target" in conflicts, (
            f"DefaultDependencies=no was not compensated for; a stop can kill a flush: {conflicts!r}"
        )

    with subtest("the sandbox permits exactly what frame resolution needs"):
        # ProtectProc=invisible would hide the *sending* process's /proc entry, the lower bound of
        # the [sender_started, received] window collapses to zero, and every record silently
        # degrades toward passthrough. Nothing reports that but a rising counter.
        assert machine.succeed(
            "systemctl show mp-collector.service -p ProtectProc --value"
        ).strip() == "default", "ProtectProc must not hide other users' processes"

        # ProtectClock=yes cannot allow a *read* of adjtimex(2) — systemd.exec(5) is explicit —
        # and kills with SIGSYS instead.
        assert machine.succeed(
            "systemctl show mp-collector.service -p ProtectClock --value"
        ).strip() == "no"

        # And the collector still cannot SET the clock, which is the property dropping
        # ProtectClock had to preserve.
        assert machine.succeed(
            "systemctl show mp-collector.service -p CapabilityBoundingSet --value"
        ).strip() == "", "an empty capability set is what withholds CAP_SYS_TIME"

        # Local only until the forward target says otherwise.
        families = machine.succeed(
            "systemctl show mp-collector.service -p RestrictAddressFamilies --value"
        )
        assert "AF_INET" not in families, f"network egress with a unix forward target: {families!r}"

        journal = machine.succeed("journalctl -u mp-collector.service --no-pager")
        for marker in ["seccomp", "SIGSYS", "signal=SYS"]:
            assert marker not in journal, (
                f"found {marker!r} in the journal — the sandbox is denying a syscall the "
                f"collector needs:\n{journal}"
            )

    with subtest("it reports a healthy clock"):
        health = collector_health()
        assert health["clock"]["synchronized"], f"the VM has a real time source: {health}"
        assert health["clock"]["ever_synchronized"], health
        assert health["clock"]["sync_source"], f"which condition fired must be recorded: {health}"

    with subtest("a record from the sending process is corrected"):
        before = row_count()
        post_through_collector()
        machine.wait_until_succeeds(f"test $(sqlite3 'file:{DB}?mode=ro' "
                                    f"'select count(*) from measurement;') -ge {before + 3}",
                                    timeout=60)

        attrs = clock_attributes("heart_rate")
        assert attrs["corrected"] is True, f"the sender's own timestamp was not corrected: {attrs}"
        assert attrs["resolution"] == "exact", attrs
        assert attrs["sync_source"], f"the condition that released the buffer must be named: {attrs}"
        assert "uncertain" not in attrs, f"the clock was fine; nothing is uncertain: {attrs}"

        # The collector's bookkeeping must not have escaped into the database, where it would be
        # part of a measurement's content hash.
        for internal in ["internal.event_boottime_ns", "internal.receipt_boottime_ns"]:
            assert internal not in attrs, f"{internal} reached the receiver: {attrs}"

    with subtest("a relayed timestamp passes through untouched"):
        # Written by one process and posted by another: exactly the shape of an application
        # re-emitting a timestamp it did not produce. The bound is real, not decorative, and this
        # is the case that proves the collector does not rewrite what it has no business rewriting.
        path = sample_batch("/tmp/relayed.pb")
        machine.succeed(
            f"su - {CLIENT} -c " + repr(
                f"curl -sS --fail-with-body --unix-socket {COLLECTOR} "
                f"-X POST -H 'Content-Type: application/x-protobuf' "
                f"--data-binary @{path} http://localhost/v1/logs"
            )
        )
        machine.wait_until_succeeds(
            f"""sqlite3 'file:{DB}?mode=ro' "select attributes from measurement;" """
            f"""| grep -q passthrough""",
            timeout=60,
        )

    with subtest("the collector accepts exactly what the receiver accepts"):
        # Or "point an application at either one unchanged" stops being true.
        for bad, why in [
            ("-H 'Content-Type: application/json'", "wrong content type"),
            ("-H 'Content-Type: application/x-protobuf' -H 'Content-Encoding: zstd'", "unknown encoding"),
        ]:
            for sock in [COLLECTOR, SOCKET]:
                code = machine.succeed(
                    f"su - {CLIENT} -c " + repr(
                        f"curl -sS -o /dev/null -w '%{{http_code}}' --unix-socket {sock} "
                        f"-X POST {bad} --data-binary @/tmp/relayed.pb http://localhost/v1/logs"
                    )
                ).strip()
                assert code == "415", f"{why} on {sock} gave {code}, expected 415"
  '';
}
