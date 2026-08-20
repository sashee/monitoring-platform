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
        # Not plain `before`: every lightweight case is spliced into ONE function scope, so a bare
        # name here is shared with the row counts below and with ingest.nix and restart.nix — and
        # the driver's type check reads the union, not the nearest assignment.
        before_units = machine.succeed("systemctl show mp-collector.service -p Before --value")
        assert "systemd-timesyncd.service" in before_units or "chronyd.service" in before_units, (
            f"the collector is not ordered before any time daemon: {before_units!r}"
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
        # Through row_count, so both sides of the comparison are scoped to this harness's
        # rows. An unscoped count here would be satisfied by a foreign producer's batch and
        # the assertions below would then read whatever row happened to be newest.
        retry(lambda _: row_count() >= before + 3, timeout_seconds=60)

        # **Stamped by exception** (design §9.1): an ordinary corrected record carries no clock
        # attributes at all, so the assertion is that the set is empty. The correction itself is
        # asserted on the timestamp by `collector-clock`, which is where it belongs — a per-row
        # "yes, this was fine" was cardinality rather than information.
        attrs = clock_attributes("heart_rate")
        assert attrs == {}, f"an ordinary corrected record must carry no clock attributes: {attrs}"

        # The corrected stamp is still the proof: `mp-make-sample` stamps now, and the collector
        # projects it through a synchronized clock, so it must land at the present moment.
        sql = (
            "select max(event_time) from measurement where type = 'heart_rate' "
            f"and {sample_scope()};"
        )
        landed = int(machine.succeed(
            "sqlite3 " + shlex.quote(f"file:{DB}?mode=ro") + " " + shlex.quote(sql)
        ).strip())
        now_ns = int(machine.succeed("date +%s%N").strip())
        assert abs(now_ns - landed) < 120 * 10**9, (
            f"the corrected timestamp should be near now; off by {(now_ns - landed) / 1e9:.1f}s"
        )

        # The collector's bookkeeping must not have escaped into the database, where it would be
        # part of a measurement's content hash.
        for internal in ["internal.event_boottime_ns", "internal.receipt_boottime_ns"]:
            assert internal not in attrs, f"{internal} reached the receiver: {attrs}"

    with subtest("a relayed timestamp passes through untouched"):
        # Written by one process and posted by another: exactly the shape of an application
        # re-emitting a timestamp it did not produce. The bound is real, not decorative, and this
        # is the case that proves the collector does not rewrite what it has no business rewriting.
        path = sample_batch("/tmp/relayed.pb")
        # The wait is the point of the case, not padding. Frame resolution admits a stamp that
        # predates the sender by up to the epoch tolerance (DEFAULT_TOLERANCE_NANOS, 50 ms in
        # epoch.rs — a fixed constant, with no flag or module option to read it from). Under it,
        # curl's own frame explains the timestamp and the record resolves `exact`; over it, only
        # passthrough is left. Relying on process-spawn latency to clear 50 ms is what made this
        # pass at ~150 ms on a loaded VM and fail at ~20 ms on a fast one. 0.5 s is 10x the
        # tolerance, so the classification is a property of the code rather than of the host.
        machine.succeed("sleep 0.5")
        machine.succeed(_as_user(CLIENT,
            f"curl -sS --fail-with-body --unix-socket {COLLECTOR} "
            f"-X POST -H 'Content-Type: application/x-protobuf' "
            f"--data-binary @{path} http://localhost/v1/logs"
        ))
        def resolutions():
            sql = (
                "select json_extract(attributes, "
                """'$."record.attributes.mp.clock.resolution"') """
                f"from measurement where {sample_scope()};"
            )
            out = machine.succeed(
                "sqlite3 " + shlex.quote(f"file:{DB}?mode=ro") + " " + shlex.quote(sql)
            )
            return [line for line in out.split("\n") if line]

        def relayed_landed(last_try):
            seen = resolutions()
            if last_try:
                assert "passthrough" in seen, (
                    f"the relayed batch was not left alone; resolutions seen: {seen}"
                )
            return "passthrough" in seen

        retry(relayed_landed, timeout_seconds=60)

    with subtest("the collector accepts exactly what the receiver accepts"):
        # Or "point an application at either one unchanged" stops being true.
        for bad, why in [
            ("-H 'Content-Type: application/json'", "wrong content type"),
            ("-H 'Content-Type: application/x-protobuf' -H 'Content-Encoding: zstd'", "unknown encoding"),
        ]:
            for sock in [COLLECTOR, SOCKET]:
                # The receiver requires an API key (SPEC.md §13); the collector's own socket is local
                # and gated by group permissions instead. Without the key the receiver answers 401
                # before it ever looks at the content type, and the parity asserted here — that an
                # application can be pointed at either one unchanged — would go untested.
                auth = "" if sock == COLLECTOR else _auth()
                code = machine.succeed(_as_user(CLIENT,
                    f"curl -sS -o /dev/null -w '%{{http_code}}' {auth}--unix-socket {sock} "
                    f"-X POST {bad} --data-binary @/tmp/relayed.pb http://localhost/v1/logs"
                )).strip()
                assert code == "415", f"{why} on {sock} gave {code}, expected 415"
  '';
}
