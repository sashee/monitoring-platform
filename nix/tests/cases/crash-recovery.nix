# An unclean kill loses nothing that was acknowledged, and the database stays usable.
#
# This is what validates `PRAGMA synchronous = NORMAL` (SPEC.md §6.1). In WAL mode
# NORMAL is durable against an *application* crash — the WAL write has reached the
# OS — and only gives up durability against power loss. SIGKILL is precisely the
# application-crash case, so every acknowledged row must still be there.
#
# The acknowledgement is what makes this a fair test: the handler awaits the writer's
# reply before answering, so a 200 means committed, not queued (SPEC.md §6.3).
#
# Isolated because it kills the service and so perturbs NRestarts for other cases.
{ pkgs }:
{
  isolate = true;

  testScript = ''
    # Two DISTINCT batches: mp-make-sample timestamps at run time, so a second call is genuinely
    # new data rather than a duplicate that would be suppressed (SPEC §6.6).
    post_protobuf(sample_batch("/tmp/crash-a.pb"))
    post_protobuf(sample_batch("/tmp/crash-b.pb"))
    committed = row_count()
    assert committed == 6, f"expected 6 acknowledged rows before the kill, got {committed}"

    # SIGKILL: no graceful path, no WAL checkpoint, no socket cleanup. Restart=on-failure
    # brings it back, so this also exercises the restart policy.
    machine.succeed("systemctl kill -s KILL monitoring-platform.service")
    machine.wait_until_fails("systemctl is-active --quiet monitoring-platform.service")
    machine.wait_for_unit("monitoring-platform.service")

    n = machine.succeed("systemctl show monitoring-platform.service -p NRestarts --value").strip()
    assert int(n) >= 1, "the service should have been restarted by Restart=on-failure"

    # Nothing acknowledged was lost. Read through the API, not just sqlite3, so this
    # also proves the reopened database is queryable rather than merely present.
    assert row_count() == committed, "an acknowledged row was lost across the crash"
    rows = get_json("/v1/measurements?limit=100")["measurements"]
    assert len(rows) == committed, f"read API returned {len(rows)} of {committed} rows"

    # The database is not left in a state that only reads: SQLite replayed the WAL on
    # open and the service can commit again.
    post_protobuf(sample_batch("/tmp/crash-c.pb"))
    assert row_count() == committed + 3, "the database is not writable after recovery"

    # No corruption. A truncated WAL replay would surface here rather than as a wrong
    # row count.
    check = machine.succeed(f"sqlite3 'file:{DB}?mode=ro' 'pragma integrity_check;'").strip()
    assert check == "ok", f"integrity_check reported: {check}"

    # The socket is back. Note this does NOT exercise the stale-socket reclamation in
    # transport/uds.rs: systemd removes RuntimeDirectory when the unit stops and
    # recreates it on start, so the path is always fresh here. That path is covered by
    # the Rust end-to-end tests instead, which is the non-systemd case it exists for.
    machine.succeed(f"test -S {SOCKET}")
    assert get_json("/healthz")["status"] == "ok"
  '';
}
