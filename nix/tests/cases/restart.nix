# Shutdown and restart are clean, and committed data outlives the process.
#
# Isolated because it stops and starts the unit, which would perturb the other
# lightweight cases sharing a VM.
{ pkgs }:
{
  isolate = true;

  testScript = ''
    payload = sample_batch()
    post_protobuf(payload)
    before = row_count()
    assert before == 3

    # Graceful stop: SIGTERM drains the writer, checkpoints WAL, unlinks the socket.
    machine.succeed("systemctl stop monitoring-platform.service")

    # RuntimeDirectory is removed with the unit, so the socket must be gone either way;
    # what matters is that the stop was clean rather than a timeout kill.
    result = machine.succeed(
        "systemctl show monitoring-platform.service -p Result --value"
    ).strip()
    assert result == "success", f"stop was not clean: Result={result}"

    # WAL was checkpointed and truncated, so no -wal/-shm are left behind.
    leftovers = machine.succeed(
        "ls /var/lib/monitoring-platform/ | sort | tr '\\n' ' '"
    ).strip()
    assert leftovers == "measurements.db", f"unexpected files after stop: {leftovers!r}"

    machine.succeed("systemctl start monitoring-platform.service")
    machine.wait_for_unit("monitoring-platform.service")

    # The rows are still there, and the service is serving again on a fresh socket.
    assert row_count() == before, "committed rows must survive a restart"
    assert get_json("/healthz")["status"] == "ok"
    assert len(get_json("/v1/measurements?limit=10")["measurements"]) == before

    # And it can still accept new data, i.e. migrations were a no-op on the existing
    # database rather than a failure.
    post_protobuf(payload)
    assert row_count() == before + 3
  '';
}
