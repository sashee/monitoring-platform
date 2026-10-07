# A schema migration may outlast TimeoutStartSec, and systemd lets it finish (SPEC.md §9.2).
#
# Migrations run before READY=1, so under Type=notify they count against the start timeout. One that
# outlasts it is killed, rolled back, and retried from scratch every RestartSec, forever: the receiver
# never comes back. So the receiver extends the timeout itself whenever a migration is pending, and
# this case proves systemd honours that.
#
# **A migration held, not a migration made slow.** Only a migration that rewrites rows is genuinely
# slow, and that would need an old-schema fixture large enough to be slow on whatever machine runs
# this. So the case parks an ordinary one instead: a fresh database leaves every migration pending, and
# a second connection holding the write lock blocks the receiver's first CREATE TABLE inside its
# busy_timeout (5 s). To systemd, a migration waiting on a lock and one grinding through rows are the
# same thing: a main process that has not sent READY=1.
#
# The timeline, from the moment the lock is taken:
#
#   ~0 s     the unit is started; the receiver reaches the migration and blocks on the lock
#   1.5 s    TimeoutStartSec: without the extension, systemd kills it here
#   2.25 s   the mid-migration probe
#   3.5 s    the lock is released and the migration runs to completion
#   ~5 s     where busy_timeout would give up, which the release stays well clear of
#
# Isolated because it reconfigures the unit.
{ pkgs }:
{
  isolate = true;

  # The case starts the unit itself, against a database it prepared.
  waitForService = false;

  machineModules = [
    (
      { lib, ... }:
      {
        systemd.services.monitoring-platform = {
          # Not started at boot, so there is no database until this case makes one, and every line in
          # the unit's journal comes from the start under test.
          wantedBy = lib.mkForce [ ];

          serviceConfig = {
            # Shorter than the held lock, and longer than it takes the receiver to reach the migration.
            TimeoutStartSec = lib.mkForce "1500ms";

            # A failed start should fail the test straight away, not be retried behind wait_for_unit
            # until the driver gives up.
            Restart = lib.mkForce "no";
          };
        };

        # The gate is an ExecStartPre=, and systemd re-arms the start timeout for every phase, so it
        # would get 1.5 s too. That is less than its consecutive good polls take, and nothing here
        # depends on the clock.
        services.monitoring-platform.clockGate.enable = lib.mkForce false;
      }
    )
  ];

  testScript = ''
    UNIT = "monitoring-platform.service"
    LOCK_HELD = "/tmp/migration-lock-held"

    def parse_props(text):
        return dict(line.split("=", 1) for line in text.strip().splitlines())

    # WAL is set in the file here, because the receiver's own `PRAGMA journal_mode = WAL` needs an
    # exclusive lock to change modes and would fail outright against the held one. On a file that is
    # already WAL it is a no-op. Done as the service user so that -wal and -shm are files the service
    # can write.
    machine.succeed(f"install -d -m 0700 -o {SERVICE_USER} -g {SERVICE_USER} $(dirname {DB})")
    machine.succeed(f"runuser -u {SERVICE_USER} -- sqlite3 {DB} 'PRAGMA journal_mode = WAL;'")

    # One shell command, so the timeline is measured inside the VM and not across the driver's round
    # trips. The lock holder signals once it has the lock; only then is the unit started.
    machine.succeed(
        f"runuser -u {SERVICE_USER} -- sqlite3 {DB} 'BEGIN IMMEDIATE;' "
        f"'.shell touch {LOCK_HELD}; sleep 3.5' 'COMMIT;' & "
        f"until [ -e {LOCK_HELD} ]; do sleep 0.01; done; "
        f"systemctl start --no-block {UNIT}; "
        "sleep 2.25; "
        f"systemctl show {UNIT} -p Result -p ActiveState -p SubState -p StatusText > /tmp/mid-migration; "
        "wait"
    )

    # Judged by `Result`, not by the journal's wording, which is not an interface: this systemd logs
    # "start operation timed out" in lower case, and a match on the capitalized form misses it without a
    # word. The journal is there to explain a failure.
    mid = parse_props(machine.succeed("cat /tmp/mid-migration"))
    journal = machine.succeed(f"journalctl -u {UNIT} --no-pager")
    assert mid["Result"] != "timeout", f"systemd killed the migration at TimeoutStartSec:\n{journal}"
    # systemd parses the value as 64-bit. A value it rejected would be ignored, and the unit killed.
    assert "failed to parse extend_timeout_usec" not in journal.lower(), journal

    # Past TimeoutStartSec and still starting, rather than dead and about to be retried. The status
    # line is what tells an operator watching `systemctl status` why.
    assert (mid["ActiveState"], mid["SubState"]) == ("activating", "start"), (
        f"not still starting after TimeoutStartSec: {mid}"
    )
    assert "migration" in mid["StatusText"], f"no migration status was reported: {mid}"

    machine.wait_for_unit(UNIT)

    props = parse_props(
        machine.succeed(
            f"systemctl show {UNIT} -p ExecMainStartTimestampMonotonic "
            "-p ActiveEnterTimestampMonotonic -p StatusText"
        )
    )
    # Without this, a start that never waited at all would pass the case without testing anything.
    took = (
        int(props["ActiveEnterTimestampMonotonic"]) - int(props["ExecMainStartTimestampMonotonic"])
    ) / 1e6
    assert took > 1.5, f"startup took {took:.2f} s, inside TimeoutStartSec, so nothing was tested"

    # The migration status must not outlive the migration.
    assert "migration" not in props["StatusText"], f"stale status after READY: {props}"

    version = int(
        machine.succeed(f"sqlite3 'file:{DB}?mode=ro' 'PRAGMA user_version;'").strip()
    )
    assert version > 0, "the unit is up but the schema was never migrated"
  '';
}
