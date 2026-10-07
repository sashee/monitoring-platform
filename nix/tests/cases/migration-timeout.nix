# A schema migration may outlast TimeoutStartSec, and systemd lets it finish (SPEC.md §9.2).
#
# Migrations run before READY=1, so under Type=notify they count against the start timeout. One that
# outlasts it is killed, rolled back, and retried from scratch every RestartSec, forever: the receiver
# never comes back. So the receiver extends the timeout itself whenever a migration is pending, and
# this case proves systemd honours that.
#
# **A migration paused, not a migration made slow.** Only a migration that rewrites rows is genuinely
# slow, and that would need an old-schema fixture large enough to be slow on whatever machine runs
# this. So the case pauses an ordinary one instead: a fresh database leaves every migration pending, a
# second connection holding the write lock keeps the receiver inside the first one, and once the
# receiver has announced it, SIGSTOP freezes it there for as long as the case needs. To systemd, a
# stopped process and one grinding through rows are the same thing: a main process that has not sent
# READY=1.
#
# **Why not just hold the lock.** That was the first version, and it cannot work on every machine. The
# lock has to be released within busy_timeout (5 s) of the receiver reaching it, so the timeout has to
# expire inside that window, after the receiver has extended it. Under KVM the receiver starts in
# milliseconds; on CI's arm runners, which have no KVM, it took 1.6 to 5.5 s to log its first line, and
# a 1.5 s timeout killed it before it opened the database. No fixed timeline fits both. Stopping the
# process lifts the 5 s ceiling, and the timeout only has to outlast startup.
#
# The timeline, from the moment the lock is taken:
#
#   ~0 s     the unit is started; the receiver extends the timeout and blocks on the lock
#   seen     the migration status appears: the receiver is stopped and the lock released
#   +17 s    the mid-migration probe, past TimeoutStartSec however late `seen` was
#   then     the receiver is continued, and the migration runs to completion
#
# Isolated because it reconfigures the unit.
{ pkgs }:
let
  # Only has to outlast the receiver's startup, which the migration's own wait no longer bounds.
  # Generous, because every second of it is paid on every run and CI's slowest start was 5.5 s.
  timeoutStartSecs = 15;
in
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
            TimeoutStartSec = lib.mkForce timeoutStartSecs;

            # A failed start should fail the test straight away, not be retried behind wait_for_unit
            # until the driver gives up.
            Restart = lib.mkForce "no";
          };
        };

        # The gate is an ExecStartPre=, and systemd re-arms the start timeout for every phase, so it
        # would get the same short timeout. Its consecutive good polls need not fit in it, and nothing
        # here depends on the clock.
        services.monitoring-platform.clockGate.enable = lib.mkForce false;
      }
    )
  ];

  testScript = ''
    UNIT = "monitoring-platform.service"
    LOCK_HELD = "/tmp/migration-lock-held"
    LOCK_RELEASE = "/tmp/migration-lock-release"
    TIMEOUT_START_SECS = ${toString timeoutStartSecs}

    def parse_props(text):
        return dict(line.split("=", 1) for line in text.strip().splitlines())

    # WAL is set in the file here, because the receiver's own `PRAGMA journal_mode = WAL` needs an
    # exclusive lock to change modes and would fail outright against the held one. On a file that is
    # already WAL it is a no-op. Done as the service user so that -wal and -shm are files the service
    # can write.
    machine.succeed(f"install -d -m 0700 -o {SERVICE_USER} -g {SERVICE_USER} $(dirname {DB})")
    machine.succeed(f"runuser -u {SERVICE_USER} -- sqlite3 {DB} 'PRAGMA journal_mode = WAL;'")

    # One shell command, so the receiver's wait on the lock is measured inside the VM and not across
    # the driver's round trips: it uses up busy_timeout until the receiver is stopped.
    #
    # The migration status is sent in the same message as EXTEND_TIMEOUT_USEC, so seeing it means the
    # extension was sent too. If it never appears, the receiver is left alone and the probe records
    # whatever became of it. Stopped before the lock is released, so the migration cannot finish
    # first; the guard on the PID because `kill -STOP 0` would stop this shell instead.
    #
    # The probe waits out the whole timeout after the stop, so it lands past the deadline however late
    # the receiver got there. The extra 2 s give a slow machine time to act on an expiry. If systemd did
    # act on one, the receiver is already gone, and the continue fails: tolerated, because the driver
    # runs this under `set -e` and the probe, not this command, is what should report it.
    machine.succeed(
        f"runuser -u {SERVICE_USER} -- sqlite3 {DB} 'BEGIN IMMEDIATE;' "
        f"'.shell touch {LOCK_HELD}; until [ -e {LOCK_RELEASE} ]; do sleep 0.01; done' 'COMMIT;' & "
        f"until [ -e {LOCK_HELD} ]; do sleep 0.01; done; "
        f"systemctl start --no-block {UNIT}; "
        "seen=; deadline=$((SECONDS + 120)); "
        "while [ $SECONDS -lt $deadline ]; do "
        f"  case $(systemctl show -p StatusText --value {UNIT}) in *migration*) seen=1; break;; esac; "
        f"  [ \"$(systemctl show -p Result --value {UNIT})\" = success ] || break; "
        "  sleep 0.05; "
        "done; "
        f"pid=$(systemctl show -p MainPID --value {UNIT}); "
        'if [ -n "$seen" ] && [ "$pid" -gt 0 ]; then kill -STOP "$pid"; fi; '
        f"touch {LOCK_RELEASE}; "
        f"sleep {TIMEOUT_START_SECS + 2}; "
        f"systemctl show {UNIT} -p Result -p ActiveState -p SubState -p StatusText > /tmp/mid-migration; "
        'if [ -n "$seen" ] && [ "$pid" -gt 0 ]; then kill -CONT "$pid" || true; fi; '
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
    assert took > TIMEOUT_START_SECS, (
        f"startup took {took:.2f} s, inside TimeoutStartSec, so nothing was tested"
    )

    # The migration status must not outlive the migration.
    assert "migration" not in props["StatusText"], f"stale status after READY: {props}"

    version = int(
        machine.succeed(f"sqlite3 'file:{DB}?mode=ro' 'PRAGMA user_version;'").strip()
    )
    assert version > 0, "the unit is up but the schema was never migrated"
  '';
}
