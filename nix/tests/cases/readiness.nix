# Type=notify actually works, and the runtime directory is what gates access.
#
# The preamble's wait_for_unit already depends on the readiness notification: under
# Type=notify systemd only reports `active` once sd_notify(READY=1) arrives, which
# the binary sends after migrations AND after the socket is accepting. So a healthz
# that succeeds with no retry loop is the assertion.
{ pkgs }:
{
  testScript = ''
    assert get_json("/healthz")["status"] == "ok"

    # No polling above: if readiness were reported early (Type=simple), this would be
    # a flaky race rather than a reliable pass.
    machine.succeed("test -S " + SOCKET)

    # 0750 and group-owned is the real access control, since between bind() and the
    # binary's chmod the socket carries 0777 & ~umask.
    mode = machine.succeed("stat -c %a /run/monitoring-platform").strip()
    assert mode == "750", f"runtime directory mode is {mode}, expected 750"
    group = machine.succeed("stat -c %G /run/monitoring-platform").strip()
    assert group == "monitoring-platform", f"runtime directory group is {group}"

    # The database lives in the StateDirectory, not in the service's working dir.
    machine.succeed(f"test -f {DB}")
    state_mode = machine.succeed("stat -c %a /var/lib/monitoring-platform").strip()
    assert state_mode == "700", f"state directory mode is {state_mode}, expected 700"
  '';
}
