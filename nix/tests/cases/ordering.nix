# A dependent unit can rely on the service being usable the moment it is `active`.
#
# This is the case that actually justifies the sd-notify dependency. `readiness`
# only shows that healthz answers once the test driver has waited for the unit; it
# cannot distinguish Type=notify from Type=simple, because by the time the driver
# gets around to asking, a Type=simple service would have finished starting anyway.
#
# Here the probe runs at boot, ordered After= the service, and curls the socket
# EXACTLY ONCE with no retry. Under Type=simple systemd would consider the service
# started at fork, so the probe would race migrations and the bind() and fail. Under
# Type=notify it cannot start until sd_notify(READY=1) has arrived.
#
# Isolated because it adds a unit to the machine and asserts about boot.
{ pkgs }:
{
  isolate = true;

  machineModules = [
    (
      { config, ... }:
      {
        systemd.services.mp-probe = {
          description = "Probe the receiver exactly once at boot";
          # Requires, not just Wants: if the service fails, this must fail too rather
          # than silently pass by never running.
          requires = [ "monitoring-platform.service" ];
          after = [ "monitoring-platform.service" ];
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "oneshot";
            # Keep the result observable after it exits.
            RemainAfterExit = true;
            # Absolute store path: ExecStart does not use the unit's `path`, it resolves
            # against a fixed default PATH, so a bare `curl` fails with 203/EXEC.
            # Deliberately no `--retry`: a retry loop would paper over exactly the
            # race this case exists to detect.
            ExecStart = "${pkgs.lib.getExe' pkgs.curl "curl"} -sS --fail-with-body --unix-socket ${config.services.monitoring-platform.socketPath} http://localhost/healthz";
          };
        };
      }
    )
  ];

  testScript = ''
    # The probe already ran during boot. If readiness had been reported before the
    # socket was accepting, this unit would have failed then — nothing here can
    # retroactively fix it, which is what makes the assertion meaningful.
    machine.wait_for_unit("mp-probe.service")

    result = machine.succeed("systemctl show mp-probe.service -p Result --value").strip()
    assert result == "success", (
        f"the boot-time probe failed (Result={result}) — readiness was reported "
        "before the socket was accepting:\n"
        + machine.succeed("journalctl -u mp-probe.service --no-pager")
    )

    # It really did run once and reach the service, rather than being skipped.
    n = machine.succeed("systemctl show mp-probe.service -p NRestarts --value").strip()
    assert n == "0", f"probe restarted {n} times, so it did not succeed first time"

    # And the ordering was actually enforced, not merely requested: systemd reports
    # the dependency, so a future edit dropping After= would show up here.
    after = machine.succeed("systemctl show mp-probe.service -p After --value")
    assert "monitoring-platform.service" in after, f"ordering dependency is missing: {after}"
  '';
}
