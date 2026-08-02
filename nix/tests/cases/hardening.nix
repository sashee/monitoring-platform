# The sandbox is applied AND is not too strict.
#
# This is the case that only a VM on the target's own nixpkgs can decide, because
# seccomp and address-family semantics depend on the systemd version (SPEC.md §11.1).
# Two directions matter:
#
#   - too loose: the options silently did not apply (an option rename, a merge that
#     dropped them). Asserted by reading them back from systemd itself.
#   - too strict: a syscall the service needs is denied. Asserted by driving a full
#     ingest cycle and then looking for denials — startup alone would not catch a
#     filter that only bites once the writer thread or SQLite's fsync path runs.
{ pkgs }:
{
  testScript = ''
    def prop(name):
        return machine.succeed(
            f"systemctl show monitoring-platform.service -p {name} --value"
        ).strip()

    # Read back from systemd rather than trusting that the module set them: a renamed
    # or mistyped option would otherwise pass silently with no sandbox at all.
    assert prop("RestrictAddressFamilies") == "AF_UNIX", (
        f"expected AF_UNIX only, got {prop('RestrictAddressFamilies')!r} — "
        "this is the line that must change when iroh lands"
    )
    assert prop("NoNewPrivileges") == "yes"
    assert prop("ProtectSystem") == "strict"
    assert prop("MemoryDenyWriteExecute") == "yes"
    assert prop("ProtectHome") == "yes"
    assert prop("SystemCallFilter") != "", "no syscall filter is applied"
    assert prop("CapabilityBoundingSet") == "", (
        f"capability set should be empty, got {prop('CapabilityBoundingSet')!r}"
    )
    assert prop("Type") == "notify"

    # The one deliberate relaxation (SPEC.md §9.4). ProtectClock= cannot distinguish reading
    # the clock from setting it, so the clock gate needs it off plus @clock allowed. Asserted
    # here so neither silently drifts back; that the relaxation actually WORKS — adjtimex(2)
    # surviving inside this sandbox — is the clock-gate case, which runs the gate for real.
    # CapabilityBoundingSet= being empty above is what still makes setting the clock impossible.
    assert prop("ProtectClock") == "no", (
        "ProtectClock must stay off — it blocks the adjtimex(2) read the clock gate needs, "
        "including in ExecStartPre"
    )
    # systemd expands the group names, so the assertion is on the syscall the gate actually
    # makes rather than on "@clock" appearing literally — which is the stronger check anyway:
    # it survives the group being renamed or its membership changing.
    assert "adjtimex" in prop("SystemCallFilter").split(), (
        f"adjtimex is not permitted; @clock is not part of @system-service, so the module "
        f"has to name it: {prop('SystemCallFilter')!r}"
    )

    # Drive the paths that a startup-only check would miss: the writer thread, a
    # transaction commit, WAL, and the read path's separate connection.
    payload = sample_batch("/tmp/hardening.pb")
    post_protobuf(payload)
    machine.succeed(f"gzip -c {payload} > {payload}.gz")
    post_protobuf(f"{payload}.gz", extra="-H 'Content-Encoding: gzip'")
    get_json("/v1/measurements?limit=50")

    # Now look for denials. seccomp kills with SIGSYS, so a filter that is too strict
    # shows up as a signalled exit as well as in the audit log.
    # Not named `log`: the test driver binds that to its own logger, and the driver's
    # type check rejects shadowing it.
    journal = machine.succeed("journalctl -u monitoring-platform.service --no-pager")
    for marker in ["seccomp", "Operation not permitted", "SIGSYS", "signal=SYS"]:
        assert marker not in journal, (
            f"found {marker!r} in the service journal — the sandbox is denying "
            f"something the service needs:\n{journal}"
        )

    # And it is still running, rather than having been killed and restarted quietly.
    assert prop("NRestarts") == "0", f"the service restarted {prop('NRestarts')} times"
    machine.succeed("systemctl is-active monitoring-platform.service")
  '';
}
