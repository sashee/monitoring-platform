# Group membership is what grants access.
#
# Only reachable in a VM: it needs real users and groups, so a minimal test machine
# that merely enables the service could not express it. The socket is reached through
# a 0750 group-owned directory, so this is asserting the mechanism SPEC.md §8.1 says
# is load-bearing — not the 0660 mode on the socket inode, which is defence in depth.
{ pkgs }:
{
  testScript = ''
    # A member of the service group connects.
    assert get_json("/healthz", user=CLIENT)["status"] == "ok"

    # A normal user outside the group must not. curl reports EACCES on a unix socket
    # as a generic connect failure, so the exit status is the assertion here and the
    # mechanism is pinned down separately below.
    curl("http://localhost/healthz", user="mp-outsider", succeed=False)

    # The reason is the directory, not the socket inode: 0750 and group-owned means an
    # outsider cannot traverse in, which is what SPEC.md §8.1 says carries the access
    # control (the 0660 mode on the socket itself is only defence in depth).
    machine.fail("su - mp-outsider -c 'ls /run/monitoring-platform'")
    machine.succeed(f"su - {CLIENT} -c 'ls /run/monitoring-platform'")

    # And the socket itself is reachable for the group, i.e. the directory is the only
    # gate and the socket's own mode is not accidentally stricter.
    machine.succeed(f"su - {CLIENT} -c 'test -S {SOCKET}'")
  '';
}
