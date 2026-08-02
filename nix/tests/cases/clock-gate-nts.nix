# The gate opens for a machine that keeps time the way the real fleet does: chrony with
# NTS against a fixed list of server names.
#
# This is the shape ../lib.nix exists to support, and without a case for it here the NTS
# wiring would be dead code in this repo's CI — exercised only when an external repo
# imports the harness with its real host module, which is exactly where a failure is
# most expensive to diagnose.
#
# Nothing about the machine's chrony configuration is modified. The harness resolves those
# server names to the helper node and trusts the CA behind its certificate, so what runs
# is the production config performing a genuine NTS-KE handshake against a real NTS
# server. That distinction is what the `authdata` assertion below is for: a fallback to
# plain NTP would still synchronize the clock and still open the gate, and would otherwise
# look identical.
{ pkgs }:
{
  isolate = true;

  machineModules = [
    {
      # Deliberately names that cannot resolve anywhere else: if the /etc/hosts override
      # ever stops being applied, this fails as "never synchronized" rather than quietly
      # reaching the real internet and passing for the wrong reason.
      services.chrony = {
        enable = true;
        enableNTS = true;
        servers = [
          "time1.example.test"
          "time2.example.test"
        ];
      };
    }
  ];

  testScript = ''
    ntp.wait_for_unit("chronyd.service")

    with subtest("the machine's own chrony config was left alone"):
        conf = machine.succeed("systemctl cat chronyd.service | grep -o '/nix/store/[^ ]*chrony.conf'")
        conf = machine.succeed(f"cat {conf.strip()}")
        # The real server names, over NTS — not rewritten to point at the helper.
        assert "server time1.example.test iburst nts" in conf, (
            f"the harness rewrote the machine's chrony config instead of impersonating "
            f"its servers:\n{conf}"
        )
        assert "ntp-server" not in conf, f"helper node leaked into the machine's config:\n{conf}"

    with subtest("the names resolve to the helper node"):
        ip = ntp.succeed("ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1").strip()
        for name in ["time1.example.test", "time2.example.test"]:
            resolved = machine.succeed(f"getent hosts {name} | awk '{{print $1}}'").strip()
            assert resolved == ip, f"{name} resolved to {resolved!r}, expected the ntp node {ip!r}"

    with subtest("chrony synchronised over NTS, so the gate opened"):
        # wait_for_unit already ran in the preamble, so reaching here means the boot gate
        # passed — i.e. the kernel's maxerror dropped below the threshold, which only
        # happens if chrony actually reached a server.
        machine.succeed("systemctl is-active --quiet monitoring-platform.service")

        journal = machine.succeed("journalctl -u monitoring-platform.service --no-pager")
        assert "clock synchronized" in journal, f"the gate did not report opening:\n{journal}"

        sources = machine.succeed("chronyc -n sources")
        assert "^*" in sources or "^+" in sources, (
            f"chrony has no usable source, so the clock was set by something else:\n{sources}"
        )

    with subtest("it was really NTS, not a fallback to plain NTP"):
        # authdata reports the authentication mode per source. NTS shows mode NTS with a
        # non-zero cookie count; an unauthenticated source shows "-". Without this the
        # test would pass just as happily against a plain NTP server.
        authdata = machine.succeed("chronyc -N authdata")
        machine.log(authdata)
        lines = authdata.splitlines()

        # Locate the cookie column from the header rather than hardcoding an index: the
        # columns are Name/IP, Mode, KeyID, Type, KLen, Last, Atmp, NAK, Cook, CLen, and
        # counting to the wrong one yields an assertion that passes on KLen no matter what
        # NTS did.
        # "Name/IP address" is two whitespace-separated tokens in the header but one in a
        # data row, so the header has to be normalised before its indices line up.
        header = next(i for i, l in enumerate(lines) if l.startswith("Name/IP"))
        cook_col = lines[header].replace("Name/IP address", "Name").split().index("Cook")

        nts_rows = [
            l.split() for l in lines[header + 1:]
            if l.startswith(("time1.example.test", "time2.example.test")) and "NTS" in l
        ]
        assert nts_rows, f"no source authenticated with NTS:\n{authdata}"
        # Cookies are handed out by the NTS-KE handshake, so a positive count proves the
        # TLS exchange completed and the certificate validated against the injected CA.
        cookies = [int(r[cook_col]) for r in nts_rows]
        assert any(c > 0 for c in cookies), (
            f"NTS mode but no cookies issued, so the NTS-KE handshake did not complete:\n{authdata}"
        )

        assert "certificate" not in machine.succeed(
            "journalctl -u chronyd.service --no-pager"
        ).lower(), "chronyd logged a certificate problem"

    with subtest("a gated service is a working service"):
        post_protobuf(sample_batch("/tmp/nts.pb"))
        assert row_count() == 3
        assert get_json("/healthz")["status"] == "ok"
  '';
}
