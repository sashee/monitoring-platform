# The whole path a device exercises, over the real socket on a real system:
# protobuf in, rows in SQLite, JSON back out.
#
# The router-level Rust tests already cover the mapping rules exhaustively; what is
# only reachable here is that they still work through systemd's sandbox, as the
# service user, against the provisioned StateDirectory.
#
# Assertions are relative, never absolute: this is a lightweight case sharing one VM
# with the others, so the database is not empty when it starts.
{ pkgs }:
{
  testScript = ''
    def gps_rows():
        return get_json("/v1/measurements?type=gps&limit=100")["measurements"]

    payload = sample_batch()
    before = row_count()
    gps_before = len(gps_rows())

    post_protobuf(payload)
    assert row_count() == before + 3, "the three sample records should have landed"

    # The same file again, gzipped. Two things at once: gzip works over the socket, and identity is
    # content-based rather than wire-based — the request bytes differ completely, yet these are the
    # same measurements, so nothing new may be stored (SPEC §6.6). This is the retry-after-a-lost-ack
    # case that §4.1's retryable 503 deliberately invites.
    machine.succeed(f"gzip -c {payload} > {payload}.gz")
    post_protobuf(f"{payload}.gz", extra="-H 'Content-Encoding: gzip'")
    assert row_count() == before + 3, "a re-upload must not store anything"

    rows = gps_rows()
    assert len(rows) == gps_before + 1, f"expected 1 new gps row, got {len(rows) - gps_before}"

    a = rows[0]

    # Structural attribute prefixes survive the round trip.
    attrs = a["attributes"]
    assert attrs["resource.attributes.device.id"] == "dev-7", attrs
    assert attrs["scope.name"] == "sensors", attrs
    assert attrs["record.attributes.unit"] == "wgs84", attrs

    # Nanosecond timestamps are strings, so a JSON parser backed by f64 cannot
    # silently round them.
    assert isinstance(a["event_time_unix_nano"], str), a
    assert int(a["event_time_unix_nano"]) > 0
    assert a["event_time"].endswith("Z") and "." in a["event_time"], a["event_time"]

    # Ids are the content hash: lowercase hex, fixed width (SPEC §6.6).
    assert isinstance(a["id"], str) and len(a["id"]) == 32, a["id"]
    assert all(c in "0123456789abcdef" for c in a["id"]), a["id"]

    # An integer attribute filter: this is the case that silently matched nothing
    # before the CAST in the query builder, so a regression would show up here as
    # zero rows rather than as an error.
    hits = get_json("/v1/measurements?attr.record.attributes.sensor.index=0")["measurements"]
    assert len(hits) >= 1, f"integer attribute filter returned {len(hits)} rows"

    # A wrong content type is refused, and the error body is protobuf as OTLP
    # requires. Written with -w/-o rather than --fail-with-body so the status and
    # content type are both observable in one request.
    got = curl_raw(
        f"-o /tmp/err.bin -w '%{{http_code}} %{{content_type}}' "
        f"-X POST -H 'Content-Type: application/json' "
        f"--data-binary @{payload} http://localhost/v1/logs"
    ).strip()
    assert got == "415 application/x-protobuf", f"unexpected error response: {got!r}"
    # Field 2 (message), wire type 2 → first byte 0x12, and a non-empty length.
    head = machine.succeed("od -An -tx1 -N2 /tmp/err.bin").split()
    assert head[0] == "12" and int(head[1], 16) > 0, f"error body is not a Status: {head}"

    assert row_count() == before + 3, "a refused request must not store anything"

    # Unknown query parameters fail loudly instead of widening the result set.
    curl("http://localhost/v1/measurements?typo=x", succeed=False)
  '';
}
