# A second writer on the same socket cannot perturb this harness's assertions.
#
# ../lib.nix takes the machine under test as an input, so a consumer runs this suite
# against its own real host config — which normally has a producer of its own posting
# into the same receiver. sashee/nixos-test does exactly that: its Raspberry Pi 5 node
# enables a systemMetrics timer, and its aarch64 crash-recovery job failed with
# "read API returned 12 of 6 rows" when a host batch landed in the 375 ms between the
# sqlite count and the read-API call. The x86 job passed only because the whole case
# finishes before the timer's first fire, five minutes in.
#
# Every helper is therefore scoped to resource.attributes.device.id. This case asserts
# that property directly — no timers, no sleeps — so a regression fails here in seconds
# instead of resurfacing as an intermittent five-minute TCG race in a consumer's CI.
#
# Isolated because it asserts absolute counts, and because a foreign row deliberately
# left in the table would be a booby trap for the other lightweight cases.
{ pkgs }:
{
  isolate = true;

  testScript = ''
    post_protobuf(sample_batch("/tmp/ours.pb"))
    mine = row_count()
    total = row_count(device_id=None)
    assert mine == 3, f"expected our 3 rows, got {mine}"
    assert len(sample_rows()) == mine, "the scoped read disagrees with the scoped count"

    # The foreign producer, standing in for the consumer's host metrics: same binary,
    # same socket, same table, distinguishable only by its resource attributes.
    post_protobuf(sample_batch("/tmp/theirs.pb", device_id="other-device"))

    assert row_count(device_id=None) == total + 3, "the foreign batch never landed"
    assert row_count() == mine, "a foreign batch moved the scoped sqlite count"
    assert len(sample_rows()) == mine, "a foreign batch moved the scoped read API result"

    # The scoping predicate has two silent failure modes, and the assertions above only
    # catch one each: a JSON path that matches NOTHING makes every scoped count 0 — which
    # `mine == 3` catches — while a predicate that matches EVERYTHING is caught by the two
    # unchanged-count assertions. This last one pins the middle case, a predicate that
    # discriminates but on the wrong value.
    assert row_count(device_id="other-device") == 3, "the scoping predicate does not select"
  '';
}
