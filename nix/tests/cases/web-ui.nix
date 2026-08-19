# The web interface over the real socket on a real system (SPEC.md §14).
#
# The router-level Rust tests in tests/web.rs cover the login, guard and rendering rules exhaustively.
# What is only reachable here is that they still work through systemd's sandbox, as the service user,
# against the provisioned StateDirectory — and, specifically, that `create-user` can write to a database
# the running service holds open. That is a second writer against a live receiver, which is safe because
# of WAL and `busy_timeout` (SPEC.md §6.1) and is the kind of claim a unit test cannot make.
#
# A lightweight case sharing one VM, so the database is not empty when it starts and the machine may be
# running a producer of its own. Nothing here counts measurement rows for that reason; it asserts on
# status codes, headers, and whether the *user* it created is on the page.
{ pkgs }:
{
  testScript = ''
    # A second writer against the running service. This is the assertion that cannot be made off-VM.
    create_web_user()

    # Present, and reachable without a credential of any kind — a login form behind a login would be a
    # locked door with the key inside.
    form = web_curl("http://localhost/login")
    assert http_status(form) == 200, form
    assert 'name="password"' in form, form

    # Every page must refuse a request with no cookie, and must not leak what it would have shown.
    for path in ["/", "/users", "/sessions"]:
        anonymous = web_curl(f"http://localhost{path}")
        assert http_status(anonymous) == 303, f"{path}: {anonymous}"
        assert "location: /login" in anonymous.lower(), f"{path}: {anonymous}"
        assert WEB_USER not in anonymous, f"{path} leaked the user list: {anonymous}"

    # A wrong password establishes nothing. Checked before the successful login, so a cookie left over
    # from an earlier step cannot make this pass.
    refused = web_curl(
        "-X POST --data-urlencode " + shlex.quote(f"username={WEB_USER}")
        + " --data-urlencode password=wrong http://localhost/login"
    )
    assert http_status(refused) == 401, refused
    assert "mp_session=" not in refused, f"a failed login set a cookie: {refused}"

    # The real thing.
    cookie = web_login()

    # The cookie is a session token, not something that could be mistaken for an API key — the prefixes
    # are what keep the two credentials apart.
    assert cookie.startswith("mps_"), cookie

    # The attributes the browser depends on, read off the wire rather than off the builder that made them.
    established = web_curl(
        "-X POST --data-urlencode " + shlex.quote(f"username={WEB_USER}")
        + " --data-urlencode " + shlex.quote(f"password={WEB_PASSWORD}")
        + " http://localhost/login"
    )
    set_cookie = [l for l in established.splitlines() if l.lower().startswith("set-cookie:")][0]
    assert "HttpOnly" in set_cookie, set_cookie
    assert "SameSite=Strict" in set_cookie, set_cookie
    assert "Path=/" in set_cookie, set_cookie
    # Deliberately absent: the browser reaches this over plain HTTP through a tunnel, so Secure would
    # make every request after login anonymous (SPEC.md §14).
    assert "Secure" not in set_cookie, set_cookie

    # With the cookie, the pages answer.
    for path in ["/", "/users", "/sessions"]:
        page = web_curl(f"http://localhost{path}", cookie=cookie)
        assert http_status(page) == 200, f"{path}: {page}"
        assert "text/html" in page.lower(), f"{path}: {page}"

    # And the user it created is on the users page, which is what proves the page is reading the same
    # database `create-user` wrote to — the mistake a wrong --db would produce.
    users = web_curl("http://localhost/users", cookie=cookie)
    assert WEB_USER in users, users

    # The CLI listings see it too, and neither prints a secret because neither is stored.
    listed = machine.succeed(
        f"runuser -u {SERVICE_USER} -- monitoring-platform list-users --db {DB} 2>/dev/null"
    )
    assert WEB_USER in listed, listed
    assert WEB_PASSWORD not in listed, "the password must not be printable"

    sessions = machine.succeed(
        f"runuser -u {SERVICE_USER} -- monitoring-platform list-sessions --db {DB} 2>/dev/null"
    )
    assert "live" in sessions, sessions
    assert cookie.split(".", 1)[1] not in sessions, "the session secret must not be printable"

    # **The separation, in both directions** (SPEC.md §13, §14). Each is a distinct mistake, and neither is
    # visible to any other case: every other request in this harness carries an API key, so without this
    # the suite would pass with the two credentials interchangeable.
    for path in ["/v1/measurements", "/v1/logs"]:
        crossed = web_curl(f"http://localhost{path}", cookie=cookie)
        assert http_status(crossed) in (401, 405), (
            f"a session cookie was accepted on {path}: {crossed}"
        )

    # ...and an API key must not open a page. curl() is the helper that sends the key.
    keyed = curl_raw(
        "-o /dev/null -w '%{http_code}' -D /tmp/keyed-headers http://localhost/users"
    ).strip()
    assert keyed == "303", f"an API key opened a page: {keyed}"
    assert WEB_USER not in machine.succeed("cat /tmp/keyed-headers")

    # **The origin check** (SPEC.md §14.3), against the real unit. Two refusals, one for each way the
    # check can fail, and each must leave the database untouched — a 403 that still wrote would be worse
    # than no check at all.
    forged = web_curl(
        "-X POST --data-urlencode username=intruder --data-urlencode password=whatever "
        "http://localhost/users/create",
        cookie=cookie,
        origin="http://localhost:3000",
    )
    assert http_status(forged) == 403, f"a cross-port POST was not refused: {forged}"

    headerless = web_curl(
        "-X POST --data-urlencode username=intruder2 --data-urlencode password=whatever "
        "http://localhost/users/create",
        cookie=cookie,
        origin=None,
    )
    assert http_status(headerless) == 403, f"a POST with no Origin was not refused: {headerless}"

    listed = machine.succeed(
        f"runuser -u {SERVICE_USER} -- monitoring-platform list-users --db {DB} 2>/dev/null"
    )
    assert "intruder" not in listed, f"a refused POST still wrote to the database: {listed}"

    # **A mutation round trip through the real unit.** This is the assertion that cannot be made off-VM:
    # the handler writes to a database the running service holds open, as the service user, through
    # systemd's sandbox.
    created = web_curl(
        "-X POST --data-urlencode username=second --data-urlencode "
        + shlex.quote(f"password={WEB_PASSWORD}-2")
        + " http://localhost/users/create",
        cookie=cookie,
    )
    assert http_status(created) == 303, created

    users_page = web_curl("http://localhost/users", cookie=cookie)
    assert "second" in users_page, users_page

    # And the new user can actually log in, which is what proves the hash the form stored is one the login
    # path accepts — a create that wrote an unusable hash would look identical up to here.
    second_cookie = web_login(username="second", password=f"{WEB_PASSWORD}-2")
    assert http_status(web_curl("http://localhost/", cookie=second_cookie)) == 200

    # Ending someone else's session must not touch your own.
    second_id = second_cookie.split(".", 1)[0].removeprefix("mps_")
    ended = web_curl(
        f"-X POST --data-urlencode id={second_id} http://localhost/sessions/end", cookie=cookie
    )
    assert http_status(ended) == 303, ended
    assert http_status(web_curl("http://localhost/", cookie=second_cookie)) == 303, "ended"
    assert http_status(web_curl("http://localhost/", cookie=cookie)) == 200, "mine survives"

    # Deleting the user we just made, now that two exist.
    deleted = web_curl(
        "-X POST --data-urlencode username=second http://localhost/users/delete", cookie=cookie
    )
    assert http_status(deleted) == 303, deleted
    listed = machine.succeed(
        f"runuser -u {SERVICE_USER} -- monitoring-platform list-users --db {DB} 2>/dev/null"
    )
    assert "second" not in listed, listed

    # The last remaining user cannot be deleted — a delete button that locks you out is a footgun, and the
    # handler refuses it rather than relying on the page having hidden it.
    refused = web_curl(
        f"-X POST --data-urlencode username={WEB_USER} http://localhost/users/delete", cookie=cookie
    )
    assert http_status(refused) == 400, refused
    listed = machine.succeed(
        f"runuser -u {SERVICE_USER} -- monitoring-platform list-users --db {DB} 2>/dev/null"
    )
    assert WEB_USER in listed, f"the only user must survive: {listed}"

    # **The explorer** over whatever this machine has actually collected (SPEC.md §14.9). No row counts
    # here: the machine under test runs producers of its own, so the assertions are about the page's
    # structure rather than about how many measurements exist.
    explorer = web_curl("'http://localhost/?range=all'", cookie=cookie)
    assert http_status(explorer) == 200, explorer
    assert 'name="range"' in explorer, "the filter row must render"
    assert "measurements over time" in explorer, "the timeline is always shown"
    # The plot is inline SVG referencing palette slots, never a hex literal — the light/dark swap lives in
    # the stylesheet.
    assert "var(--series-1)" in explorer, explorer[:400]

    # Logging out invalidates the cookie the browser is holding.
    logged_out = web_curl("-X POST http://localhost/logout", cookie=cookie)
    assert http_status(logged_out) == 303, logged_out
    assert "max-age=0" in logged_out.lower(), f"the cookie must be cleared: {logged_out}"

    after = web_curl("http://localhost/", cookie=cookie)
    assert http_status(after) == 303, f"a logged-out cookie still worked: {after}"

    # The unit is still healthy after all of that — in particular, the second writer did not wedge it.
    machine.succeed("systemctl is-active monitoring-platform.service")
    assert http_status(web_curl("http://localhost/healthz")) == 200
  '';
}
