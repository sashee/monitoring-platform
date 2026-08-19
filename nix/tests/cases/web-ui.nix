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
