"""Passkeys in a real browser (SPEC §14.10).

The Rust suite drives the server with a software authenticator written to match it, and never runs the pages'
scripts. This runs them, in Chromium, with Chromium's own WebAuthn behind a virtual authenticator — so what is
checked is everything a person's browser does: the page's script reads the options, the browser fills in the
RP ID from the host, treats `*.localhost` as a secure context and honours `excludeCredentials`, and the
script posts its answer back to the release binary.

    nix-build nix -A tests.browser-passkeys     # also built by `make run-tests`

Reached the way a person reaches it: the binary listens on a unix socket and socat forwards a loopback TCP port
to it, as the tunnel shim does (SPEC §14.5). Chromium resolves `*.localhost` to loopback by itself, so each
check can use its own site on the one port without any DNS.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

BINARY = os.environ.get("MP_BIN", "monitoring-platform")
USER = "sashee"

failures: list[str] = []


def check(name: str, condition: bool, detail: object = "") -> None:
    print(("  ok    " if condition else "  FAIL  ") + name + ("" if condition else f": {detail}"), flush=True)
    if not condition:
        failures.append(name)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(condition, what: str, seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise TimeoutError(f"{what} within {seconds}s")


def healthy(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
            return response.status == 200
    except OSError:
        return False


def main() -> int:
    work = tempfile.mkdtemp()
    db, sock, log = (os.path.join(work, name) for name in ("m.db", "m.sock", "server.log"))
    # The token it prints goes unused: each browser profile signs in with one of its own (`signed_in`).
    subprocess.run([BINARY, "create-user", "--db", db, "--username", USER], check=True, stdout=subprocess.DEVNULL)
    port = free_port()
    with open(log, "w") as server_log:
        server = subprocess.Popen([BINARY, "serve", "--socket", sock, "--db", db], stdout=server_log, stderr=server_log)
        shim = subprocess.Popen(
            ["socat", f"TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr", f"UNIX-CONNECT:{sock}"],
            stderr=subprocess.DEVNULL,
        )
    try:
        wait_for(lambda: healthy(port), "the receiver answering through the shim")
        run_checks(port, db)
    finally:
        shim.terminate()
        server.terminate()
        if failures:
            print("--- receiver log ---\n" + open(log).read(), flush=True)

    print("passed" if not failures else f"FAILED: {', '.join(failures)}", flush=True)
    return 1 if failures else 0


def sign_in_token(db: str) -> str:
    """A fresh sign-in token, as the operator issues one on the host. The receiver is running: a second
    writer, as it is on the Pi."""
    issued = subprocess.run(
        [BINARY, "create-login-token", "--db", db, "--username", USER], check=True, capture_output=True, text=True
    )
    return issued.stdout.strip()


def run_checks(port: int, db: str) -> None:
    with sync_playwright() as playwright:
        # No sandbox: Chromium's needs user namespaces, which the Nix build sandbox does not offer, and this
        # browser only ever loads the page under test.
        browser = playwright.chromium.launch(
            executable_path=shutil.which("chromium"), args=["--no-sandbox", "--disable-dev-shm-usage"]
        )

        def signed_in(host: str, without_tojson: bool = False):
            """A fresh browser profile with its own virtual authenticator, signed in with a sign-in token."""
            context = browser.new_context()
            page = context.new_page()
            if without_tojson:
                # The script's own JSON, for a browser that predates `toJSON`.
                page.add_init_script("delete PublicKeyCredential.prototype.toJSON;")
            cdp = context.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            cdp.send(
                "WebAuthn.addVirtualAuthenticator",
                {
                    "options": {
                        "protocol": "ctap2",
                        "transport": "internal",
                        "hasResidentKey": True,
                        "hasUserVerification": True,
                        "isUserVerified": True,
                    }
                },
            )
            base = f"http://{host}:{port}"
            page.goto(f"{base}/login")
            page.fill("input[name=token]", sign_in_token(db))
            with page.expect_navigation():
                page.click("form[action='/login'] button")
            check(f"a sign-in token lands on the account page at {host}", page.url == f"{base}/account", page.url)
            return page, base

        def submit(page, button: str) -> str | None:
            """Presses a passkey button that should end in a navigation. `None` if it did; otherwise what the
            page's status line says, which is where the script reports a failure — so a broken script fails a
            check with its own error message rather than with a bare timeout."""
            try:
                with page.expect_navigation(timeout=15_000):
                    page.click(button)
                return None
            except PlaywrightTimeout:
                status = page.query_selector("#passkey-status")
                return f"no navigation; the page says: {status.inner_text() if status else '(no status line)'}"

        def add_passkey(page, base: str, label: str) -> str | None:
            page.goto(f"{base}/account")
            page.fill("#passkey-add input[name=label]", label)
            return submit(page, "#passkey-add button")

        def cells(page, column: str) -> list[str]:
            return page.locator(f"td[data-label='{column}']").all_inner_texts()

        def sign_out_and_back_in_with_the_passkey(page) -> str:
            with page.expect_navigation():
                page.click("nav button")
            return submit(page, "#passkey-sign-in button") or page.url

        page, base = signed_in("alpha.localhost")
        error = add_passkey(page, base, "laptop")
        check("a passkey added through the page's button is listed", cells(page, "name") == ["laptop"], error or cells(page, "name"))
        check("bound to the host the page was opened at", cells(page, "site") == ["alpha.localhost"], cells(page, "site"))

        # The same authenticator again: the existing passkey is in excludeCredentials, so the browser refuses
        # it, and the page says why instead of failing silently.
        page.goto(f"{base}/account")
        page.fill("#passkey-add input[name=label]", "again")
        page.click("#passkey-add button")
        try:
            page.wait_for_function("document.getElementById('passkey-status').textContent.includes('already')", timeout=15_000)
        except PlaywrightTimeout:
            pass
        status = page.inner_text("#passkey-status")
        check("a second passkey from the same device is refused, and the page says so", "already has a passkey" in status, status)

        url = sign_out_and_back_in_with_the_passkey(page)
        check("after logging out, the passkey button signs back in", url == f"{base}/", url)
        page.goto(f"{base}/account")
        # Exactly one row, not merely "not never": signed out, the account page is the login form and has no
        # table at all, which must not pass for a recorded use.
        last_used = cells(page, "last used")
        check("and the sign-in is recorded as the passkey's last use", len(last_used) == 1 and last_used != ["never"], last_used)

        page, base = signed_in("beta.localhost", without_tojson=True)
        error = add_passkey(page, base, "no-tojson")
        check("without toJSON, the script's own JSON registers a passkey", cells(page, "name") == ["no-tojson", "laptop"], error or cells(page, "name"))
        url = sign_out_and_back_in_with_the_passkey(page)
        check("and signs in with it", url == f"{base}/", url)

        # Browsers refuse WebAuthn on an IP address, so neither page offers a passkey there — each links to
        # itself under localhost instead.
        page, base = signed_in("127.0.0.1")
        page.goto(f"{base}/account")
        check(
            "the account page at 127.0.0.1 links to localhost instead of offering a passkey",
            page.query_selector("#passkey-add") is None
            and page.query_selector(f"a[href='http://localhost:{port}/account']") is not None,
        )
        page.goto(f"{base}/login")
        check(
            "and so does the login page",
            page.query_selector("#passkey-sign-in") is None
            and page.query_selector(f"a[href='http://localhost:{port}/login']") is not None,
        )
        browser.close()


if __name__ == "__main__":
    sys.exit(main())
