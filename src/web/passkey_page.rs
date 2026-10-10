//! The browser side of passkeys (SPEC §14.10): the two forms, the options they answer, and the scripts that
//! join them — one on the account page to add a passkey, one on the login page to sign in with one.
//!
//! **The only scripts in this interface**, and kept to one job: WebAuthn has no HTML-form API, so a script
//! reads the server's options, asks the browser, and posts the browser's answer back in an ordinary form.
//! Nothing is fetched and nothing else on the page is touched.
//!
//! The options travel as JSON in a `<script type="application/json">`, which a browser never executes. JSON
//! may contain `</script>` inside a string — the username is in there — so every `<` is written as
//! `\u003c`, which JSON reads back as the same character.

use super::html;

/// What both scripts start with: the options, the status line, and base64url to and from bytes.
///
/// Converts by hand between WebAuthn's JSON (base64url strings) and the `ArrayBuffer`s the API takes, rather
/// than relying on `parseCreationOptionsFromJSON` and `toJSON`, which not every browser this is opened in has
/// yet. Where the browser does have `toJSON`, its own output is used.
macro_rules! helpers {
    () => {
        r#"
  const status = document.getElementById("passkey-status");
  const options = JSON.parse(document.getElementById("passkey-options").textContent);
  const bytes = (text) =>
    Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const text = (buffer) =>
    btoa(String.fromCharCode(...new Uint8Array(buffer)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const ids = (list) => (list || []).map((c) => ({ ...c, id: bytes(c.id) }));
  const supported = () => {
    if (window.PublicKeyCredential) return true;
    status.textContent = "This browser does not support passkeys.";
    return false;
  };
"#
    };
}

/// Asks the browser to create a passkey and posts it.
///
/// `authenticatorData`, `publicKey` and `publicKeyAlgorithm` are sent together or not at all: the server
/// reads the first two to locate what the third describes, so one without the others is a malformed
/// response.
const REGISTER: &str = concat!(
    "(() => {",
    helpers!(),
    r#"
  const form = document.getElementById("passkey-add");
  const json = (credential) => {
    if (typeof credential.toJSON === "function") return credential.toJSON();
    const response = credential.response;
    const key = response.getPublicKey ? response.getPublicKey() : null;
    return {
      id: credential.id,
      rawId: text(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: text(response.clientDataJSON),
        attestationObject: text(response.attestationObject),
        transports: response.getTransports ? response.getTransports() : [],
        ...(key ? {
          authenticatorData: text(response.getAuthenticatorData()),
          publicKey: text(key),
          publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
        } : {}),
      },
    };
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!supported()) return;
    status.textContent = "Waiting for the passkey prompt…";
    const publicKey = {
      ...options,
      challenge: bytes(options.challenge),
      user: { ...options.user, id: bytes(options.user.id) },
      excludeCredentials: ids(options.excludeCredentials),
    };
    try {
      const credential = await navigator.credentials.create({ publicKey });
      form.elements.response.value = JSON.stringify(json(credential));
      form.submit();
    } catch (error) {
      status.textContent = error.name === "InvalidStateError"
        ? "This device already has a passkey for your account here."
        : "No passkey was added: " + error.message;
    }
  });
})();"#
);

/// Asks the browser for a passkey to sign in with and posts the signed answer.
const SIGN_IN: &str = concat!(
    "(() => {",
    helpers!(),
    r#"
  const form = document.getElementById("passkey-sign-in");
  const json = (credential) => {
    if (typeof credential.toJSON === "function") return credential.toJSON();
    const response = credential.response;
    return {
      id: credential.id,
      rawId: text(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: text(response.clientDataJSON),
        authenticatorData: text(response.authenticatorData),
        signature: text(response.signature),
        userHandle: response.userHandle ? text(response.userHandle) : null,
      },
    };
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!supported()) return;
    status.textContent = "Waiting for the passkey prompt…";
    const publicKey = {
      ...options,
      challenge: bytes(options.challenge),
      allowCredentials: ids(options.allowCredentials),
    };
    try {
      const credential = await navigator.credentials.get({ publicKey });
      form.elements.response.value = JSON.stringify(json(credential));
      form.submit();
    } catch (error) {
      status.textContent = error.name === "NotAllowedError"
        ? "No passkey was used."
        : "Signing in with a passkey failed: " + error.message;
    }
  });
})();"#
);

/// The account page's "add a passkey" form, answering registration `options`.
pub fn add_form(options: &str, max_label_chars: usize) -> String {
    let form = format!(
        "<form method=\"post\" action=\"/account/passkeys/create\" class=\"filters\" id=\"passkey-add\">\
         <label>name<input name=\"label\" required maxlength=\"{max_label_chars}\" placeholder=\"phone\" \
         autocomplete=\"off\"></label>\
         <input type=\"hidden\" name=\"response\">\
         <button type=\"submit\" class=\"go\">add a passkey</button>\
         </form>\n"
    );
    with_script(&form, options, REGISTER, "Adding a passkey needs JavaScript: the browser only creates one when a script asks it to.")
}

/// The login page's "sign in with a passkey" button, answering sign-in `options`.
pub fn sign_in_form(options: &str) -> String {
    let form = "<form method=\"post\" action=\"/login/passkey\" class=\"login\" id=\"passkey-sign-in\">\
                <input type=\"hidden\" name=\"response\">\
                <button type=\"submit\">sign in with a passkey</button>\
                </form>\n";
    with_script(form, options, SIGN_IN, "Signing in with a passkey needs JavaScript. The sign-in token form works without it.")
}

fn with_script(form: &str, options: &str, script: &str, without_script: &str) -> String {
    format!(
        "{form}<p class=\"note\" id=\"passkey-status\" role=\"status\"></p>\n\
         <noscript><p class=\"note\">{}</p></noscript>\n\
         <script type=\"application/json\" id=\"passkey-options\">{}</script>\n\
         <script>{script}</script>\n",
        html::escape(without_script),
        options.replace('<', "\\u003c")
    )
}

/// What a page says on an address passkeys cannot be bound to: a link to the same `path` under `localhost`,
/// where the tunnel's port answers too. `doing` finishes the sentence "Passkeys can only be … on a localhost
/// address".
pub fn not_localhost(host: Option<&str>, path: &str, doing: &str) -> String {
    let port = host
        .and_then(|h| h.rsplit_once(':'))
        .map(|(_, port)| port)
        .filter(|p| p.parse::<u16>().is_ok());
    let target = match port {
        Some(port) => format!("http://localhost:{port}{path}"),
        None => format!("http://localhost{path}"),
    };
    format!(
        "<p class=\"note\">Passkeys can only be {} on a localhost address — browsers do not offer them on an \
         IP address. Open <a href=\"{1}\">{1}</a>. (Cookies belong to the address, so you sign in there \
         separately.)</p>\n",
        html::escape(doing),
        html::escape(&target)
    )
}
