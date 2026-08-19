//! HTML rendering (SPEC §14). Pure: every function here is a value in, a `String` out.
//!
//! **No templating crate.** The pages are a login form and three tables; a template engine would be a
//! dependency, a build-time asset path and a second language to debug, in exchange for string
//! interpolation that `format!` already does. This repo declares one protobuf message by hand rather
//! than pull in `tonic-types` (see [`crate::api::status`]) — the same trade.
//!
//! The cost of hand-written HTML is that escaping is now this module's job rather than a library's, so
//! [`escape`] is the load-bearing function here and is tested as such.
//!
//! **Every URL is root-relative.** The receiver listens on a unix socket and the browser reaches it
//! through a tunnel and a local TCP shim (SPEC §14), so the `Host` it sees is whatever that shim is
//! bound to — `127.0.0.1:8080` today, something else from anywhere else. An absolute URL would work
//! from exactly one vantage point.

/// Escapes text for interpolation into HTML.
///
/// All five of the classic characters, including both quote forms, so the result is safe in an attribute
/// value as well as in element content — a function that were only safe in one of the two positions would
/// be an invitation to use it in the other.
///
/// Everything rendered from the database goes through this. Measurement `type` values, attribute keys and
/// JSON bodies are device-supplied: a device is free to send `<script>` as an event name, and nothing
/// upstream of here rejects it (SPEC §5.2 stores attribute keys verbatim by design).
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Inline stylesheet, so the receiver serves no second request and needs no static-file route.
///
/// A `/static/style.css` route would mean a path-handling surface — traversal, content types, caching —
/// for a page whose entire styling is a monospace font and some borders.
const STYLE: &str = "\
:root{color-scheme:light dark}\
body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:2rem auto;max-width:70rem;padding:0 1rem;line-height:1.5}\
h1{font-size:1.2rem;margin:0}\
nav{display:flex;gap:1rem;align-items:baseline;margin-bottom:1.5rem;flex-wrap:wrap}\
nav form{margin:0 0 0 auto}\
table{border-collapse:collapse;width:100%;font-size:.85rem}\
th,td{text-align:left;padding:.35rem .6rem;border-bottom:1px solid rgba(128,128,128,.35);vertical-align:top}\
th{font-weight:600;white-space:nowrap}\
td.wrap{word-break:break-all}\
.empty{opacity:.7;font-style:italic}\
.error{color:#b00020;font-weight:600}\
@media(prefers-color-scheme:dark){.error{color:#ff6b6b}}\
label{display:block;margin-bottom:.75rem}\
input{font:inherit;padding:.4rem;width:100%;box-sizing:border-box}\
button{font:inherit;padding:.4rem .8rem;cursor:pointer}\
form.login{max-width:22rem}\
";

/// The shell every signed-in page shares: nav, and a logout button.
///
/// `content` is inserted verbatim, so it must already be escaped. That is why the assembling functions in
/// [`super`] build their rows with [`escape`] rather than handing raw values here.
pub fn page(title: &str, current_path: &str, content: &str) -> String {
    let nav = [("/", "measurements"), ("/users", "users"), ("/sessions", "sessions")]
        .iter()
        .map(|(path, label)| {
            if *path == current_path {
                format!("<strong>{}</strong>", escape(label))
            } else {
                format!(r#"<a href="{}">{}</a>"#, escape(path), escape(label))
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "{}<title>{} — monitoring platform</title>\n<style>{}</style>\n\
         <nav>\n<h1>monitoring platform</h1>\n{}\n\
         <form method=\"post\" action=\"/logout\"><button type=\"submit\">log out</button></form>\n\
         </nav>\n{}\n",
        DOCTYPE,
        escape(title),
        STYLE,
        nav,
        content
    )
}

/// `lang` is set because a screen reader needs it, and the charset because a page without one is at the
/// mercy of the browser's guess — which for UTF-8 content is a guess that can go wrong.
const DOCTYPE: &str = "<!doctype html>\n<html lang=\"en\">\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n";

/// The login form. Deliberately shares nothing with [`page`]: it has no nav, because every link in it
/// leads somewhere that would bounce straight back here, and no logout button for the same reason.
///
/// `error` is rendered when a previous attempt failed. It is a fixed string chosen by the caller, never
/// anything the request supplied — see [`super::login`] for why the message is identical for every way a
/// login can fail.
pub fn login(error: Option<&str>) -> String {
    let message = match error {
        Some(text) => format!("<p class=\"error\">{}</p>\n", escape(text)),
        None => String::new(),
    };

    format!(
        "{}<title>log in — monitoring platform</title>\n<style>{}</style>\n\
         <h1>monitoring platform</h1>\n\
         <form class=\"login\" method=\"post\" action=\"/login\">\n{}\
         <label>username<input name=\"username\" autocomplete=\"username\" autofocus required></label>\n\
         <label>password<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label>\n\
         <button type=\"submit\">log in</button>\n\
         </form>\n",
        DOCTYPE, STYLE, message
    )
}

/// A table, or a note that there is nothing to show.
///
/// The empty case is spelled out rather than rendered as a table with no rows: "no measurements yet" is
/// an answer, where a bare header row leaves the reader wondering whether the page failed.
pub fn table(headers: &[&str], rows: &[Vec<String>], empty: &str) -> String {
    if rows.is_empty() {
        return format!("<p class=\"empty\">{}</p>\n", escape(empty));
    }

    let head = headers.iter().map(|h| format!("<th>{}</th>", escape(h))).collect::<String>();
    let body = rows
        .iter()
        .map(|row| {
            let cells = row.iter().map(|cell| format!("<td class=\"wrap\">{cell}</td>")).collect::<String>();
            format!("<tr>{cells}</tr>")
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!("<table>\n<thead><tr>{head}</tr></thead>\n<tbody>\n{body}\n</tbody>\n</table>\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_all_five_characters() {
        assert_eq!(escape("&"), "&amp;");
        assert_eq!(escape("<"), "&lt;");
        assert_eq!(escape(">"), "&gt;");
        assert_eq!(escape("\""), "&quot;");
        assert_eq!(escape("'"), "&#39;");
    }

    /// The ampersand has to be replaced first, or escaping its own replacements double-escapes them.
    #[test]
    fn does_not_double_escape() {
        assert_eq!(escape("a&lt;b"), "a&amp;lt;b");
        assert_eq!(escape("<&>"), "&lt;&amp;&gt;");
    }

    /// The regression test the function exists for: a device may send `<script>` as an event name, and
    /// nothing before this point rejects it.
    #[test]
    fn a_script_tag_cannot_survive_escaping() {
        let escaped = escape("<script>alert('x')</script>");
        assert!(!escaped.contains('<'), "{escaped}");
        assert!(!escaped.contains('>'), "{escaped}");
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
    }

    /// Both quote forms, because a value interpolated into an attribute can break out of either. This is
    /// what makes one escape function correct in both positions.
    #[test]
    fn cannot_break_out_of_an_attribute() {
        for hostile in ["\" onclick=\"evil()", "' onclick='evil()"] {
            let rendered = format!(r#"<a href="{}">x</a>"#, escape(hostile));
            assert!(!rendered.contains("onclick=\"evil"), "{rendered}");
            assert!(!rendered.contains("onclick='evil"), "{rendered}");
        }
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        assert_eq!(escape("cpu.temperature 42.5 °C — dev-7"), "cpu.temperature 42.5 °C — dev-7");
        assert_eq!(escape(""), "");
    }

    #[test]
    fn an_empty_table_says_so_instead_of_rendering_a_header() {
        let rendered = table(&["a"], &[], "nothing here");
        assert!(rendered.contains("nothing here"));
        assert!(!rendered.contains("<table"), "{rendered}");
    }

    #[test]
    fn a_table_renders_its_headers_and_rows() {
        let rendered =
            table(&["id", "type"], &[vec!["ab".into(), "cpu".into()]], "nothing here");
        assert!(rendered.contains("<th>id</th>"));
        assert!(rendered.contains("<td class=\"wrap\">cpu</td>"));
    }

    /// Table headers are escaped even though they are static today, so a later dynamic column cannot
    /// introduce a hole.
    #[test]
    fn table_headers_are_escaped() {
        assert!(table(&["<b>"], &[vec!["x".into()]], "empty").contains("&lt;b&gt;"));
    }

    /// The nav marks where you are rather than linking to it, so every page has exactly one non-link.
    #[test]
    fn the_current_page_is_not_a_link_to_itself() {
        let rendered = page("users", "/users", "<p>x</p>");
        assert!(rendered.contains("<strong>users</strong>"), "{rendered}");
        assert!(!rendered.contains(r#"<a href="/users">"#), "{rendered}");
        assert!(rendered.contains(r#"<a href="/sessions">"#));
    }

    /// Root-relative, because the origin the browser sees depends on where the tunnel's shim is bound.
    #[test]
    fn links_and_form_targets_are_root_relative() {
        let rendered = page("measurements", "/", "");
        assert!(!rendered.contains("http://"), "{rendered}");
        assert!(rendered.contains(r#"action="/logout""#));
        assert!(login(None).contains(r#"action="/login""#));
        assert!(!login(None).contains("http://"));
    }

    #[test]
    fn the_login_form_shows_an_error_only_when_there_is_one() {
        assert!(!login(None).contains("class=\"error\""));

        let failed = login(Some("that did not work"));
        assert!(failed.contains("class=\"error\""));
        assert!(failed.contains("that did not work"));
    }

    /// No nav and no logout button: every link on it would bounce straight back to the form.
    #[test]
    fn the_login_page_offers_nothing_to_click_through_to() {
        let rendered = login(None);
        assert!(!rendered.contains("<nav"), "{rendered}");
        assert!(!rendered.contains("/logout"), "{rendered}");
    }
}
