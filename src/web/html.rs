//! HTML rendering (SPEC §14). Pure: every function here is a value in, a `String` out.
//!
//! **No templating crate.** The pages are a login form, three tables and two plots; a template engine would be a
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
///
/// **Every colour is a custom property, and the plots reference them by role** (`var(--series-3)`, not a
/// hex literal). Two consequences worth the indirection: the light and dark values are declared in one
/// place each, and `web::svg` cannot render a chart in the wrong mode's palette because it never sees a
/// colour at all.
///
/// The categorical slots are a documented palette used **unchanged and in its published order**, which
/// is the CVD-safety mechanism rather than a cosmetic choice — the order was selected so that every
/// adjacent pair clears its separation gates. It was validated with the palette checker rather than by
/// eye: all checks pass for eight slots in both modes, worst adjacent CVD ΔE 9.1 light / 8.4 dark
/// against a ≥8 target, worst normal-vision ΔE 19.6 / 19.3 against a ≥15 floor.
///
/// On the light surface aqua, yellow and magenta sit below 3:1, which obliges *relief* — the values must
/// be legible without relying on the colour. The measurements table under every plot is that relief, and
/// it is why the table is not collapsible.
///
/// Dark is a **selected** set of steps for the dark surface, not an automatic inversion of the light
/// values. There is no theme toggle, so the media query is the only scope needed.
const STYLE: &str = "\
:root{color-scheme:light dark;\
--surface:#fcfcfb;--text:#0b0b0b;--text-2:#52514e;--muted:#898781;\
--grid:#e1e0d9;--axis:#c3c2b7;--rule:rgba(11,11,11,.10);--err:#b00020;\
--series-1:#2a78d6;--series-2:#eb6834;--series-3:#1baf7a;--series-4:#eda100;\
--series-5:#e87ba4;--series-6:#008300;--series-7:#4a3aa7;--series-8:#e34948}\
@media(prefers-color-scheme:dark){:root{\
--surface:#1a1a19;--text:#fff;--text-2:#c3c2b7;--muted:#898781;\
--grid:#2c2c2a;--axis:#383835;--rule:rgba(255,255,255,.10);--err:#ff6b6b;\
--series-1:#3987e5;--series-2:#d95926;--series-3:#199e70;--series-4:#c98500;\
--series-5:#d55181;--series-6:#008300;--series-7:#9085e9;--series-8:#e66767}}\
body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:2rem auto;max-width:72rem;padding:0 1rem;line-height:1.5;color:var(--text)}\
h1{font-size:1.2rem;margin:0}\
h2{font-size:.95rem;margin:1.5rem 0 .25rem;font-weight:600}\
nav{display:flex;gap:1rem;align-items:baseline;margin-bottom:1.5rem;flex-wrap:wrap}\
nav form{margin:0 0 0 auto}\
table{border-collapse:collapse;width:100%;font-size:.85rem;font-variant-numeric:tabular-nums}\
th,td{text-align:left;padding:.35rem .6rem;border-bottom:1px solid var(--rule);vertical-align:top}\
th{font-weight:600;white-space:nowrap}\
td.wrap{word-break:break-all}\
td.act{white-space:nowrap;width:1%}\
.empty{opacity:.7;font-style:italic}\
.error{color:var(--err);font-weight:600}\
.note{font-size:.8rem;color:var(--text-2);margin:.25rem 0}\
button{font:inherit;padding:.4rem .8rem;cursor:pointer}\
button.link{background:none;border:none;padding:0;color:var(--err);text-decoration:underline;cursor:pointer;font:inherit}\
select,input{font:inherit;padding:.3rem}\
form.login{max-width:22rem}\
form.login label{display:block;margin-bottom:.75rem}\
form.login input{width:100%;box-sizing:border-box;padding:.4rem}\
form.inline{display:inline}\
.filters{display:flex;gap:.75rem;flex-wrap:wrap;align-items:flex-end;\
border:1px solid var(--rule);border-radius:4px;padding:.75rem;margin-bottom:1rem}\
.filters label{display:flex;flex-direction:column;font-size:.75rem;color:var(--text-2);gap:.2rem;\
flex:1 1 9rem;min-width:0}\
.filters select,.filters input{max-width:100%}\
.filters .go{align-self:flex-end;flex:0 0 auto}\
fieldset.fields{border:1px solid var(--rule);border-radius:3px;margin:0;padding:.3rem .5rem;\
flex:1 1 12rem;min-width:0}\
fieldset.fields legend{font-size:.75rem;color:var(--text-2);padding:0 .25rem}\
fieldset.fields label{display:inline-flex;flex-direction:row;align-items:center;gap:.3rem;\
margin-right:.75rem;font-size:.8rem;color:var(--text);flex:0 0 auto}\
fieldset.fields input{width:auto}\
.hint{font-size:.75rem;color:var(--text-2);margin:.35rem 0 0;flex:1 1 100%}\
/* The plot keeps its natural width and scrolls on a narrow screen. Letting it shrink to fit would \
   scale the whole viewBox, and 11px axis labels become unreadable at phone width. */\
.plot-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:.25rem 0}\
.plot{background:var(--surface);border:1px solid var(--rule);border-radius:4px;display:block;\
min-width:38rem}\
.grid{stroke:var(--grid);stroke-width:1}\
.axis{stroke:var(--axis);stroke-width:1}\
.tick{fill:var(--muted);font-size:11px;font-variant-numeric:tabular-nums}\
.tick-y{text-anchor:end}\
.tick-x{text-anchor:middle}\
.col{fill:var(--series-1)}\
.band{fill-opacity:.18}\
.line{stroke-width:2;stroke-linejoin:round;stroke-linecap:round}\
.dot{stroke:var(--surface);stroke-width:2}\
.direct{font-size:11px}\
.empty-plot{fill:var(--muted);font-size:12px}\
.legend{list-style:none;display:flex;gap:1rem;flex-wrap:wrap;padding:0;margin:.25rem 0;font-size:.78rem;color:var(--text-2)}\
.legend .key{display:inline-block;width:14px;height:2px;vertical-align:middle;margin-right:.4rem}\
.constant{font-size:.75rem;color:var(--text-2);margin:.35rem 0}\
.constant code{word-break:break-all}\
/* Narrow screens: the table becomes one card per row. A wide table with JSON in it is unreadable on a \
   phone whichever way you turn it, and horizontal scrolling a table means losing the row you were \
   reading. Each cell carries its column name in data-label, which the ::before below promotes to a \
   label — the standard no-JavaScript responsive-table pattern. */\
@media(max-width:46rem){\
body{margin:1rem auto}\
nav{gap:.6rem}\
nav form{margin-left:0}\
table thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}\
table,tbody,tr,td{display:block;width:auto}\
tr{border:1px solid var(--rule);border-radius:4px;padding:.4rem .6rem;margin-bottom:.6rem}\
td{border:none;padding:.15rem 0;display:flex;gap:.5rem}\
td:before{content:attr(data-label);color:var(--text-2);flex:0 0 7.5rem;font-size:.75rem}\
td:empty{display:none}\
}\
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
///
/// The viewport sets `width=device-width,initial-scale=1` and **nothing else**. No `user-scalable=no` and
/// no `maximum-scale`: blocking pinch-to-zoom fails WCAG 1.4.4, and it would be particularly wrong here,
/// because the plots deliberately scroll rather than shrink (see `.plot-wrap`) so zooming is exactly how a
/// dense chart gets read on a phone.
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
            // `data-label` carries the column name into each cell, which the narrow-screen stylesheet
            // promotes to a visible label once the header row is hidden. Without it a card layout is a
            // stack of unlabelled values.
            let cells = row
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    format!(
                        "<td class=\"wrap\" data-label=\"{}\">{cell}</td>",
                        escape(headers.get(i).copied().unwrap_or_default())
                    )
                })
                .collect::<String>();
            format!("<tr>{cells}</tr>")
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!("<table>\n<thead><tr>{head}</tr></thead>\n<tbody>\n{body}\n</tbody>\n</table>\n")
}

/// A plot, wrapped so it can scroll sideways on a narrow screen rather than shrinking illegibly.
pub fn plot(svg: &str) -> String {
    format!("<div class=\"plot-wrap\">{svg}</div>\n")
}

/// A checkbox group — several values for one parameter name.
///
/// Checkboxes rather than `<select multiple>`: a multi-select needs ctrl-click, which does not exist on a
/// touch screen, and its native mobile rendering is a modal list that hides how many are chosen. Checkboxes
/// also submit only what is ticked, so the parameter simply repeats and an empty set sends nothing.
pub fn checkboxes(name: &str, legend_text: &str, options: &[String], selected: &[String]) -> String {
    let mut out = format!(
        "<fieldset class=\"fields\"><legend>{}</legend>",
        escape(legend_text)
    );
    for option in options {
        out.push_str(&format!(
            "<label><input type=\"checkbox\" name=\"{}\" value=\"{}\"{}>{}</label>",
            escape(name),
            escape(option),
            if selected.contains(option) { " checked" } else { "" },
            escape(option)
        ));
    }
    out.push_str("</fieldset>");
    out
}

/// An explanatory line inside the filter row, for a control whose effect is not obvious from its label.
pub fn hint(text: &str) -> String {
    format!("<p class=\"hint\">{}</p>", escape(text))
}

/// A short note in secondary ink — "showing 8 of 16", "options from the newest 2000 rows".
pub fn note(text: &str) -> String {
    format!("<p class=\"note\">{}</p>\n", escape(text))
}

/// A labelled `<select>`.
///
/// `options` are `(value, label)` pairs. `blank` is the label for the unset option, which is always
/// offered first so a filter can be cleared — a dropdown you cannot get back out of is a trap.
///
/// The selected option is marked server-side. That is the whole state mechanism here: with no
/// JavaScript, the page's controls are re-rendered from the query string on every request, so
/// "selected" is a fact about the URL rather than something the browser remembers.
pub fn select(
    name: &str,
    label: &str,
    options: &[(String, String)],
    selected: Option<&str>,
    blank: &str,
) -> String {
    let mut out = format!(
        "<label>{}<select name=\"{}\">",
        escape(label),
        escape(name)
    );
    let is_selected = |v: &str| selected.is_some_and(|s| s == v);
    out.push_str(&format!(
        "<option value=\"\"{}>{}</option>",
        if selected.is_none_or(str::is_empty) { " selected" } else { "" },
        escape(blank)
    ));
    for (value, text) in options {
        out.push_str(&format!(
            "<option value=\"{}\"{}>{}</option>",
            escape(value),
            if is_selected(value) { " selected" } else { "" },
            escape(text)
        ));
    }
    out.push_str("</select></label>");
    out
}

/// A labelled free-text input, for the filters whose value space is too large to enumerate.
pub fn text_input(name: &str, label: &str, value: Option<&str>, placeholder: &str) -> String {
    format!(
        "<label>{}<input name=\"{}\" value=\"{}\" placeholder=\"{}\" size=\"14\"></label>",
        escape(label),
        escape(name),
        escape(value.unwrap_or("")),
        escape(placeholder)
    )
}

/// A one-button `POST` form, for the mutations.
///
/// Each is its own form because each carries its own hidden field, and because a `GET` link that
/// mutated something would be a link a prefetcher could fire — the same reason `/logout` is a form
/// (SPEC §14.1).
///
/// `confirm` is not offered: there is no JavaScript to run a dialog, and a server-rendered
/// confirmation step would be a second page for an action that is one row in a table. What stands in
/// for it is that these are the only destructive buttons on the site and each names its target.
pub fn post_button(action: &str, field: &str, value: &str, label: &str, class: &str) -> String {
    format!(
        "<form method=\"post\" action=\"{}\" class=\"inline\">\
         <input type=\"hidden\" name=\"{}\" value=\"{}\">\
         <button type=\"submit\" class=\"{}\">{}</button></form>",
        escape(action),
        escape(field),
        escape(value),
        escape(class),
        escape(label)
    )
}

/// The create-user form.
///
/// `autocomplete="new-password"` so a browser offers to generate one rather than filling in the
/// operator's own — the premise of the fast hash (SPEC §14.7) is that these are high-entropy, and a
/// password manager is the realistic way that happens.
pub fn create_user_form() -> String {
    "<h2>add a user</h2>\n\
     <form method=\"post\" action=\"/users/create\" class=\"filters\">\
     <label>username<input name=\"username\" autocomplete=\"off\" required></label>\
     <label>password<input name=\"password\" type=\"password\" autocomplete=\"new-password\" required></label>\
     <button type=\"submit\" class=\"go\">create</button>\
     </form>\n"
        .to_owned()
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
        let rendered = table(&["id", "type"], &[vec!["ab".into(), "cpu".into()]], "nothing here");
        assert!(rendered.contains("<th>id</th>"));
        assert!(rendered.contains(">cpu</td>"), "{rendered}");
    }

    /// Every cell carries its column name, which is what the narrow-screen stylesheet promotes to a label
    /// once the header row is hidden. Without it the card layout is a stack of unlabelled values.
    #[test]
    fn every_cell_carries_its_column_name_for_the_card_layout() {
        let rendered = table(&["id", "type"], &[vec!["ab".into(), "cpu".into()]], "nothing here");
        assert!(rendered.contains(r#"data-label="id""#), "{rendered}");
        assert!(rendered.contains(r#"data-label="type""#), "{rendered}");
    }

    /// A header containing markup must not escape through the attribute either.
    #[test]
    fn the_cell_label_is_escaped() {
        let rendered = table(&[r#"a"b"#], &[vec!["v".into()]], "empty");
        assert!(!rendered.contains(r#"data-label="a"b""#), "{rendered}");
        assert!(rendered.contains("&quot;"), "{rendered}");
    }

    #[test]
    fn checkboxes_mark_what_is_selected() {
        let rendered = checkboxes(
            "field",
            "chart these",
            &["a".to_owned(), "b".to_owned()],
            &["b".to_owned()],
        );
        assert!(rendered.contains(r#"value="b" checked"#), "{rendered}");
        assert!(rendered.contains(r#"value="a">"#), "{rendered}");
        // One name, repeated: an unticked box sends nothing, so the parameter simply repeats.
        assert_eq!(rendered.matches(r#"name="field""#).count(), 2);
    }

    /// The plot scrolls sideways rather than shrinking: scaling the viewBox to phone width would take 11px
    /// axis labels down to about 4px.
    #[test]
    fn a_plot_is_wrapped_in_a_scrollable_container() {
        assert!(plot("<svg/>").contains("class=\"plot-wrap\""));
        assert!(STYLE.contains(".plot-wrap{overflow-x:auto"), "the wrapper must actually scroll");
        assert!(STYLE.contains("min-width:38rem"), "and the plot must keep its width");
    }

    /// **Pinch-to-zoom must keep working.** Blocking it fails WCAG 1.4.4, and it matters more than usual
    /// here: the plots scroll rather than scale, so zooming is how a dense chart is read on a phone. Pinned
    /// because `user-scalable=no` is a thing people add with good intentions to stop iOS zooming on a
    /// focused input.
    #[test]
    fn the_viewport_does_not_block_zooming() {
        let rendered = page("measurements", "/", "");
        assert!(rendered.contains("width=device-width"), "{rendered}");
        for blocking in ["user-scalable=no", "user-scalable=0", "maximum-scale"] {
            assert!(!rendered.contains(blocking), "{blocking} would disable pinch-to-zoom");
            assert!(!login(None).contains(blocking), "{blocking} on the login page");
        }
    }

    /// The card layout is what makes the table readable on a phone, so its two halves are pinned: the
    /// header row is hidden and the per-cell label is shown.
    #[test]
    fn the_narrow_stylesheet_turns_rows_into_cards() {
        assert!(STYLE.contains("@media(max-width:46rem)"));
        assert!(STYLE.contains("table thead{position:absolute"), "the header row is hidden");
        assert!(STYLE.contains("td:before{content:attr(data-label)"), "and each cell labels itself");
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

    // ------------------------------------------------------------------------------- controls

    fn opts(values: &[&str]) -> Vec<(String, String)> {
        values.iter().map(|v| ((*v).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn a_select_marks_the_current_value() {
        let rendered = select("type", "type", &opts(&["cpu", "gps"]), Some("gps"), "any");
        assert!(rendered.contains(r#"<option value="gps" selected>gps</option>"#), "{rendered}");
        assert!(rendered.contains(r#"<option value="cpu">cpu</option>"#), "{rendered}");
    }

    /// A filter you cannot clear is a trap, so the blank option is always first and is selected when
    /// nothing is.
    #[test]
    fn a_select_always_offers_a_way_back_to_unset() {
        let rendered = select("type", "type", &opts(&["cpu"]), None, "any type");
        assert!(rendered.contains(r#"<option value="" selected>any type</option>"#), "{rendered}");

        let rendered = select("type", "type", &opts(&["cpu"]), Some("cpu"), "any type");
        assert!(rendered.contains(r#"<option value="">any type</option>"#), "{rendered}");
    }

    /// Every one of these renders device-supplied text — type names, attribute keys and values all
    /// come off the wire (SPEC §5.2 stores them verbatim).
    #[test]
    fn controls_escape_device_supplied_text() {
        let hostile = r#"<script>"x"</script>"#;
        for rendered in [
            select("k", hostile, &opts(&[hostile]), Some(hostile), hostile),
            text_input(hostile, hostile, Some(hostile), hostile),
            post_button("/x", hostile, hostile, hostile, hostile),
            note(hostile),
        ] {
            assert!(!rendered.contains("<script>"), "unescaped markup: {rendered}");
            assert!(rendered.contains("&lt;script&gt;"), "value must still show: {rendered}");
        }
    }

    /// A mutation must be a POST form, never a link: a `GET` that changes something is a URL a
    /// prefetcher can fire.
    #[test]
    fn a_post_button_is_a_form_not_a_link() {
        let rendered = post_button("/users/delete", "username", "bob", "delete", "link");
        assert!(rendered.contains(r#"method="post""#), "{rendered}");
        assert!(rendered.contains(r#"action="/users/delete""#), "{rendered}");
        assert!(rendered.contains(r#"name="username" value="bob""#), "{rendered}");
        assert!(!rendered.contains("<a "), "{rendered}");
    }
}
