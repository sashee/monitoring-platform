//! Server-rendered inline SVG plots (SPEC §14.9). Pure: data in, a `String` of markup out.
//!
//! **Why SVG built by hand rather than a charting library.** The same reasoning as `html.rs`: a chart
//! library means a dependency, a bundle, and a build step, and §14.6 keeps this page free of all
//! three. Building the marks here costs a few hundred lines of arithmetic that is all pure functions
//! with ordinary unit tests, and the output is a string the browser can render with no JavaScript at
//! all.
//!
//! **Colours are emitted as `var(--series-N)`, never as hex.** The light and dark values live in the
//! stylesheet, so the two modes swap in one place and the markup does not have to know which one is
//! in force — there is no way to render a chart in the wrong mode's palette. The palette itself, and
//! the reasoning behind the eight slots and their fixed order, is in `html.rs`.
//!
//! **Three deliberate departures from what an interactive chart would do**, all following from having
//! no JavaScript:
//!
//! - No crosshair or hover readout. Each mark carries an SVG `<title>`, which browsers show as a
//!   native tooltip on hover, and the measurements table below the plot carries every value — so a
//!   number is never reachable *only* by hovering, which is the property that actually matters.
//! - No zoom or pan. The time-range control re-queries instead, which is more honest anyway: zooming
//!   a bucketed plot would show more pixels of the same averages.
//! - No small multiples past the series cap. The chart plots [`crate::store::read::MAX_SERIES`] and
//!   says how many it left out.

use crate::store::read::{PALETTE_SLOTS, Point, Series};

use super::html::escape;

/// Plot geometry. One struct so the two plot kinds cannot drift out of alignment — their x axes must
/// line up, since they are read as one stacked pair over the same window — and so the same rendering
/// code can serve a small inline plot and a large one on its own page.
///
/// **Why more than one preset exists at all.** The SVG is sized with a `viewBox` and `width="100%"`, so
/// the browser scales everything in it, text included. That is fine while the rendered width is near the
/// viewBox width and hopeless when it is not: a 960-unit viewBox in a 360px phone viewport is a 0.375×
/// scale, which takes an 11px axis label to about 4px. No amount of CSS fixes that, because the scale
/// applies to the font too. The only real answers are a viewBox that matches the target width, or a
/// scrollbar. So the full-page view ships two — one sized for a phone, one for a desktop — and lets a
/// media query pick, which costs one extra copy of one chart on the page whose whole purpose is being
/// readable.
#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    pub width: f64,
    pub pad_left: f64,
    pub pad_right: f64,
    /// Room for the direct labels at the right-hand end of each line.
    pub pad_top: f64,
    /// The x-axis band. Part of the height rather than outside it: a container sized to the plot alone
    /// crops its own axis labels and grows a nested scrollbar.
    pub pad_bottom: f64,
    pub value_height: f64,
    pub timeline_height: f64,
    pub time_ticks: usize,
    pub value_ticks: usize,
    /// Extra class on the `<svg>`, which is how the media query chooses between the full-page pair.
    pub class: &'static str,
}

impl Geometry {
    /// In the page, under the filter row. Fits the column width on a desktop; on a phone the labels are
    /// hidden by CSS and it reads as a shape, with the full view a tap away.
    pub const INLINE: Geometry = Geometry {
        width: 960.0,
        pad_left: 64.0,
        pad_right: 96.0,
        pad_top: 12.0,
        pad_bottom: 26.0,
        value_height: 200.0,
        timeline_height: 72.0,
        time_ticks: 6,
        value_ticks: 4,
        class: "",
    };

    /// The full-page view on a wide screen: bigger, more ticks, room to read.
    pub const FULL_WIDE: Geometry = Geometry {
        width: 1200.0,
        pad_left: 76.0,
        pad_right: 120.0,
        pad_top: 16.0,
        pad_bottom: 32.0,
        value_height: 440.0,
        timeline_height: 120.0,
        time_ticks: 7,
        value_ticks: 5,
        class: "wide",
    };

    /// The full-page view on a phone. The viewBox is close to a portrait viewport, so the scale is near
    /// 1 and the labels render at their real size. Few ticks, because there is no width to spend.
    pub const FULL_NARROW: Geometry = Geometry {
        width: 420.0,
        pad_left: 46.0,
        pad_right: 14.0,
        pad_top: 14.0,
        pad_bottom: 30.0,
        value_height: 320.0,
        timeline_height: 96.0,
        time_ticks: 3,
        value_ticks: 4,
        class: "narrow",
    };

    fn plot_right(&self) -> f64 {
        self.width - self.pad_right
    }
}

/// Compile-time guards, not tests, because these are invariants about constants and a build is the right
/// place to lose an argument with one.
///
/// The presets exist to *differ* — if the narrow one stopped suiting a portrait viewport, or the wide one
/// stopped being the larger, the media-query swap on the full-page view would be decoration and the
/// legibility problem it solves would silently return.
const _: () = assert!(
    Geometry::FULL_NARROW.width < 480.0,
    "the narrow preset has to be near a portrait viewport's width, or its text scales down again"
);
const _: () = assert!(Geometry::FULL_WIDE.width > Geometry::INLINE.width);
const _: () = assert!(Geometry::FULL_WIDE.value_height > Geometry::INLINE.value_height);
// Fewer ticks where there is less room to put them.
const _: () = assert!(Geometry::FULL_NARROW.time_ticks < Geometry::INLINE.time_ticks);
const _: () = assert!(Geometry::FULL_WIDE.time_ticks >= Geometry::INLINE.time_ticks);
// The plot area must be positive in every preset, or a scale inverts and the marks render outside it.
const _: () = assert!(Geometry::INLINE.width > Geometry::INLINE.pad_left + Geometry::INLINE.pad_right);
const _: () = assert!(
    Geometry::FULL_NARROW.width > Geometry::FULL_NARROW.pad_left + Geometry::FULL_NARROW.pad_right
);
const _: () =
    assert!(Geometry::FULL_WIDE.width > Geometry::FULL_WIDE.pad_left + Geometry::FULL_WIDE.pad_right);

/// Markers are drawn only when they would not merge into a smear. At 8px across, ~40 of them across
/// 800px is already touching.
const MAX_MARKERS: usize = 40;
/// Narrowest tap target, in viewBox units, for the drill-down zones.
///
/// A bucket can be five units wide — 240 of them across a 1200-unit plot — and a five-pixel tap target is
/// one nobody hits. Zones therefore span as many whole buckets as it takes to clear this, and the link
/// covers that whole span. A little above the usual 24px floor, because the zones sit edge to edge with no
/// gaps to aim between.
const MIN_HIT_WIDTH: f64 = 28.0;
/// Past this, direct labels collide with each other and the legend carries identity alone.
const MAX_DIRECT_LABELS: usize = 4;

/// A linear mapping from data space to pixel space.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Scale {
    pub d0: f64,
    pub d1: f64,
    pub r0: f64,
    pub r1: f64,
}

impl Scale {
    pub fn new(d0: f64, d1: f64, r0: f64, r1: f64) -> Self {
        Self { d0, d1, r0, r1 }
    }

    /// Maps a value, clamped to the range.
    ///
    /// A zero-width domain maps everything to the middle of the range rather than dividing by zero —
    /// which is the single-distinct-value case (one reading, or a perfectly flat hour), and a flat
    /// line through the middle is the right picture of it.
    pub fn map(&self, v: f64) -> f64 {
        if (self.d1 - self.d0).abs() < f64::EPSILON {
            return (self.r0 + self.r1) / 2.0;
        }
        let t = (v - self.d0) / (self.d1 - self.d0);
        self.r0 + t * (self.r1 - self.r0)
    }
}

/// Round tick values covering `[min, max]`, using a 1 / 2 / 5 × 10ⁿ step.
///
/// Round numbers rather than `min + k·(max-min)/n`, because an axis labelled 3.2847, 3.2913, 3.2979
/// is an axis nobody reads.
pub fn value_ticks(min: f64, max: f64, target: usize) -> Vec<f64> {
    if !min.is_finite() || !max.is_finite() || target == 0 {
        return Vec::new();
    }
    if (max - min).abs() < f64::EPSILON {
        return vec![min];
    }
    let raw = (max - min) / target as f64;
    let magnitude = 10f64.powf(raw.abs().log10().floor());
    let normalized = raw / magnitude;
    // The 1/2/5 ladder, so every step is a number a reader can add up in their head.
    let step = magnitude
        * if normalized <= 1.0 {
            1.0
        } else if normalized <= 2.0 {
            2.0
        } else if normalized <= 5.0 {
            5.0
        } else {
            10.0
        };

    let first = (min / step).ceil() * step;
    let mut ticks = Vec::new();
    let mut t = first;
    // `<= target + 2` bounds the loop independently of the arithmetic, so a pathological domain
    // cannot spin here.
    while t <= max + step * 0.001 && ticks.len() <= target + 2 {
        ticks.push(t);
        t += step;
    }
    ticks
}

/// Candidate axis steps in nanoseconds, coarsest last.
///
/// A fixed ladder rather than a computed step, because these are the only intervals that produce
/// labels on round wall-clock times — an axis ticking every 7 minutes is arithmetically fine and
/// useless to read.
const TIME_STEPS: &[i64] = &[
    1_000_000_000,          // 1s
    5_000_000_000,          // 5s
    15_000_000_000,         // 15s
    30_000_000_000,         // 30s
    60_000_000_000,         // 1m
    300_000_000_000,        // 5m
    900_000_000_000,        // 15m
    1_800_000_000_000,      // 30m
    3_600_000_000_000,      // 1h
    10_800_000_000_000,     // 3h
    21_600_000_000_000,     // 6h
    43_200_000_000_000,     // 12h
    86_400_000_000_000,     // 1d
    604_800_000_000_000,    // 7d
    2_592_000_000_000_000,  // 30d
];

/// Tick instants across `[from, to]`, aligned to round multiples of a step from [`TIME_STEPS`].
pub fn time_ticks(from: i64, to: i64, target: usize) -> Vec<i64> {
    if to <= from || target == 0 {
        return Vec::new();
    }
    let span = to - from;
    let step = TIME_STEPS
        .iter()
        .copied()
        .find(|s| span / s <= target as i64)
        // Past 30 days, fall back to whole 30-day blocks rather than to no ticks at all.
        .unwrap_or_else(|| *TIME_STEPS.last().expect("TIME_STEPS is not empty"));

    // Aligned to the epoch, which for every step above lands on a round UTC instant.
    let first = from.div_euclid(step) * step;
    let first = if first < from { first + step } else { first };
    let mut ticks = Vec::new();
    let mut t = first;
    while t <= to && ticks.len() <= target + 2 {
        ticks.push(t);
        t += step;
    }
    ticks
}

/// A short axis label for an instant, at a precision suited to the span being shown.
///
/// Derived by slicing [`crate::api::query::format_nanos`]'s fixed-width RFC 3339 output rather than
/// by reaching for a second formatter: that function is already tested to produce nine fractional
/// digits at a fixed width, so the offsets below are stable. It falls back to the raw nanosecond
/// count for instants outside the representable range, which is why the length is checked before
/// slicing.
pub fn time_label(nanos: i64, span: i64) -> String {
    let full = crate::api::query::format_nanos(nanos);
    // "2026-08-19T18:45:29.371467361Z" — anything shorter is the out-of-range fallback.
    if full.len() < 20 || full.as_bytes().get(10) != Some(&b'T') {
        return full;
    }
    const DAY: i64 = 86_400_000_000_000;
    if span < DAY {
        full[11..16].to_owned() // HH:MM
    } else if span < 30 * DAY {
        format!("{} {}", &full[5..10], &full[11..16]) // MM-DD HH:MM
    } else {
        full[0..10].to_owned() // YYYY-MM-DD
    }
}

/// Formats a value for an axis label or a tooltip, trimming the noise off a float.
pub fn value_label(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    let s = format!("{v:.4}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    s.to_owned()
}

/// How one series is drawn: a validated hue, and a line pattern.
///
/// **Composite encoding, because a ninth hue does not exist.** The palette's eight slots are validated as a
/// set; a generated ninth is indistinguishable from one of them under colour-vision deficiency, so past
/// eight the *pattern* carries identity and the hue repeats. Two series sharing a hue therefore never share
/// a pattern, and within each pattern the eight hues clear their separation gates unchanged.
///
/// `slot` is the series' position in the **full sorted group list** — not among the ones currently visible.
/// That is what makes hiding a line leave every other line's appearance alone: a reader who learned that
/// `NemSnet` is the dashed aqua one must still find it dashed and aqua after hiding something else.
pub fn series_style(slot: usize) -> (String, &'static str) {
    let hue = format!("var(--series-{})", (slot % PALETTE_SLOTS) + 1);
    let dash = match (slot / PALETTE_SLOTS) % 3 {
        0 => "",
        1 => "7 4",
        _ => "2 3",
    };
    (hue, dash)
}

/// The CSS `border-style` matching a slot's line pattern, for the legend key.
pub fn series_border_style(slot: usize) -> &'static str {
    match (slot / PALETTE_SLOTS) % 3 {
        0 => "solid",
        1 => "dashed",
        _ => "dotted",
    }
}

/// Opens an SVG element sized to include its axis band.
fn open_svg(geo: &Geometry, height: f64, label: &str) -> String {
    format!(
        "<svg viewBox=\"0 0 {} {height}\" width=\"100%\" height=\"{height}\" \
         preserveAspectRatio=\"xMidYMid meet\" role=\"img\" aria-label=\"{}\" class=\"plot {}\">",
        geo.width,
        escape(label),
        geo.class
    )
}

/// Gridlines and axis labels, shared by both plot kinds so their x axes align exactly.
fn axes(
    geo: &Geometry,
    x: &Scale,
    y: &Scale,
    from: i64,
    to: i64,
    plot_bottom: f64,
    value_axis: bool,
) -> String {
    let mut out = String::new();
    let span = to.saturating_sub(from);
    let right = geo.plot_right();

    if value_axis {
        // Solid hairlines, one shade off the surface. Dashed gridlines read as "threshold" or
        // "projection" when they are just a grid.
        for tick in value_ticks(y.d0, y.d1, geo.value_ticks) {
            let py = y.map(tick);
            out.push_str(&format!(
                "<line x1=\"{:.1}\" y1=\"{py:.1}\" x2=\"{right:.1}\" y2=\"{py:.1}\" class=\"grid\"/>\
                 <text x=\"{:.1}\" y=\"{:.1}\" class=\"tick tick-y\">{}</text>",
                geo.pad_left,
                geo.pad_left - 6.0,
                py + 3.0,
                escape(&value_label(tick))
            ));
        }
    }

    out.push_str(&format!(
        "<line x1=\"{:.1}\" y1=\"{plot_bottom:.1}\" x2=\"{right:.1}\" y2=\"{plot_bottom:.1}\" \
         class=\"axis\"/>",
        geo.pad_left
    ));

    for tick in time_ticks(from, to, geo.time_ticks) {
        let px = x.map(tick as f64);
        out.push_str(&format!(
            "<line x1=\"{px:.1}\" y1=\"{plot_bottom:.1}\" x2=\"{px:.1}\" y2=\"{:.1}\" class=\"axis\"/>\
             <text x=\"{px:.1}\" y=\"{:.1}\" class=\"tick tick-x\">{}</text>",
            plot_bottom + 4.0,
            plot_bottom + 16.0,
            escape(&time_label(tick, span))
        ));
    }
    out
}

/// The timeline: how many matching measurements arrived in each bucket.
///
/// Always available, whatever the data is made of — it is the plot that answers "when did these
/// arrive", which is the only question a type whose body is all text can be asked. One hue, because
/// there is one series and its identity is the title's job.
pub fn timeline(
    points: &[Point],
    from: i64,
    to: i64,
    bucket_nanos: i64,
    geo: &Geometry,
    link: Option<&str>,
) -> String {
    let plot_bottom = geo.timeline_height + geo.pad_top;
    let height = geo.timeline_height + geo.pad_top + geo.pad_bottom;
    if points.is_empty() {
        return empty_plot(geo, height, "no measurements in range");
    }

    let x = Scale::new(from as f64, to as f64, geo.pad_left, geo.plot_right());
    let max_count = points.iter().map(|p| p.count).max().unwrap_or(1).max(1) as f64;
    let y = Scale::new(0.0, max_count, plot_bottom, geo.pad_top);

    let mut out = open_svg(geo, height, "measurements over time");
    out.push_str(&axes(geo, &x, &y, from, to, plot_bottom, false));

    // One column per bucket, at least a hairline wide so a sparse bucket is still visible, and with a
    // 1px gap so adjacent columns read as separate marks without a border being drawn around them.
    let width = ((geo.plot_right() - geo.pad_left) * bucket_nanos as f64 / (to - from).max(1) as f64)
        .max(1.5);
    for p in points {
        let px = x.map(p.start as f64);
        let py = y.map(p.count as f64);
        let h = (plot_bottom - py).max(0.5);
        out.push_str(&format!(
            "<rect x=\"{px:.1}\" y=\"{py:.1}\" width=\"{:.1}\" height=\"{h:.1}\" class=\"col\">\
             <title>{}</title></rect>",
            (width - 1.0).max(1.0),
            escape(&format!(
                "{} — {} measurement{}",
                crate::api::query::format_nanos(p.start),
                p.count,
                if p.count == 1 { "" } else { "s" }
            ))
        ));
    }

    out.push_str(&format!(
        "<text x=\"{:.1}\" y=\"{:.1}\" class=\"tick tick-y\">{}/bucket</text>",
        geo.pad_left,
        geo.pad_top - 2.0,
        escape(&value_label(max_count))
    ));
    if let Some(link) = link {
        out.push_str(&hit_layer(from, to, bucket_nanos, geo, plot_bottom, link));
    }
    out.push_str("</svg>");
    out
}

/// The value chart: average per bucket per series, with the min/max spread behind it.
///
/// The band is not decoration. Every point is an average over a bucket, and a bare line would imply
/// a smoothness the samples never had — the band shows exactly what the averaging hid, so a reader
/// can see when a flat-looking mean is covering a swing.
pub fn value_chart(
    series: &[Series],
    slots: &[usize],
    from: i64,
    to: i64,
    field: &str,
    geo: &Geometry,
    link: Option<&str>,
) -> String {
    // Paired with their slots, so a series' appearance depends on its position in the full group list
    // rather than on how many happen to be plotted right now.
    let plotted: Vec<(usize, &Series)> = series
        .iter()
        .enumerate()
        .filter(|(_, s)| s.points.iter().any(|p| p.avg.is_some()))
        .map(|(i, s)| (slots.get(i).copied().unwrap_or(i), s))
        .collect();
    let height = geo.value_height + geo.pad_top + geo.pad_bottom;
    if plotted.is_empty() {
        return empty_plot(geo, height, "no numeric values in range for this field");
    }

    let plot_bottom = geo.value_height + geo.pad_top;
    let x = Scale::new(from as f64, to as f64, geo.pad_left, geo.plot_right());

    // The domain spans the band, not just the means, or the band would be clipped by the plot edge.
    let (mut lo, mut hi) = (f64::MAX, f64::MIN);
    for (_, s) in &plotted {
        for p in &s.points {
            for v in [p.min, p.max, p.avg].into_iter().flatten() {
                lo = lo.min(v);
                hi = hi.max(v);
            }
        }
    }
    // A little headroom so a line does not sit exactly on the axis.
    let pad = ((hi - lo) * 0.08).max(f64::EPSILON);
    let y = Scale::new(lo - pad, hi + pad, plot_bottom, geo.pad_top);

    let mut out = open_svg(geo, height, &format!("{field} over time"));
    out.push_str(&axes(geo, &x, &y, from, to, plot_bottom, true));

    let direct_label = plotted.len() <= MAX_DIRECT_LABELS;
    for (slot, s) in &plotted {
        let (color, dash) = series_style(*slot);
        out.push_str(&band_path(&s.points, &x, &y, &color));
        out.push_str(&line_path(&s.points, &x, &y, &color, dash));
        out.push_str(&markers(&s.points, &x, &y, &color, field, s.group.as_deref()));

        if let (true, Some(last)) =
            (direct_label, s.points.iter().rev().find(|p| p.avg.is_some()))
        {
            let label = s.group.clone().unwrap_or_else(|| field.to_owned());
            out.push_str(&format!(
                "<text x=\"{:.1}\" y=\"{:.1}\" class=\"direct\" fill=\"{color}\">{}</text>",
                x.map(last.start as f64) + 6.0,
                y.map(last.avg.expect("filtered to Some")) + 3.0,
                escape(&label)
            ));
        }
    }

    if let Some(link) = link {
        // The bucket width is derivable from the points, and the hit layer needs whole buckets.
        let bucket = plotted
            .iter()
            .flat_map(|(_, s)| s.points.windows(2))
            .map(|w| w[1].start - w[0].start)
            .min()
            .unwrap_or((to - from).max(1));
        out.push_str(&hit_layer(from, to, bucket, geo, plot_bottom, link));
    }
    out.push_str("</svg>");

    // **No legend and no notes here.** They used to be appended to the returned string, which was fine
    // while they were static text. The legend now carries links — tapping an entry hides that series — and
    // a link is a web concern, not a drawing one. `web::mod` composes them alongside this SVG, so this
    // function stays what it says it is: data in, one `<svg>` out.
    out
}

/// The min/max envelope, drawn behind the line in the series' own hue.
fn band_path(points: &[Point], x: &Scale, y: &Scale, color: &str) -> String {
    // Only the stretches that have both bounds; a gap must break the band exactly as it breaks the
    // line, or the fill would bridge a period with no data.
    let mut d = String::new();
    for run in runs(points) {
        if run.len() < 2 {
            continue;
        }
        let mut forward = String::new();
        let mut backward = String::new();
        for (n, p) in run.iter().enumerate() {
            let px = x.map(p.start as f64);
            let hi = y.map(p.max.or(p.avg).expect("run points carry a value"));
            let lo = y.map(p.min.or(p.avg).expect("run points carry a value"));
            forward.push_str(&format!("{}{px:.1} {hi:.1}", if n == 0 { "M" } else { "L" }));
            backward.insert_str(0, &format!("L{px:.1} {lo:.1}"));
        }
        d.push_str(&forward);
        d.push_str(&backward);
        d.push('Z');
    }
    if d.is_empty() {
        return String::new();
    }
    format!("<path d=\"{d}\" fill=\"{color}\" class=\"band\"/>")
}

/// The mean line. 2px, and broken across gaps rather than interpolated over them.
fn line_path(points: &[Point], x: &Scale, y: &Scale, color: &str, dash: &str) -> String {
    let mut d = String::new();
    for run in runs(points) {
        for (n, p) in run.iter().enumerate() {
            let px = x.map(p.start as f64);
            let py = y.map(p.avg.expect("run points carry a value"));
            d.push_str(&format!("{}{px:.1} {py:.1}", if n == 0 { "M" } else { "L" }));
        }
    }
    if d.is_empty() {
        return String::new();
    }
    let dasharray =
        if dash.is_empty() { String::new() } else { format!(" stroke-dasharray=\"{dash}\"") };
    format!("<path d=\"{d}\" fill=\"none\" stroke=\"{color}\"{dasharray} class=\"line\"/>")
}

/// A transparent layer of tap targets, one per span of buckets, laid over a plot whose marks drill down.
///
/// **Why this rather than linking the marks themselves.** The marks are the wrong hit target twice over.
/// They are too small — an 8px dot is a pinpoint — and, worse, on a dense chart there are none at all:
/// [`markers`] drops them past [`MAX_MARKERS`] precisely because 240 of them would smear, which is exactly
/// the chart someone wants to drill into. Linking the marks meant the feature disappeared when it was most
/// wanted. A separate layer is also how an interactive chart does it, minus the JavaScript.
///
/// Drawn last so it sits above everything and receives the taps. `fill="transparent"` rather than
/// `fill="none"`: the latter is not hit-testable, so the zones would be invisible *and* unclickable.
fn hit_layer(
    from: i64,
    to: i64,
    bucket_nanos: i64,
    geo: &Geometry,
    plot_bottom: f64,
    link: &str,
) -> String {
    let span = (to - from).max(1);
    let plot_width = geo.plot_right() - geo.pad_left;
    let bucket_width = plot_width * bucket_nanos as f64 / span as f64;
    // Whole buckets per zone, so a zone's window lands on a bucket boundary rather than slicing through
    // one — a link to half a bucket would list rows the point never covered.
    let per_zone = if bucket_width >= MIN_HIT_WIDTH {
        1
    } else {
        (MIN_HIT_WIDTH / bucket_width.max(0.01)).ceil() as i64
    };
    let zone_nanos = bucket_nanos.saturating_mul(per_zone.max(1)).max(1);

    let x = Scale::new(from as f64, to as f64, geo.pad_left, geo.plot_right());
    let mut out = String::new();
    let mut start = from;
    while start < to {
        let mut end = (start + zone_nanos).min(to);
        // Absorb a remainder that would itself be too thin to hit, rather than leaving a sliver at the
        // right-hand edge. Measured in width, not in buckets: "half a zone" is the wrong test, because a
        // remainder of nearly a whole zone can still be under the minimum when the zone barely clears it.
        let remainder_width = plot_width * (to - end) as f64 / span as f64;
        if remainder_width > 0.0 && remainder_width < MIN_HIT_WIDTH {
            end = to;
        }
        let left = x.map(start as f64);
        let right = x.map(end as f64);
        out.push_str(&format!(
            "<a href=\"{}&amp;from={start}&amp;to={end}\">\
             <rect x=\"{left:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" \
             fill=\"transparent\" class=\"hit\"><title>{}</title></rect></a>",
            escape(link),
            geo.pad_top,
            (right - left).max(1.0),
            (plot_bottom - geo.pad_top).max(1.0),
            escape(&format!(
                "{} — tap for the measurements in this slice",
                crate::api::query::format_nanos(start)
            ))
        ));
        start = end;
    }
    out
}

/// Consecutive runs of points that carry a value.
///
/// **A bucket with no value breaks the line rather than being interpolated across.** Joining across a
/// gap draws a straight line through a period when nothing was reported, which is a claim about data
/// that does not exist — the most common way a time-series chart lies.
fn runs(points: &[Point]) -> Vec<Vec<&Point>> {
    let mut out: Vec<Vec<&Point>> = Vec::new();
    for p in points {
        if p.avg.is_some() {
            match out.last_mut() {
                Some(run) if !run.is_empty() => run.push(p),
                _ => out.push(vec![p]),
            }
        } else if out.last().is_some_and(|r| !r.is_empty()) {
            out.push(Vec::new());
        }
    }
    out.retain(|r| !r.is_empty());
    out
}

/// Point markers, and the `<title>` that makes each one hoverable.
///
/// Drawn only when they would stay distinguishable. Each carries a 2px surface ring so overlapping
/// markers read as separate marks — a ring in the surface colour, not a border drawn around the mark.
fn markers(
    points: &[Point],
    x: &Scale,
    y: &Scale,
    color: &str,
    field: &str,
    group: Option<&str>,
) -> String {
    let with_values: Vec<&Point> = points.iter().filter(|p| p.avg.is_some()).collect();
    if with_values.len() > MAX_MARKERS {
        return String::new();
    }
    let mut out = String::new();
    for p in with_values {
        let avg = p.avg.expect("filtered to Some");
        let mut title = format!(
            "{}\n{field} avg {}",
            crate::api::query::format_nanos(p.start),
            value_label(avg)
        );
        // Only when the spread is real: "(min 3.29, max 3.29)" is noise.
        if let (Some(min), Some(max)) = (p.min, p.max)
            && (max - min).abs() > f64::EPSILON
        {
            title.push_str(&format!(" (min {}, max {})", value_label(min), value_label(max)));
        }
        if let Some(g) = group {
            title.push_str(&format!("\n{g}"));
        }
        // When a bucket's average speaks for only some of its rows, say so here rather than let the
        // point imply it covered all of them.
        if p.value_count < p.count {
            title.push_str(&format!("\n{} of {} rows had a value", p.value_count, p.count));
        }
        let mark = format!(
            "<circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"4\" fill=\"{color}\" class=\"dot\">\
             <title>{}</title></circle>",
            x.map(p.start as f64),
            y.map(avg),
            escape(&title)
        );
        out.push_str(&mark);
    }
    out
}

/// The empty state. A message, not an axis with nothing between it — a bare grid leaves the reader
/// wondering whether the page failed.
fn empty_plot(geo: &Geometry, height: f64, message: &str) -> String {
    format!(
        "{}<text x=\"{:.1}\" y=\"{:.1}\" class=\"empty-plot\" text-anchor=\"middle\">{}</text></svg>",
        open_svg(geo, height, message),
        geo.width / 2.0,
        height / 2.0,
        escape(message)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inline preset, which is what the old bare constants referred to.
    const G: Geometry = Geometry::INLINE;

    /// Slots for `n` series in their natural order — what the caller passes when nothing is hidden.
    fn slots(n: usize) -> Vec<usize> {
        (0..n).collect()
    }

    fn point(start: i64, avg: Option<f64>) -> Point {
        Point {
            start,
            count: 1,
            value_count: if avg.is_some() { 1 } else { 0 },
            avg,
            min: avg,
            max: avg,
        }
    }

    #[test]
    fn a_scale_maps_its_endpoints_and_midpoint() {
        let s = Scale::new(0.0, 10.0, 100.0, 200.0);
        assert_eq!(s.map(0.0), 100.0);
        assert_eq!(s.map(10.0), 200.0);
        assert_eq!(s.map(5.0), 150.0);
    }

    /// Inverted ranges are the normal case for y: pixels grow downwards.
    #[test]
    fn a_scale_handles_an_inverted_range() {
        let s = Scale::new(0.0, 10.0, 200.0, 100.0);
        assert_eq!(s.map(0.0), 200.0);
        assert_eq!(s.map(10.0), 100.0);
    }

    /// One distinct value — a single reading, or a perfectly flat hour — must not divide by zero.
    #[test]
    fn a_zero_width_domain_maps_to_the_middle() {
        let s = Scale::new(3.29, 3.29, 0.0, 100.0);
        assert_eq!(s.map(3.29), 50.0);
    }

    /// The step is rounded *up* onto the 1/2/5 ladder, so `target` is an upper bound on the tick count
    /// rather than a quota to fill: over [0,1] asking for 4 gives three round ticks, not four awkward
    /// ones.
    #[test]
    fn value_ticks_are_round_numbers() {
        assert_eq!(value_ticks(0.0, 10.0, 5), vec![0.0, 2.0, 4.0, 6.0, 8.0, 10.0]);
        assert_eq!(value_ticks(0.0, 1.0, 4), vec![0.0, 0.5, 1.0]);
        assert_eq!(value_ticks(0.0, 100.0, 4), vec![0.0, 50.0, 100.0]);
    }

    /// The real case: cell voltages span ~0.004 V, so the ticks have to be round at that magnitude
    /// rather than round at 1.0.
    #[test]
    fn value_ticks_work_at_a_tiny_magnitude() {
        let ticks = value_ticks(3.288, 3.292, 4);
        assert!(ticks.len() >= 3, "{ticks:?}");
        assert!(ticks.iter().all(|t| *t >= 3.288 - 0.001 && *t <= 3.292 + 0.001), "{ticks:?}");
        // Every tick is a multiple of the step, so the labels are short.
        assert!(ticks.iter().all(|t| value_label(*t).len() <= 6), "{ticks:?}");
    }

    #[test]
    fn value_ticks_degenerate_gracefully() {
        assert_eq!(value_ticks(5.0, 5.0, 4), vec![5.0]);
        assert!(value_ticks(f64::NAN, 1.0, 4).is_empty());
        assert!(value_ticks(0.0, 1.0, 0).is_empty());
    }

    const SEC: i64 = 1_000_000_000;
    const MIN: i64 = 60 * SEC;
    const HOUR: i64 = 60 * MIN;
    const DAY: i64 = 24 * HOUR;

    /// Ticks must land on round instants and stay few enough to read, across every range the presets
    /// offer.
    #[test]
    fn time_ticks_stay_readable_from_minutes_to_a_month() {
        for (span, name) in [
            (5 * MIN, "5m"),
            (HOUR, "1h"),
            (6 * HOUR, "6h"),
            (DAY, "24h"),
            (7 * DAY, "7d"),
            (30 * DAY, "30d"),
        ] {
            let from = 1_787_000_000_000_000_000;
            let ticks = time_ticks(from, from + span, 6);
            assert!(!ticks.is_empty(), "{name}: no ticks");
            assert!(ticks.len() <= 8, "{name}: {} ticks is too many", ticks.len());
            // Round: every tick is a whole multiple of some step on the ladder.
            assert!(
                ticks.iter().all(|t| TIME_STEPS.iter().any(|s| t % s == 0)),
                "{name}: a tick is not on a round instant: {ticks:?}"
            );
        }
    }

    #[test]
    fn time_ticks_degenerate_gracefully() {
        assert!(time_ticks(10, 10, 6).is_empty());
        assert!(time_ticks(20, 10, 6).is_empty(), "an inverted window yields nothing");
        assert!(!time_ticks(0, 10_000 * DAY, 6).is_empty(), "past the ladder, still ticks");
    }

    #[test]
    fn time_labels_shorten_with_the_span() {
        let t = 1_787_165_129_371_467_361; // 2026-08-19T18:45:29Z
        assert_eq!(time_label(t, HOUR), "18:45");
        assert_eq!(time_label(t, 7 * DAY), "08-19 18:45");
        assert_eq!(time_label(t, 90 * DAY), "2026-08-19");
    }

    /// The extremes of the domain must not panic in the slicing.
    ///
    /// In practice they cannot even reach the fallback: `i64` nanoseconds run out in 2262, comfortably
    /// inside the range `format_nanos` can print, so every value it is ever handed produces a full RFC
    /// 3339 string. The length check in [`time_label`] is therefore belt-and-braces against
    /// `format_nanos` changing its fallback, not a live path — but slicing a string on byte offsets
    /// without one is exactly how this would become a panic later.
    #[test]
    fn a_time_label_at_the_extremes_of_the_domain_does_not_panic() {
        for t in [i64::MAX, i64::MIN, 0] {
            for span in [HOUR, 7 * DAY, 90 * DAY] {
                assert!(!time_label(t, span).is_empty(), "empty label for {t} at span {span}");
            }
        }
        assert_eq!(time_label(0, HOUR), "00:00", "the epoch itself");
    }

    #[test]
    fn value_labels_trim_float_noise() {
        assert_eq!(value_label(3.0), "3");
        assert_eq!(value_label(3.29), "3.29");
        assert_eq!(value_label(3.29_f64 + f64::EPSILON), "3.29", "float noise is trimmed");
        assert_eq!(value_label(-0.5), "-0.5");
    }

    /// The regression test for recolour-on-filter: a series' colour depends on its own position in
    /// the caller's sorted list, so removing another series cannot repaint it.
    /// The regression test for recolour-on-filter, now also covering what happens past the palette: the
    /// hue repeats and the *pattern* changes, so identity survives without a ninth hue being invented.
    #[test]
    fn styles_are_stable_slots_and_composite_past_the_palette() {
        assert_eq!(series_style(0), ("var(--series-1)".to_owned(), ""));
        assert_eq!(series_style(7), ("var(--series-8)".to_owned(), ""));
        // Slot 8 reuses hue 1 but is dashed, so it is not confusable with slot 0.
        assert_eq!(series_style(8), ("var(--series-1)".to_owned(), "7 4"));
        assert_eq!(series_style(16), ("var(--series-1)".to_owned(), "2 3"), "and then dotted");
        assert_eq!(series_border_style(0), "solid");
        assert_eq!(series_border_style(8), "dashed");
        assert_eq!(series_border_style(16), "dotted");

        // No two slots inside the bound share both channels.
        let mut seen = std::collections::HashSet::new();
        for slot in 0..crate::store::read::MAX_SERIES {
            assert!(seen.insert(series_style(slot)), "slot {slot} duplicates an earlier appearance");
        }
    }

    /// **A gap must break the line, not be drawn across.** Interpolating over a period with no data
    /// is a claim about data that does not exist.
    #[test]
    fn a_gap_breaks_the_line_into_subpaths() {
        let points =
            vec![point(0, Some(1.0)), point(10, Some(2.0)), point(20, None), point(30, Some(3.0))];
        let x = Scale::new(0.0, 30.0, 0.0, 300.0);
        let y = Scale::new(0.0, 3.0, 100.0, 0.0);

        let path = line_path(&points, &x, &y, "var(--series-1)", "");
        assert_eq!(path.matches('M').count(), 2, "two runs means two subpaths: {path}");
    }

    #[test]
    fn a_single_point_still_renders_a_marker_but_no_line_segment() {
        let points = vec![point(0, Some(1.0))];
        let x = Scale::new(0.0, 10.0, 0.0, 100.0);
        let y = Scale::new(0.0, 1.0, 100.0, 0.0);

        assert!(line_path(&points, &x, &y, "c", "").contains('M'));
        assert!(band_path(&points, &x, &y, "c").is_empty(), "a band needs two points");
        assert!(markers(&points, &x, &y, "c", "v", None).contains("<circle"));
    }

    #[test]
    fn markers_are_dropped_when_they_would_smear() {
        let points: Vec<Point> =
            (0..(MAX_MARKERS as i64 + 1)).map(|i| point(i, Some(i as f64))).collect();
        let x = Scale::new(0.0, 100.0, 0.0, 100.0);
        let y = Scale::new(0.0, 100.0, 100.0, 0.0);
        assert!(markers(&points, &x, &y, "c", "v", None).is_empty());
    }

    #[test]
    fn an_empty_series_renders_an_empty_state_not_a_broken_path() {
        let svg = value_chart(&[], &[], 0, 100, "v", &G, None);
        assert!(svg.contains("no numeric values"), "{svg}");
        assert!(!svg.contains("<path"), "{svg}");

        let svg = timeline(&[], 0, 100, 10, &G, None);
        assert!(svg.contains("no measurements in range"), "{svg}");
    }

    /// A series whose every bucket is null (a text field) must render the empty state rather than an
    /// axis with nothing on it.
    #[test]
    fn a_series_with_no_values_is_treated_as_empty() {
        let series = vec![Series { group: None, points: vec![point(0, None), point(10, None)] }];
        let svg = value_chart(&series, &slots(series.len()), 0, 100, "state", &G, None);
        assert!(svg.contains("no numeric values"), "{svg}");
    }

    /// Device-supplied text reaches the SVG through group values, field names and titles. SVG is XML,
    /// so an unescaped `<` is as dangerous here as in HTML.
    #[test]
    fn device_supplied_text_is_escaped_everywhere_it_reaches_the_svg() {
        let hostile = "<script>alert('x')</script>";
        let series = vec![Series {
            group: Some(hostile.to_owned()),
            points: vec![point(0, Some(1.0)), point(10, Some(2.0))],
        }];
        let svg = value_chart(&series, &slots(series.len()), 0, 100, hostile, &G, None);

        assert!(!svg.contains("<script>"), "unescaped markup reached the SVG: {svg}");
        assert!(svg.contains("&lt;script&gt;"), "the value must still be shown, escaped");
    }

    /// The legend and the notes are HTML, composed by `web::mod` — this function returns one `<svg>` and
    /// nothing else, which is what lets the legend carry links.
    #[test]
    fn the_chart_is_only_an_svg() {
        let two = vec![
            Series { group: Some("a".into()), points: vec![point(0, Some(1.0))] },
            Series { group: Some("b".into()), points: vec![point(0, Some(2.0))] },
        ];
        let svg = value_chart(&two, &slots(two.len()), 0, 100, "v", &G, None);
        assert!(!svg.contains("legend"), "{svg}");
        assert!(svg.trim_end().ends_with("</svg>"), "{svg}");
    }

    /// A series past the palette is drawn with a dash pattern, which is the channel carrying its identity.
    #[test]
    fn a_series_past_the_palette_is_drawn_dashed() {
        let series = vec![Series { group: Some("ninth".into()), points: vec![point(0, Some(1.0)), point(10, Some(2.0))] }];
        let svg = value_chart(&series, &[8], 0, 20, "v", &G, None);
        assert!(svg.contains("stroke-dasharray=\"7 4\""), "{svg}");
    }

    /// Hiding a series must not repaint the others: the slot is the position in the full group list, so a
    /// series drawn alone still has the appearance it had among its peers.
    #[test]
    fn a_series_keeps_its_appearance_when_others_are_hidden() {
        let third = vec![Series { group: Some("c".into()), points: vec![point(0, Some(1.0)), point(10, Some(2.0))] }];
        let alone = value_chart(&third, &[2], 0, 20, "v", &G, None);
        assert!(alone.contains("var(--series-3)"), "slot 2 keeps hue 3: {alone}");
        assert!(!alone.contains("var(--series-1)"), "it must not be promoted to the first hue");
    }




    /// **What tapping means.** A point is an average over a bucket, not one measurement, so the only honest
    /// target is the rows in that window — and the link has to carry exactly that window, not the whole
    /// visible range.
    #[test]
    fn the_hit_layer_links_each_slice_to_its_own_window() {
        // Wide buckets, so each gets its own zone rather than being merged for tappability.
        let points = vec![point(0, Some(1.0)), point(2_000, Some(2.0))];
        let svg = timeline(&points, 0, 4_000, 2_000, &G, Some("/?type=cpu"));

        assert!(svg.contains("from=0&amp;to=2000"), "first slice: {svg}");
        assert!(svg.contains("from=2000&amp;to=4000"), "second slice: {svg}");
        assert!(svg.contains("class=\"hit\""), "there must be a hit layer");
        assert!(svg.contains("fill=\"transparent\""), "fill=none would not be clickable");
    }

    /// **The bug this layer exists for.** `markers` drops the dots on a dense chart, so linking the marks
    /// meant a 240-bucket chart — exactly the one worth drilling into — had nothing to tap at all.
    #[test]
    fn a_dense_chart_is_still_clickable_although_it_has_no_markers() {
        let points: Vec<Point> =
            (0..200).map(|i| point(i * 10, Some(i as f64))).collect();
        let series = vec![Series { group: None, points }];
        let svg = value_chart(&series, &slots(series.len()), 0, 2_000, "v", &G, Some("/?type=t"));

        assert!(!svg.contains("<circle"), "precondition: markers are dropped when dense");
        assert!(svg.contains("class=\"hit\""), "but the chart must still be clickable: {svg}");
        assert!(svg.contains("<a href="), "{svg}");
    }

    /// Narrow buckets are merged into a tappable zone rather than left as slivers, and the merged link
    /// spans whole buckets so it cannot select rows the marks never covered.
    #[test]
    fn slivers_are_merged_into_a_reachable_target() {
        // 400 buckets across the plot: each is well under the minimum.
        let points: Vec<Point> = (0..400).map(|i| point(i * 10, Some(1.0))).collect();
        let series = vec![Series { group: None, points }];
        let svg = value_chart(&series, &slots(series.len()), 0, 4_000, "v", &G, Some("/?t=1"));

        let zones = svg.matches("class=\"hit\"").count();
        assert!(zones > 1, "there must be several zones: {zones}");
        assert!(zones < 400, "but not one per bucket: {zones}");

        // Every zone is at least the minimum wide. Parsed per `<rect>` element, so the visible column
        // marks — which are legitimately thin — are not mistaken for hit zones.
        let is_hit = |rect: &&str| {
            rect.split("/>").next().is_some_and(|el| el.contains("class=\"hit\""))
                || rect.split("><title>").next().is_some_and(|el| el.contains("class=\"hit\""))
        };
        for rect in svg.split("<rect ").skip(1).filter(is_hit) {
            let width: f64 = rect
                .split("width=\"")
                .nth(1)
                .and_then(|w| w.split('"').next())
                .and_then(|w| w.parse().ok())
                .expect("a width");
            assert!(width >= MIN_HIT_WIDTH - 0.5, "a sliver survived: {width} in {rect:.120}");
        }
    }

    /// ...and with no link the marks are plain, so the inline plot does not become a field of tap targets
    /// that all leave the page.
    #[test]
    fn there_is_no_hit_layer_without_a_target() {
        let svg = timeline(&[point(0, Some(1.0))], 0, 100, 10, &G, None);
        assert!(!svg.contains("<a href="), "{svg}");
        assert!(!svg.contains("class=\"hit\""), "and no invisible rectangles either: {svg}");
    }

    /// The `&` in a link must be escaped: this is XML inside HTML, and a bare `&from=` is a malformed
    /// entity reference.
    #[test]
    fn a_link_is_xml_safe() {
        let svg = timeline(&[point(0, Some(1.0))], 0, 100, 10, &G, Some("/?a=1&amp;b=2"));
        assert!(!svg.contains("?a=1&b=2"), "an unescaped ampersand: {svg}");
        assert!(svg.contains("&amp;"), "{svg}");
    }

    #[test]
    fn the_value_chart_gets_a_hit_layer_too() {
        let series = vec![Series {
            group: None,
            points: vec![point(0, Some(1.0)), point(10, Some(2.0))],
        }];
        let svg = value_chart(&series, &slots(series.len()), 0, 20, "v", &G, Some("/?type=t"));
        assert!(svg.contains("class=\"hit\""), "{svg}");
        assert!(svg.contains("<a href=\"/?type=t&amp;from="), "{svg}");
    }

    /// The class is how CSS picks one of the pair, so each preset must be distinguishable in the markup.
    #[test]
    fn each_preset_labels_itself_in_the_markup() {
        for (geo, expected) in [
            (&Geometry::INLINE, "class=\"plot \""),
            (&Geometry::FULL_WIDE, "class=\"plot wide\""),
            (&Geometry::FULL_NARROW, "class=\"plot narrow\""),
        ] {
            let svg = timeline(&[point(0, Some(1.0))], 0, 100, 10, geo, None);
            assert!(svg.contains(expected), "{expected} missing from {svg}");
        }
    }

    /// The container has to be tall enough for its own axis labels, or the card grows a nested
    /// scrollbar and crops them.
    #[test]
    fn the_viewbox_includes_the_axis_band() {
        let svg = timeline(&[point(0, None)], 0, 100, 10, &G, None);
        let expected = G.timeline_height + G.pad_top + G.pad_bottom;
        assert!(svg.contains(&format!("0 0 {} {expected}", G.width)), "{svg}");
    }

    /// The two plots are read as a stacked pair over one window, so their x axes must line up to the
    /// pixel.
    #[test]
    fn both_plots_share_the_same_horizontal_geometry() {
        let x = Scale::new(0.0, 100.0, G.pad_left, G.width - G.pad_right);
        assert_eq!(x.map(0.0), G.pad_left);
        assert_eq!(x.map(100.0), G.width - G.pad_right);
    }
}
