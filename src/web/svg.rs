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

use crate::store::read::{MAX_SERIES, Point, Series};

use super::html::escape;

/// Plot geometry. One set of numbers so the two plot kinds cannot drift out of alignment — their x
/// axes must line up, since they are read as one stacked pair over the same window.
const WIDTH: f64 = 960.0;
const PAD_LEFT: f64 = 64.0;
const PAD_RIGHT: f64 = 96.0;
/// Room for the direct labels at the right-hand end of each line.
const PAD_TOP: f64 = 12.0;
/// The x-axis band. Part of the height rather than outside it: a container sized to the plot alone
/// crops its own axis labels and grows a nested scrollbar.
const PAD_BOTTOM: f64 = 26.0;
const VALUE_PLOT_HEIGHT: f64 = 200.0;
const TIMELINE_PLOT_HEIGHT: f64 = 72.0;

/// Markers are drawn only when they would not merge into a smear. At 8px across, ~40 of them across
/// 800px is already touching.
const MAX_MARKERS: usize = 40;
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

/// The CSS variable naming one categorical slot.
///
/// Indexed by the caller's series position, and the caller's order is derived from the *sorted group
/// value* — so a group keeps its colour when a filter removes some other group. Colour following the
/// entity rather than the row number is the point: a reader who learned that cell 3 is aqua must not
/// find it orange after narrowing the view.
pub fn series_color(index: usize) -> String {
    format!("var(--series-{})", (index % MAX_SERIES) + 1)
}

/// Opens an SVG element sized to include its axis band.
fn open_svg(height: f64, label: &str) -> String {
    format!(
        "<svg viewBox=\"0 0 {WIDTH} {height}\" width=\"100%\" height=\"{height}\" \
         preserveAspectRatio=\"xMidYMid meet\" role=\"img\" aria-label=\"{}\" class=\"plot\">",
        escape(label)
    )
}

/// Gridlines and axis labels, shared by both plot kinds so their x axes align exactly.
fn axes(
    x: &Scale,
    y: &Scale,
    from: i64,
    to: i64,
    plot_bottom: f64,
    value_axis: bool,
) -> String {
    let mut out = String::new();
    let span = to.saturating_sub(from);

    if value_axis {
        // Solid hairlines, one shade off the surface. Dashed gridlines read as "threshold" or
        // "projection" when they are just a grid.
        for tick in value_ticks(y.d0, y.d1, 4) {
            let py = y.map(tick);
            out.push_str(&format!(
                "<line x1=\"{PAD_LEFT}\" y1=\"{py:.1}\" x2=\"{:.1}\" y2=\"{py:.1}\" class=\"grid\"/>\
                 <text x=\"{:.1}\" y=\"{:.1}\" class=\"tick tick-y\">{}</text>",
                WIDTH - PAD_RIGHT,
                PAD_LEFT - 6.0,
                py + 3.0,
                escape(&value_label(tick))
            ));
        }
    }

    out.push_str(&format!(
        "<line x1=\"{PAD_LEFT}\" y1=\"{plot_bottom:.1}\" x2=\"{:.1}\" y2=\"{plot_bottom:.1}\" \
         class=\"axis\"/>",
        WIDTH - PAD_RIGHT
    ));

    for tick in time_ticks(from, to, 6) {
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
pub fn timeline(points: &[Point], from: i64, to: i64, bucket_nanos: i64) -> String {
    let plot_bottom = TIMELINE_PLOT_HEIGHT + PAD_TOP;
    if points.is_empty() {
        return empty_plot(TIMELINE_PLOT_HEIGHT + PAD_TOP + PAD_BOTTOM, "no measurements in range");
    }

    let x = Scale::new(from as f64, to as f64, PAD_LEFT, WIDTH - PAD_RIGHT);
    let max_count = points.iter().map(|p| p.count).max().unwrap_or(1).max(1) as f64;
    let y = Scale::new(0.0, max_count, plot_bottom, PAD_TOP);

    let mut out = open_svg(TIMELINE_PLOT_HEIGHT + PAD_TOP + PAD_BOTTOM, "measurements over time");
    out.push_str(&axes(&x, &y, from, to, plot_bottom, false));

    // One column per bucket, at least a hairline wide so a sparse bucket is still visible, and with a
    // 1px gap so adjacent columns read as separate marks without a border being drawn around them.
    let width = ((WIDTH - PAD_LEFT - PAD_RIGHT) * bucket_nanos as f64
        / (to - from).max(1) as f64)
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
        "<text x=\"{PAD_LEFT}\" y=\"{:.1}\" class=\"tick tick-y\">{}/bucket</text>",
        PAD_TOP - 2.0,
        escape(&value_label(max_count))
    ));
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
    from: i64,
    to: i64,
    field: &str,
    total_groups: usize,
) -> String {
    let plotted: Vec<&Series> = series.iter().filter(|s| s.points.iter().any(|p| p.avg.is_some())).collect();
    if plotted.is_empty() {
        return empty_plot(
            VALUE_PLOT_HEIGHT + PAD_TOP + PAD_BOTTOM,
            "no numeric values in range for this field",
        );
    }

    let plot_bottom = VALUE_PLOT_HEIGHT + PAD_TOP;
    let x = Scale::new(from as f64, to as f64, PAD_LEFT, WIDTH - PAD_RIGHT);

    // The domain spans the band, not just the means, or the band would be clipped by the plot edge.
    let (mut lo, mut hi) = (f64::MAX, f64::MIN);
    for s in &plotted {
        for p in &s.points {
            for v in [p.min, p.max, p.avg].into_iter().flatten() {
                lo = lo.min(v);
                hi = hi.max(v);
            }
        }
    }
    // A little headroom so a line does not sit exactly on the axis.
    let pad = ((hi - lo) * 0.08).max(f64::EPSILON);
    let y = Scale::new(lo - pad, hi + pad, plot_bottom, PAD_TOP);

    let mut out = open_svg(VALUE_PLOT_HEIGHT + PAD_TOP + PAD_BOTTOM, &format!("{field} over time"));
    out.push_str(&axes(&x, &y, from, to, plot_bottom, true));

    let direct_label = plotted.len() <= MAX_DIRECT_LABELS;
    for (i, s) in plotted.iter().enumerate() {
        let color = series_color(i);
        out.push_str(&band_path(&s.points, &x, &y, &color));
        out.push_str(&line_path(&s.points, &x, &y, &color));
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

    out.push_str("</svg>");

    // A legend whenever there is more than one series — identity must never rest on colour alone.
    // With one series the heading names it, and a legend box would be ink saying nothing.
    let mut html = out;
    if plotted.len() > 1 {
        html.push_str("<ul class=\"legend\">");
        for (i, s) in plotted.iter().enumerate() {
            html.push_str(&format!(
                "<li><span class=\"key\" style=\"background:{}\"></span>{}</li>",
                series_color(i),
                escape(s.group.as_deref().unwrap_or("(none)"))
            ));
        }
        html.push_str("</ul>");
    }
    if total_groups > plotted.len() {
        html.push_str(&format!(
            "<p class=\"note\">Showing {} of {} groups — narrow the filter to see the rest.</p>",
            plotted.len(),
            total_groups
        ));
    }

    // **Partial coverage, said out loud.** Each point is an average over the rows in its bucket that
    // carried a number, and on a leaf that is often null — `system.unit.active_enter_seconds_ago` is null
    // on more than half its rows — that is a very different claim from an average over all of them.
    //
    // Marker `<title>`s carry this per bucket, but markers are dropped on a dense chart precisely when
    // there are most buckets, so relying on them alone means the caveat disappears exactly when the chart
    // is busiest. This note does not depend on marker density.
    let (rows, valued) = plotted.iter().flat_map(|s| &s.points).fold((0i64, 0i64), |(r, v), p| {
        (r + p.count, v + p.value_count)
    });
    if valued < rows {
        html.push_str(&format!(
            "<p class=\"note\">{valued} of {rows} matching measurements carried a number for this \
             field; the rest are counted in the timeline but not averaged here.</p>"
        ));
    }
    html
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
fn line_path(points: &[Point], x: &Scale, y: &Scale, color: &str) -> String {
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
    format!("<path d=\"{d}\" fill=\"none\" stroke=\"{color}\" class=\"line\"/>")
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
        out.push_str(&format!(
            "<circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"4\" fill=\"{color}\" class=\"dot\">\
             <title>{}</title></circle>",
            x.map(p.start as f64),
            y.map(avg),
            escape(&title)
        ));
    }
    out
}

/// The empty state. A message, not an axis with nothing between it — a bare grid leaves the reader
/// wondering whether the page failed.
fn empty_plot(height: f64, message: &str) -> String {
    format!(
        "{}<text x=\"{:.1}\" y=\"{:.1}\" class=\"empty-plot\" text-anchor=\"middle\">{}</text></svg>",
        open_svg(height, message),
        WIDTH / 2.0,
        height / 2.0,
        escape(message)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
    #[test]
    fn series_colours_are_stable_slots() {
        assert_eq!(series_color(0), "var(--series-1)");
        assert_eq!(series_color(7), "var(--series-8)");
        assert_eq!(series_color(8), "var(--series-1)", "wraps rather than inventing a ninth hue");
    }

    /// **A gap must break the line, not be drawn across.** Interpolating over a period with no data
    /// is a claim about data that does not exist.
    #[test]
    fn a_gap_breaks_the_line_into_subpaths() {
        let points =
            vec![point(0, Some(1.0)), point(10, Some(2.0)), point(20, None), point(30, Some(3.0))];
        let x = Scale::new(0.0, 30.0, 0.0, 300.0);
        let y = Scale::new(0.0, 3.0, 100.0, 0.0);

        let path = line_path(&points, &x, &y, "var(--series-1)");
        assert_eq!(path.matches('M').count(), 2, "two runs means two subpaths: {path}");
    }

    #[test]
    fn a_single_point_still_renders_a_marker_but_no_line_segment() {
        let points = vec![point(0, Some(1.0))];
        let x = Scale::new(0.0, 10.0, 0.0, 100.0);
        let y = Scale::new(0.0, 1.0, 100.0, 0.0);

        assert!(line_path(&points, &x, &y, "c").contains('M'));
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
        let svg = value_chart(&[], 0, 100, "v", 0);
        assert!(svg.contains("no numeric values"), "{svg}");
        assert!(!svg.contains("<path"), "{svg}");

        let svg = timeline(&[], 0, 100, 10);
        assert!(svg.contains("no measurements in range"), "{svg}");
    }

    /// A series whose every bucket is null (a text field) must render the empty state rather than an
    /// axis with nothing on it.
    #[test]
    fn a_series_with_no_values_is_treated_as_empty() {
        let series = vec![Series { group: None, points: vec![point(0, None), point(10, None)] }];
        let svg = value_chart(&series, 0, 100, "state", 1);
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
        let svg = value_chart(&series, 0, 100, hostile, 1);

        assert!(!svg.contains("<script>"), "unescaped markup reached the SVG: {svg}");
        assert!(svg.contains("&lt;script&gt;"), "the value must still be shown, escaped");
    }

    #[test]
    fn a_legend_appears_only_with_more_than_one_series() {
        let one = vec![Series { group: Some("a".into()), points: vec![point(0, Some(1.0))] }];
        assert!(!value_chart(&one, 0, 100, "v", 1).contains("legend"));

        let two = vec![
            Series { group: Some("a".into()), points: vec![point(0, Some(1.0))] },
            Series { group: Some("b".into()), points: vec![point(0, Some(2.0))] },
        ];
        let svg = value_chart(&two, 0, 100, "v", 2);
        assert!(svg.contains("legend"), "{svg}");
    }

    /// The caveat must not depend on marker density: markers are dropped on a dense chart, which is
    /// exactly when there are most buckets to be partially covered.
    #[test]
    fn partial_coverage_is_reported_even_when_markers_are_dropped() {
        let sparse = vec![Series {
            group: None,
            points: vec![Point { start: 0, count: 10, value_count: 4, avg: Some(1.0), min: Some(1.0), max: Some(1.0) }],
        }];
        assert!(
            value_chart(&sparse, 0, 100, "ago", 1).contains("4 of 10 matching measurements"),
            "the sparse case"
        );

        let dense = vec![Series {
            group: None,
            points: (0..(MAX_MARKERS as i64 + 10))
                .map(|i| Point {
                    start: i,
                    count: 2,
                    value_count: 1,
                    avg: Some(i as f64),
                    min: Some(i as f64),
                    max: Some(i as f64),
                })
                .collect(),
        }];
        let svg = value_chart(&dense, 0, 100, "ago", 1);
        assert!(!svg.contains("<circle"), "precondition: markers are dropped when dense");
        assert!(svg.contains("matching measurements carried a number"), "but the caveat survives: {svg}");
    }

    /// ...and stays quiet when every row had a value, or it would be noise on every chart.
    #[test]
    fn full_coverage_is_not_commented_on() {
        let full = vec![Series {
            group: None,
            points: vec![Point { start: 0, count: 3, value_count: 3, avg: Some(1.0), min: Some(1.0), max: Some(1.0) }],
        }];
        assert!(!value_chart(&full, 0, 100, "v", 1).contains("carried a number"));
    }

    #[test]
    fn a_capped_series_count_says_how_many_were_left_out() {
        let series: Vec<Series> = (0..MAX_SERIES)
            .map(|i| Series { group: Some(i.to_string()), points: vec![point(0, Some(i as f64))] })
            .collect();
        let svg = value_chart(&series, 0, 100, "v", 16);
        assert!(svg.contains("Showing 8 of 16 groups"), "{svg}");
    }

    /// The container has to be tall enough for its own axis labels, or the card grows a nested
    /// scrollbar and crops them.
    #[test]
    fn the_viewbox_includes_the_axis_band() {
        let svg = timeline(&[point(0, None)], 0, 100, 10);
        let expected = TIMELINE_PLOT_HEIGHT + PAD_TOP + PAD_BOTTOM;
        assert!(svg.contains(&format!("0 0 {WIDTH} {expected}")), "{svg}");
    }

    /// The two plots are read as a stacked pair over one window, so their x axes must line up to the
    /// pixel.
    #[test]
    fn both_plots_share_the_same_horizontal_geometry() {
        let x = Scale::new(0.0, 100.0, PAD_LEFT, WIDTH - PAD_RIGHT);
        assert_eq!(x.map(0.0), PAD_LEFT);
        assert_eq!(x.map(100.0), WIDTH - PAD_RIGHT);
    }
}
