#!/usr/bin/env python3
"""Plot twelve performance panels from recorded median and byte-count CSV rows."""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP, localcontext
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "aw-mhac-matplotlib"))
import matplotlib as mpl
mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.lines import Line2D
from matplotlib.collections import LineCollection
from matplotlib.legend_handler import HandlerPatch
from matplotlib.markers import MarkerStyle
from matplotlib.patches import Patch, Rectangle
from matplotlib.ticker import FixedLocator, FuncFormatter, LogLocator, NullFormatter
from matplotlib.transforms import Bbox
import numpy as np

COLUMNS = (
    "scheme", "algorithm", "role", "N", "b", "k", "n", "h", "weight_bits",
    "runs", "median_ms", "p25_ms", "p75_ms", "bytes", "note", "layout",
    "warmup_runs", "warmup_s", "warmup_stable", "block_medians_ms",
)
DIMENSIONS = ("N", "b", "k", "n", "h", "weight_bits", "layout")
CANVAS_INCHES = (1.7, 1.45)
AXES_INCHES = (0.40, 0.45, 1.25, 0.85)
ALGORITHMS = {
    "Setup": ("setup", "#A3A3A3", None),
    "HKeyGen": ("holder", "#E9A23B", "s"),
    "PartSign": ("holder", "#E9A23B", "s"),
    "Issue": ("issuer", "#7B5EA7", "^"),
    "Accept": ("host", "#B5283A", "o"),
    "Show": ("host", "#B5283A", "o"),
    "Verify": ("verifier", "#3F6E9A", "D"),
    "Trace": ("auditor", "#2E9C8F", "^"),
    "Judge": ("judge", "#6D6875", "p"),
}
SCHEMES = {
    "aw_mhac": ("AW-MHAC", "#B5283A", "o"),
    "fll25": ("FLL25", "#23395B", "s"),
    "fll25_opt": ("FLL25 (opt.)", "#23395B", "s"),
    "hints": ("hinTS", "#5A9E6F", "^"),
    "fhll26": ("FHLL26", "#A3A3A3", "D"),
}


def font_family():
    for family in ("Arial", "Helvetica", "Liberation Sans"):
        try:
            font_manager.findfont(font_manager.FontProperties(family=family), fallback_to_default=False)
            return family
        except ValueError:
            continue
    raise RuntimeError("Arial, Helvetica, or Liberation Sans is required")


FONT_FAMILY = font_family()
mpl.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": [FONT_FAMILY],
    "font.size": 6.3,
    "mathtext.fontset": "custom",
    "mathtext.rm": FONT_FAMILY,
    "mathtext.it": FONT_FAMILY+":italic",
    "mathtext.bf": FONT_FAMILY+":bold",
    "mathtext.default": "regular",
    "axes.labelsize": 7,
    "xtick.labelsize": 6.3,
    "ytick.labelsize": 6.3,
    "legend.fontsize": 5.3,
    "axes.linewidth": 0.5,
    "axes.spines.top": True,
    "axes.spines.right": True,
    "xtick.direction": "in",
    "ytick.direction": "in",
    "xtick.top": True,
    "ytick.right": True,
    "xtick.major.size": 2.2,
    "ytick.major.size": 2.2,
    "xtick.minor.size": 1.2,
    "ytick.minor.size": 1.2,
    "lines.linewidth": 0.9,
    "lines.markersize": 3,
    "hatch.linewidth": 0.3,
    "pdf.fonttype": 42,
    "svg.fonttype": "none",
    "savefig.bbox": None,
    "savefig.facecolor": "white",
    "figure.facecolor": "white",
    "axes.unicode_minus": False,
})


@dataclass(frozen=True)
class Series:
    scheme: str
    algorithm: str
    role: str
    label: str
    color: str
    marker: str | None
    linestyle: str = "-"
    hatch: str | None = None


def algorithm_series(names):
    return tuple(Series("aw_mhac", name, ALGORITHMS[name][0], name, *ALGORITHMS[name][1:])
                 for name in names)


def scheme_series(names, algorithm, role):
    return tuple(Series(name, algorithm, role, *SCHEMES[name],
                        linestyle="--" if name == "fll25_opt" else "-",
                        hatch="////////" if name == "fll25_opt" else None) for name in names)


@dataclass(frozen=True)
class Panel:
    filename: str
    number: str
    experiment: str
    kind: str
    xfield: str | None
    grid: tuple
    series: tuple[Series, ...]
    xlabel: str
    ylabel: str
    metric: str = "median_ms"
    scale: float = 1.0
    logy: bool = True
    categories: tuple = ()


def panels():
    own = algorithm_series(("PartSign", "Show", "Verify"))
    compared = ("aw_mhac", "fll25", "hints", "fll25_opt")
    return (
        Panel("fig_alg_time.pdf", "6(a)", "time_cost_table", "single_bars", None, (),
              algorithm_series(("Setup", "HKeyGen", "Issue", "Accept", "PartSign", "Show", "Verify", "Trace", "Judge")),
              "", "Execution Time (ms)"),
        Panel("fig_alg_size.pdf", "6(b)", "default_parameters", "single_bars", None, (),
              tuple(Series("aw_mhac", algorithm, role, label, ALGORITHMS[label][1], None)
                    for algorithm, role, label in (
                        ("Parameters", "setup", "Setup"), ("Rho", "holder", "HKeyGen"),
                        ("Credential", "holder", "Issue"), ("PartialSignature", "holder", "PartSign"),
                        ("Presentation", "host", "Show"), ("TraceOutput", "auditor", "Trace"))),
              "", "Output Size (B)", metric="bytes", logy=False),
        Panel("fig_growth_slots.pdf", "7(a)", "vary_slots", "lines", "N", (16,32,64,128,256,512),
              own, "N: number of slots", "Execution Time (ms)"),
        Panel("fig_growth_attrs.pdf", "7(b)", "vary_attributes", "lines", "n", (5,10,20,30,40,50),
              own, "n: number of attributes", "Execution Time (ms)"),
        Panel("fig_pres_holders.pdf", "8(a)", "vary_participants", "grouped_bars", "k", (2,4,8,16),
              own, "k: number of participants", "Execution Time (ms)"),
        Panel("fig_pres_weights.pdf", "8(b)", "vary_weight_bits", "grouped_bars", "weight_bits", (1,4,8,16,32),
              own, "Bit length of weights", "Execution Time (ms)"),
        Panel("fig_issue_slots.pdf", "9(a)", "vary_slots", "lines", "N", (16,32,64,128,256,512),
              algorithm_series(("HKeyGen", "Issue", "Accept")), "N: number of slots", "Execution Time (ms)"),
        Panel("fig_audit.pdf", "9(b)", "audit_vs_participants", "lines", "k", (2,4,8,16),
              algorithm_series(("Verify", "Trace", "Judge")), "k: number of participants", "Execution Time (ms)"),
        Panel("fig_cmp_comp.pdf", "10(a)", "compare_computation", "grouped_bars", "k", (2,4,8,16),
              scheme_series(compared, "Total", "total"), "k: number of participants", "Execution Time (ms)"),
        Panel("fig_cmp_comm.pdf", "10(b)", "compare_link_bytes", "grouped_bars", "k", (2,4,8,16),
              scheme_series(compared, "LinkBytes", "link"), "k: number of participants", "Communication (B)",
              metric="bytes"),
        Panel("fig_cmp_holder.pdf", "11(a)", "compare_computation", "lines", "k", (2,4,8,16),
              scheme_series(compared, "PartSign", "holder"), "k: number of participants", "Execution Time (ms)"),
        Panel("fig_cmp_storage.pdf", "11(b)", "compare_holder_storage", "lines", "n", (5,10,20,30,40,50),
              scheme_series(("aw_mhac", "fll25", "fhll26", "fll25_opt"), "Storage", "holder"),
              "n: number of attributes", "Storage (B)", metric="bytes"),
    )


def parse_number(value, integer, field, filename):
    if value in ("", "-"):
        return None
    result = int(value) if integer else float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"Invalid {field} in {filename}")
    return result


def rows_from(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise ValueError(f"Invalid CSV columns in {path.name}")
        rows = list(reader)
    seen = set()
    for line, row in enumerate(rows, 2):
        if None in row:
            raise ValueError(f"Unexpected CSV fields at {path.name}:{line}")
        row["median_ms_exact"] = row["median_ms"]
        row["bytes_exact"] = row["bytes"]
        for field in (*DIMENSIONS, "runs", "bytes"):
            row[field] = parse_number(row[field], True, field, path.name)
        for field in ("median_ms", "p25_ms", "p75_ms"):
            row[field] = parse_number(row[field], False, field, path.name)
        key = tuple(row[field] for field in ("scheme", "algorithm", "role", *DIMENSIONS))
        if key in seen:
            raise ValueError(f"Duplicate measurement at {path.name}:{line}")
        seen.add(key)
        if row["median_ms"] is not None:
            lower, median, upper = (row[field] for field in ("p25_ms", "median_ms", "p75_ms"))
            if lower is None or upper is None or not lower <= median <= upper or not row["runs"]:
                raise ValueError(f"Invalid measured quartiles at {path.name}:{line}")
            if row["bytes"] is not None:
                raise ValueError(f"Mixed timing and byte fields at {path.name}:{line}")
        if any(word in row["note"].lower() for word in ("blocked", "timeout", "timed out")):
            if row["median_ms"] is not None or row["bytes"] is not None:
                raise ValueError(f"Unavailable row contains numeric output at {path.name}:{line}")
    return rows


def expected_dimensions(panel, scheme, x):
    dimensions = dict(N=32, b=16, k=8, n=10, h=7, weight_bits=1, layout=0)
    if panel.experiment == "vary_slots":
        dimensions["N"] = x
    elif panel.experiment in ("vary_attributes", "compare_holder_storage"):
        dimensions.update(n=x, h=x-3)
    elif panel.experiment == "vary_participants":
        dimensions["k"] = x
    elif panel.experiment == "vary_weight_bits":
        dimensions["weight_bits"] = x
    elif panel.experiment == "audit_vs_participants":
        dimensions["k"] = x
    elif panel.experiment in ("compare_computation", "compare_link_bytes"):
        dimensions["k"] = x
    if scheme in ("fll25", "fll25_opt"):
        dimensions["N"] = None
    elif scheme == "fhll26":
        dimensions.update(N=None, b=1, k=1)
    return dimensions


def select_row(rows, panel, series, x):
    dimensions = expected_dimensions(panel, series.scheme, x)
    candidates = [row for row in rows if row["scheme"] == series.scheme
                  and row["algorithm"] == series.algorithm and row["role"] == series.role
                  and all(row[field] == value for field, value in dimensions.items())]
    if len(candidates) > 1:
        raise ValueError(f"Ambiguous {panel.filename}/{series.label}/{x}")
    return candidates[0] if candidates else None


def plain_number(value, position=None):
    if value == 0:
        return "0"
    if abs(value) < 0.01:
        return f"{value:g}"
    return f"{value:g}"


def median_label(csv_text):
    """Round an exact CSV decimal to three significant digits, half upwards."""
    if not isinstance(csv_text, (str, Decimal)):
        raise TypeError("median_label requires the exact CSV decimal string")
    value = Decimal(csv_text)
    if not value.is_finite() or value <= 0:
        raise ValueError("A bar timing must be finite and positive")
    with localcontext() as context:
        context.prec = max(50, len(value.as_tuple().digits) + abs(value.adjusted()) + 8)
        rounded = value.quantize(Decimal(1).scaleb(value.adjusted()-2), rounding=ROUND_HALF_UP)
        exponent = rounded.adjusted()
        if exponent >= 3 or exponent < -3:
            coefficient = rounded.scaleb(-exponent)
            return f"{coefficient:.2f}e{exponent:+03d}"
        return f"{rounded:.{max(0,2-exponent)}f}"


def decade_label(value, position=None):
    if value <= 0:
        return ""
    exponent = round(math.log10(value))
    return rf"$10^{{{exponent}}}$"


def new_panel(panel):
    figure = plt.figure(figsize=CANVAS_INCHES)
    left, bottom, width, height = AXES_INCHES
    axis = figure.add_axes([left/CANVAS_INCHES[0], bottom/CANVAS_INCHES[1],
                            width/CANVAS_INCHES[0], height/CANVAS_INCHES[1]])
    axis.set_axisbelow(True)
    axis.grid(which="major", axis="both" if panel.kind == "lines" else "y",
              color="#B0B0B0", linewidth=0.4, linestyle="--", alpha=0.8)
    axis.tick_params(which="both", direction="in", top=True, right=True, pad=1.6)
    for spine in axis.spines.values():
        spine.set_visible(True)
        spine.set_linewidth(0.5)
        spine.set_edgecolor("black")
    axis.xaxis.labelpad = 1.8
    axis.yaxis.labelpad = 1.8
    axis.set_xlabel(panel.xlabel)
    axis.set_ylabel(panel.ylabel)
    axis.yaxis.set_major_formatter(FuncFormatter(plain_number))
    if panel.logy:
        axis.set_yscale("log")
        axis.yaxis.set_major_locator(LogLocator(base=10, numticks=5))
        axis.yaxis.set_major_formatter(FuncFormatter(plain_number))
        axis.yaxis.set_minor_locator(LogLocator(base=10, subs=(2,5), numticks=30))
        axis.yaxis.set_minor_formatter(NullFormatter())
    if panel.filename == "fig_cmp_comm.pdf":
        axis.yaxis.set_major_formatter(FuncFormatter(decade_label))
    return figure, axis


class CenteredHatchHandler(HandlerPatch):
    """Use centered, closely spaced diagonals without resizing the legend key."""

    def create_artists(self, legend, original, xdescent, ydescent, width, height, fontsize, transform):
        left, bottom = -xdescent, -ydescent
        color = original.get_edgecolor()
        background = Rectangle((left, bottom), width, height, facecolor="white",
                               edgecolor="none", transform=transform)
        # Handler coordinates are physical points. Centering fixes the hatch phase
        # for a small key independently of the figure's position on the page.
        pitch = 1.5
        center_x, center_y = left+width/2, bottom+height/2
        reach = width+height
        count = math.ceil(reach/pitch)
        segments = [((center_x-reach, center_y-reach+index*pitch),
                     (center_x+reach, center_y+reach+index*pitch))
                    for index in range(-count, count+1)]
        strokes = LineCollection(segments, colors=[color], linewidths=0.3,
                                 capstyle="butt", transform=transform)
        strokes.set_clip_path(background)
        border = Rectangle((left, bottom), width, height, facecolor="none",
                           edgecolor=color, linewidth=0.3, transform=transform)
        return [background, strokes, border]


def legend_for(axis, panel):
    if panel.kind == "single_bars":
        return None
    if panel.kind == "lines":
        handles = [Line2D([], [], color=series.color, marker=series.marker,
                          linewidth=0.9, linestyle=series.linestyle, markersize=3,
                          markerfacecolor="white", markeredgewidth=0.6)
                   for series in panel.series]
    else:
        handles = [Patch(facecolor="white" if series.hatch else series.color,
                         edgecolor=series.color if series.hatch else "#303030",
                         linewidth=0.3, hatch=series.hatch) for series in panel.series]
    handlers = {handle: CenteredHatchHandler() for handle, series in zip(handles, panel.series)
                if panel.kind != "lines" and series.hatch}
    def build(spacing):
        previous = axis.get_legend()
        if previous:
            previous.remove()
        legend = axis.legend(handles, [series.label for series in panel.series],
                             handler_map=handlers, loc="upper center", bbox_to_anchor=(0.5, 0.995), ncol=2 if len(handles) == 4 else len(handles),
                             fontsize=5.3, frameon=True, fancybox=False, framealpha=1,
                             facecolor="white", edgecolor="#303030",
                             handlelength=0.4 if panel.kind == "grouped_bars" else 0.8,
                             handletextpad=0.15 if panel.kind == "grouped_bars" else 0.22,
                             columnspacing=spacing,
                             borderpad=0.1 if panel.kind == "grouped_bars" else 0.18,
                             borderaxespad=0.16, labelspacing=0.2 if len(handles) == 4 else 0)
        legend.get_frame().set_linewidth(0.3)
        axis.figure.canvas.draw()
        return legend

    def fits(legend):
        renderer = axis.figure.canvas.get_renderer()
        frame = legend.get_frame()
        bounds = frame.get_window_extent(renderer).padded(renderer.points_to_pixels(frame.get_linewidth()/2))
        axes_bounds = axis.get_window_extent(renderer)
        return bounds.x0 >= axes_bounds.x0 and bounds.x1 <= axes_bounds.x1

    requested = 0.8 if panel.kind == "grouped_bars" else 0.42
    legend = build(requested)
    if not fits(legend):
        low, high = 0.0, requested
        legend = build(low)
        if not fits(legend):
            raise ValueError("Legend cannot fit at zero column spacing")
        for _ in range(22):
            middle = (low+high)/2
            legend = build(middle)
            if fits(legend):
                low = middle
            else:
                high = middle
        legend = build(low)
    return legend


def set_limits(axis, panel, values):
    present = [value for value in values if value is not None]
    if panel.logy:
        if any(value <= 0 for value in present):
            raise ValueError(f"{panel.filename}: logarithmic scale requires positive recorded values")
        if present:
            lower = 10**math.floor(math.log10(min(present)))
            upper = max(max(present)*1.05, lower*10)
            axis.set_ylim(lower, upper)
        else:
            axis.set_ylim(0.1, 10)
    else:
        axis.set_ylim(0, max(present, default=1)*1.05)


def layout_bounds(axis, labels, legend, renderer):
    bounds = []
    for index, label in enumerate(labels):
        bounds.append((f"annotation:{index}", "annotation", label.get_window_extent(renderer)))
    if legend:
        frame = legend.get_frame()
        box = frame.get_window_extent(renderer).padded(renderer.points_to_pixels(frame.get_linewidth()/2))
        bounds.append(("legend", "legend", box))
    for line_index, line in enumerate(axis.lines):
        if line.get_marker() in (None, "None", "", " "):
            continue
        marker = MarkerStyle(line.get_marker())
        shape = marker.get_path().transformed(marker.get_transform()).get_extents()
        size = renderer.points_to_pixels(line.get_markersize())
        padding = renderer.points_to_pixels(line.get_markeredgewidth()/2)
        for point_index, point in enumerate(line.get_transform().transform(line.get_xydata())):
            if not np.all(np.isfinite(point)):
                continue
            x, y = point
            box = Bbox.from_extents(x+shape.x0*size, y+shape.y0*size,
                                    x+shape.x1*size, y+shape.y1*size).padded(padding)
            bounds.append((f"marker:{line_index}:{point_index}", "marker", box))
    spine = axis.spines["top"]
    top = spine.get_path().get_extents(spine.get_transform()).padded(renderer.points_to_pixels(spine.get_linewidth()/2))
    bounds.append(("upper_frame", "upper_frame", top))
    return bounds


def layout_collisions(bounds, renderer):
    collisions, marker_overlaps = [], []
    top = next(box for _, kind, box in bounds if kind == "upper_frame")
    clearance = []
    for name, kind, box in bounds:
        if kind == "annotation":
            distance = (top.y0-box.y1)/renderer.points_to_pixels(1)
            clearance.append(dict(object=name, distance_pt=distance))
            if distance < 1.5:
                collisions.append(dict(objects=[name, "upper_frame"], reason="annotation clearance below 1.5 pt"))
    for index, (left_name, left_kind, left_box) in enumerate(bounds):
        for right_name, right_kind, right_box in bounds[index+1:]:
            if not left_box.overlaps(right_box):
                continue
            pair = dict(objects=[left_name,right_name], reason="rendered bounding boxes overlap")
            if left_kind == right_kind == "marker":
                marker_overlaps.append(pair)
            else:
                collisions.append(pair)
    return collisions, marker_overlaps, clearance


def clear_top(axis, panel, labels, legend):
    initial = list(axis.get_ylim())
    history = []
    for _ in range(100):
        lower, upper = axis.get_ylim()
        if panel.logy:
            first = round(math.log10(lower))
            last = math.floor(math.log10(upper)+1e-12)
            ticks = [10**exponent for exponent in range(first,last+1)]
            if len(ticks) < 2:
                raise ValueError(f"{panel.filename}: fewer than two full-decade major ticks")
            axis.yaxis.set_major_locator(FixedLocator(ticks))
        axis.figure.canvas.draw()
        renderer = axis.figure.canvas.get_renderer()
        bounds = layout_bounds(axis,labels,legend,renderer)
        collisions, marker_overlaps, clearance = layout_collisions(bounds,renderer)
        if not collisions:
            return dict(
                initial_ylim=initial, final_ylim=[lower,upper], headroom_steps=len(history),
                growth_factor=10**0.5 if panel.logy else 1.1,
                annotation_clearance_required_pt=1.5, annotation_upper_clearance=clearance,
                collision_history=history, final_collisions=[], marker_overlap_pairs=marker_overlaps,
                marker_overlap_policy="Preserve coincident recorded points and report marker-only overlap",
                legend_columnspacing=legend.columnspacing if legend else None,
                legend_requested_columnspacing=0.8 if panel.kind == "grouped_bars" else None,
                legend_rows=2 if len(panel.series) == 4 else (1 if legend else 0),
                renderer_bounds_pt=[dict(object=name,kind=kind,bbox=[value/renderer.points_to_pixels(1) for value in box.extents])
                                    for name,kind,box in bounds],
            )
        history.append(dict(ylim=[lower,upper],collisions=collisions))
        axis.set_ylim(lower,upper*(10**0.5 if panel.logy else 1.1))
    raise ValueError(f"{panel.filename}: layout collisions remain after 100 headroom steps: {collisions}")


def visible_text(figure):
    for axis in figure.axes:
        yield axis.xaxis.label
        yield axis.yaxis.label
        for direction in (axis.xaxis, axis.yaxis):
            low, high = sorted(direction.get_view_interval())
            for tick in direction.get_major_ticks() + direction.get_minor_ticks():
                if low <= tick.get_loc() <= high:
                    if tick.label1.get_visible():
                        yield tick.label1
                    if tick.label2.get_visible():
                        yield tick.label2
        yield from axis.texts
        legend = axis.get_legend()
        if legend:
            yield from legend.get_texts()


def geometry_check(figure, axis, labels, legend):
    figure.canvas.draw()
    renderer = figure.canvas.get_renderer()
    clipped = []
    for text in visible_text(figure):
        if not text.get_visible() or not text.get_text():
            continue
        box = text.get_window_extent(renderer)
        if min(box.x0, box.y0, figure.bbox.width-box.x1, figure.bbox.height-box.y1) < -0.75:
            clipped.append(text.get_text())
    if clipped:
        raise ValueError(f"Text leaves the prescribed canvas: {clipped}")
    if legend:
        bounds = legend.get_window_extent(renderer)
        axis_bounds = axis.get_window_extent(renderer)
        if bounds.x0 < axis_bounds.x0 - 0.5 or bounds.x1 > axis_bounds.x1 + 0.5:
            raise ValueError("Legend exceeds the prescribed axes width")
    label_collisions = []
    for index, left in enumerate(labels):
        for right in labels[index+1:]:
            if left.get_window_extent(renderer).overlaps(right.get_window_extent(renderer)):
                label_collisions.append((left.get_text(), right.get_text()))
    if label_collisions:
        raise ValueError(f"Bar labels overlap: {label_collisions}")


class Renderer:
    def __init__(self, data, output, previews=None, allow_incomplete=False, check_only=False):
        self.data, self.output, self.previews = data, output, previews
        self.allow_incomplete, self.check_only = allow_incomplete, check_only
        self.sources = {}
        self.source_provenance = {}
        self.audit = []

    def collect(self, panel):
        if panel.experiment not in self.sources:
            path = self.data / (panel.experiment + ".csv")
            self.sources[panel.experiment] = rows_from(path)
            self.source_provenance[path.name] = dict(
                sha256=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None,
                rows=len(self.sources[panel.experiment]),
            )
        rows = self.sources[panel.experiment]
        observations = []
        missing = []
        grid = panel.grid if panel.xfield else (None,)
        for series in panel.series:
            values = []
            for x in grid:
                row = select_row(rows, panel, series, x)
                if row is None or row[panel.metric] is None:
                    missing.append(f"{series.label}/{x if x is not None else series.algorithm}")
                    values.append(None)
                    continue
                value = row[panel.metric] * panel.scale
                if value <= 0 and panel.logy:
                    raise ValueError(f"{panel.filename}: nonpositive logarithmic observation")
                values.append(value)
                observations.append(dict(
                    scheme=row["scheme"], algorithm=row["algorithm"], role=row["role"],
                    **{field: row[field] for field in DIMENSIONS}, raw_value=row[panel.metric],
                    raw_exact=row[panel.metric+"_exact"],
                    plotted_value=value, metric=panel.metric, runs=row["runs"],
                    note=row["note"], warmup_runs=row["warmup_runs"], warmup_s=row["warmup_s"],
                    warmup_stable=row["warmup_stable"], block_medians_ms=row["block_medians_ms"],
                ))
            series_values = tuple(values)
            series_entry = (series, series_values)
            yield series_entry
        self.audit.append(dict(
            file=panel.filename, panel=panel.number, experiment=panel.experiment,
            kind=panel.kind, source_rows=len(rows), plotted_rows=len(observations),
            used_rows=observations, missing=missing, complete=not missing,
            statistic="median" if panel.metric == "median_ms" else "serialized bytes",
            uncertainty="not drawn; quartiles retained in CSV",
            xscale="log2" if panel.kind == "lines" and panel.xfield in ("N","k") else "linear",
            yscale="log10" if panel.logy else "linear", ylabel=panel.ylabel,
        ))

    def render(self, panel, series_data, missing):
        figure, axis = new_panel(panel)
        annotations, values, annotation_records = [], [], []
        exact_rows = {(row["scheme"], row["algorithm"], row["role"], row[panel.xfield] if panel.xfield else None): row
                      for row in self.audit[-1]["used_rows"]}
        if panel.kind == "lines":
            for series, observed in series_data:
                yy = [value if value is not None else math.nan for value in observed]
                axis.plot(panel.grid, yy, color=series.color, marker=series.marker,
                          markerfacecolor="white", markeredgecolor=series.color, markeredgewidth=0.6,
                          linewidth=0.9, linestyle=series.linestyle, markersize=3)
                for x, value in zip(panel.grid, observed):
                    if value is None:
                        axis.text(x,0.03,"×",transform=axis.get_xaxis_transform(),
                                  ha="center",va="bottom",color=series.color,fontsize=5.3)
                values.extend(observed)
            if panel.xfield in ("N","k"):
                axis.set_xscale("log",base=2)
            axis.xaxis.set_major_locator(FixedLocator(panel.grid))
            axis.set_xticklabels([str(x) for x in panel.grid])
            axis.xaxis.set_minor_locator(FixedLocator([]))
            if panel.xfield in ("N","k"):
                axis.set_xlim(panel.grid[0]/1.12, panel.grid[-1]*1.12)
            else:
                axis.set_xlim(panel.grid[0]-2,panel.grid[-1]+2)
        else:
            groups = len(panel.series) if panel.kind == "single_bars" else len(panel.grid)
            count = 1 if panel.kind == "single_bars" else len(panel.series)
            step, width = 0.78/count, 0.78/count*0.86
            for index, (series, observed) in enumerate(series_data):
                for group, value in enumerate(observed):
                    x = index if panel.kind == "single_bars" else group + (index-(count-1)/2)*step
                    values.append(value)
                    if value is None:
                        axis.text(x,0.025,"NA",transform=axis.get_xaxis_transform(),
                                  ha="center",va="bottom",rotation=90,rotation_mode="anchor",
                                  color=series.color,fontsize=4.5)
                        continue
                    axis.bar(x,value,width=width,color="white" if series.hatch else series.color,
                             edgecolor=series.color if series.hatch else "#303030",
                             linewidth=0.3,hatch=series.hatch)
                    exact_row = exact_rows[(series.scheme, series.algorithm, series.role,
                                            panel.grid[group] if panel.xfield else None)]
                    exact = exact_row["raw_exact"]
                    label = str(int(exact)) if panel.metric == "bytes" else median_label(exact)
                    annotation_records.append(dict(source=exact_row, label=label, rounding="integer" if panel.metric == "bytes" else "decimal ROUND_HALF_UP, three significant digits"))
                    annotations.append(axis.annotate(label,(x,value),xytext=(0,2),textcoords="offset points",
                                                     ha="left",va="center",rotation=90,rotation_mode="anchor",fontsize=4.5))
            labels = [series.label for series in panel.series] if panel.kind == "single_bars" else [str(x) for x in panel.grid]
            axis.set_xticks(range(groups),labels=labels,rotation=55 if panel.kind == "single_bars" else 0,
                            rotation_mode="anchor")
            if panel.kind == "single_bars":
                plt.setp(axis.get_xticklabels(),ha="right",va="top")
            axis.set_xlim(-0.5,groups-0.5)
            axis.xaxis.set_minor_locator(FixedLocator([]))
        set_limits(axis,panel,values)
        legend = legend_for(axis,panel)
        if missing:
            axis.text(0.99,0.015,"Missing data",transform=axis.transAxes,ha="right",va="bottom",fontsize=5.3,color="#666666")
        layout = clear_top(axis,panel,annotations,legend)
        geometry_check(figure,axis,annotations,legend)
        self.audit[-1]["ylim"] = list(axis.get_ylim())
        self.audit[-1]["xlim"] = list(axis.get_xlim())
        self.audit[-1]["bar_width"] = width if panel.kind != "lines" else None
        self.audit[-1]["bar_labels"] = [annotation.get_text() for annotation in annotations]
        self.audit[-1]["bar_annotations"] = annotation_records
        self.audit[-1]["geometry_check"] = "passed"
        self.audit[-1]["layout"] = layout
        figure.savefig(self.output/panel.filename,metadata={
            "Author":None,"Title":None,"Subject":None,"Creator":None,"Producer":None,
            "CreationDate":None,"ModDate":None})
        if self.previews:
            figure.savefig(self.previews/panel.filename.replace(".pdf",".png"),dpi=300)
        plt.close(figure)
        print(f"{panel.filename}: {self.audit[-1]['plotted_rows']} recorded rows; "
              f"ylim=[{float(axis.get_ylim()[0]):.12g}, {float(axis.get_ylim()[1]):.12g}]; "
              f"headroom_steps={layout['headroom_steps']}; "
              f"legend_columnspacing={layout['legend_columnspacing']}; "
              f"marker_overlap_pairs={len(layout['marker_overlap_pairs'])}" +
              (f"; missing {', '.join(missing)}" if missing else ""),flush=True)

    def run(self, selected=None):
        prepared = []
        for panel in panels():
            if selected and panel.filename.removesuffix(".pdf") not in selected:
                continue
            data = list(self.collect(panel))
            prepared.append((panel,data,self.audit[-1]["missing"]))
        incomplete = [entry for entry in self.audit if entry["missing"]]
        if incomplete and not self.allow_incomplete:
            raise ValueError("Required recorded data are missing: " + "; ".join(entry["file"]+"="+",".join(entry["missing"]) for entry in incomplete))
        if self.check_only:
            print(json.dumps(dict(panels=self.audit,complete=not incomplete),indent=2))
            return
        self.output.mkdir(parents=True,exist_ok=True)
        if self.previews:
            self.previews.mkdir(parents=True,exist_ok=True)
        # Each panel owns its QA record while it is rendered.
        audit = self.audit
        self.audit = []
        for entry,(panel,data,missing) in zip(audit,prepared):
            self.audit.append(entry)
            self.render(panel,data,missing)
        contract = dict(
            canvas_inches=CANVAS_INCHES,axes_inches=AXES_INCHES,font=FONT_FAMILY,
            tick_pt=6.3,axis_label_pt=7,legend_pt=5.3,bar_annotation_pt=4.5,
            bar_annotation_rule="Timing bars use exact CSV decimal ROUND_HALF_UP to three significant digits; byte bars use integer B with no suffix",
            communication_tick_rule="All major ticks use powers of ten in Arial mathtext; base6.3pt, superscript4.41pt",
            log_lower_rule="Largest integer power of ten no greater than the smallest plotted value",
            headroom_log_multiplier=10**0.5, headroom_linear_multiplier=1.1,
            annotation_upper_clearance_pt=1.5, bar_legend_columnspacing_target=0.8,
            size_unit="B",line_width_pt=0.9,marker_size_pt=3,
            error_bars=False,pdf_titles=False,panels=self.audit,
            sources=self.source_provenance,
            source_filter="Exact experiment, scheme, algorithm, role, and fixed parameter values",
            exclusions="Rows used by other panels are retained in CSV. hinTS storage is retained in CSV and omitted from storage plot as specified.",
            storage_variant="FLL25 original and FLL25 (opt.), including cache and excluding shared public parameters",
        )
        (self.output/"plot-audit.json").write_text(json.dumps(contract,indent=2)+"\n",encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data",type=Path,default=Path("data"))
    parser.add_argument("--out",type=Path,default=Path("figures"))
    parser.add_argument("--preview-dir",type=Path)
    parser.add_argument("--allow-incomplete",action="store_true")
    parser.add_argument("--check-only",action="store_true",help="validate recorded input without writing figures")
    parser.add_argument("--only",action="append",choices=[p.filename.removesuffix(".pdf") for p in panels()],
                        metavar="PANEL",help="render only the named panel; repeat for multiple panels")
    args = parser.parse_args()
    try:
        Renderer(args.data,args.out,args.preview_dir,args.allow_incomplete,args.check_only).run(args.only)
    except (OSError,ValueError,RuntimeError) as error:
        parser.exit(1,f"plot.py: {error}\n")


if __name__ == "__main__":
    main()
