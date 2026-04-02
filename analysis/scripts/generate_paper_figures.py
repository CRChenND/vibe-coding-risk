#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter


ROOT = Path(__file__).resolve().parents[2]
ATTR_SUMMARY = ROOT / "analysis/output/code_risk_analysis/attribution_summary.json"
TRAJ_SUMMARY = ROOT / "analysis/output/code_risk_analysis/trajectory_summary.json"
TOP_CWE_COUNTS = ROOT / "analysis/output/code_risk_analysis/top_cwe_counts.csv"
REGRESSION_BY_CWE = ROOT / "analysis/output/code_risk_analysis/assistant_regression_by_cwe.csv"
SOURCE_BY_CWE = ROOT / "analysis/output/code_risk_analysis/attribution_source_by_cwe.csv"
TEMPORAL_CURVE = ROOT / "analysis/output/code_risk_analysis/temporal_security_degradation_curve.csv"
OUT_DIR = ROOT / "paper_figures"

FIGSIZE = (10, 5.8)
TITLE_SIZE = 15
LABEL_SIZE = 11
TICK_SIZE = 10

CAUSE_ORDER = [
    ("user_requested_risk", "user requested"),
    ("assistant_over_implemented", "assistant over-implemented"),
    ("assistant_hallucinated_risk", "assistant hallucinated"),
    ("inherited_or_context_risk", "inherited/context"),
    ("mixed_causality", "mixed"),
    ("insufficient_evidence", "insufficient"),
]


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def style_axes(ax) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linestyle="--", alpha=0.25)
    ax.tick_params(axis="x", labelsize=TICK_SIZE)
    ax.tick_params(axis="y", labelsize=TICK_SIZE)


def annotate_bars(ax, bars, values, fmt: str = "{:.1%}") -> None:
    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(values) * 0.02,
            fmt.format(value),
            ha="center",
            va="bottom",
            fontsize=9,
        )


def fig1_attribution_distribution(attr_summary: dict) -> None:
    dist = attr_summary["attribution_distribution"]
    labels = [label for key, label in CAUSE_ORDER]
    values = [dist[key]["ratio"] for key, _ in CAUSE_ORDER]
    n = attr_summary["n_code_risk_rows"]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    bars = ax.bar(labels, values, color="#2458e6")
    style_axes(ax)
    ax.set_title(f"Attribution Distribution (Code-Risk Subset, N={n})", fontsize=TITLE_SIZE)
    ax.set_ylabel("Share of risky findings", fontsize=LABEL_SIZE)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylim(0, max(values) * 1.18)
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right")
    annotate_bars(ax, bars, values)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig1_attribution_distribution.svg", format="svg")
    plt.close(fig)


def fig2_top_cwe(attr_summary: dict) -> None:
    rows = load_csv(TOP_CWE_COUNTS)[:8]
    labels = [row["cwe"] for row in rows][::-1]
    values = [int(row["count"]) for row in rows][::-1]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    bars = ax.barh(labels, values, color="#e4572e")
    style_axes(ax)
    ax.set_title("Top CWE Counts in Code-Risk Findings", fontsize=TITLE_SIZE)
    ax.set_xlabel("Count", fontsize=LABEL_SIZE)
    ax.set_xlim(0, max(values) * 1.15)
    for bar, value in zip(bars, values):
        ax.text(value + max(values) * 0.015, bar.get_y() + bar.get_height() / 2, str(value), va="center", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig2_top_cwe_counts.svg", format="svg")
    plt.close(fig)


def fig3_risk_emergence_bucket(traj_summary: dict) -> None:
    rows = traj_summary["risk_emergence_position"]["bucket_distribution"]
    labels = [row["turn_bucket"] for row in rows]
    values = [row["probability"] for row in rows]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    bars = ax.bar(labels, values, color="#f59e0b")
    style_axes(ax)
    ax.set_title("Code-Risk Emergence by Turn Bucket", fontsize=TITLE_SIZE)
    ax.set_ylabel("Probability", fontsize=LABEL_SIZE)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylim(0, max(values) * 1.18)
    annotate_bars(ax, bars, values)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig3_risk_emergence_bucket.svg", format="svg")
    plt.close(fig)


def fig4_regression_by_cwe() -> None:
    rows = load_csv(REGRESSION_BY_CWE)
    top = sorted(rows, key=lambda r: int(r["n_assistant_driven"]), reverse=True)[:8]
    labels = [row["cwe"] for row in top][::-1]
    values = [float(row["regression_rate"]) for row in top][::-1]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    bars = ax.barh(labels, values, color="#8b5cf6")
    style_axes(ax)
    ax.set_title("Assistant Regression Rate by CWE (Code-Risk Subset)", fontsize=TITLE_SIZE)
    ax.set_xlabel("Regression rate", fontsize=LABEL_SIZE)
    ax.xaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_xlim(0, max(values) * 1.15)
    for bar, value in zip(bars, values):
        ax.text(value + max(values) * 0.015, bar.get_y() + bar.get_height() / 2, f"{value:.1%}", va="center", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig4_regression_by_cwe.svg", format="svg")
    plt.close(fig)


def fig5_temporal_survival_curve() -> None:
    rows = load_csv(TEMPORAL_CURVE)
    xs = [int(row["turn"]) for row in rows]
    ys = [float(row["survival_remaining_secure"]) for row in rows]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.plot(xs, ys, color="#059669", linewidth=2.5)
    ax.fill_between(xs, ys, [0] * len(xs), color="#10b981", alpha=0.12)
    style_axes(ax)
    ax.set_title("Temporal Code-Risk Degradation Curve", fontsize=TITLE_SIZE)
    ax.set_xlabel("Turn", fontsize=LABEL_SIZE)
    ax.set_ylabel("P(remaining secure)", fontsize=LABEL_SIZE)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylim(0, 1.02)
    ax.set_xlim(0, min(max(xs), 60))
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig5_temporal_survival_curve.svg", format="svg")
    plt.close(fig)


def fig6_source_by_cwe() -> None:
    rows = load_csv(SOURCE_BY_CWE)
    top = sorted(rows, key=lambda r: int(r["total"]), reverse=True)[:8]
    labels = [row["cwe"] for row in top]
    assistant = [float(row["assistant_driven_ratio"]) for row in top]
    user = [float(row["user_driven_ratio"]) for row in top]
    unclear = [float(row["unclear_ratio"]) for row in top]

    x = range(len(labels))
    width = 0.24

    fig, ax = plt.subplots(figsize=(11.2, 5.8))
    b1 = ax.bar([i - width for i in x], assistant, width=width, color="#2563eb", label="assistant-driven")
    b2 = ax.bar(x, user, width=width, color="#dc2626", label="user-driven")
    b3 = ax.bar([i + width for i in x], unclear, width=width, color="#6b7280", label="unclear")
    style_axes(ax)
    ax.set_title("Attribution Source by CWE (Code-Risk Subset)", fontsize=TITLE_SIZE)
    ax.set_ylabel("Within-CWE share", fontsize=LABEL_SIZE)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylim(0, 1.08)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    ax.legend(frameon=False, fontsize=9, ncol=3, loc="upper right")
    for bars in (b1, b2, b3):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.015, f"{h:.0%}", ha="center", va="bottom", fontsize=7)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig6_attribution_source_by_cwe.svg", format="svg")
    plt.close(fig)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    attr_summary = load_json(ATTR_SUMMARY)
    traj_summary = load_json(TRAJ_SUMMARY)

    fig1_attribution_distribution(attr_summary)
    fig2_top_cwe(attr_summary)
    fig3_risk_emergence_bucket(traj_summary)
    fig4_regression_by_cwe()
    fig5_temporal_survival_curve()
    fig6_source_by_cwe()

    print(f"Wrote figures to {OUT_DIR}")


if __name__ == "__main__":
    main()
