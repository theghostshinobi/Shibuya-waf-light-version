#!/usr/bin/env python3
"""
SHIBUYA WAF — Benchmark Report Generator
Reads all benchmark outputs and generates a single markdown report.
Usage: python3 benchmarks/report_generator.py --results-dir ./results/<timestamp> --output REPORT.md
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from statistics import mean

# ── Configuration ────────────────────────────────────────────────────────────

TARGETS = {
    "latency_p50_ms": 2.0,
    "latency_p95_ms": 5.0,
    "latency_p99_ms": 10.0,
    "throughput_rps": 10000,
    "memory_mb": 500,
    "detection_sqli": 98.0,
    "detection_xss": 98.0,
    "detection_overall": 95.0,
    "false_positive_rate": 2.0,
}


def status_emoji(value, target, lower_is_better=True):
    """Return ✅/⚠️/❌ based on how close value is to target."""
    if lower_is_better:
        if value <= target:
            return "✅"
        elif value <= target * 1.5:
            return "⚠️"
        return "❌"
    else:
        if value >= target:
            return "✅"
        elif value >= target * 0.8:
            return "⚠️"
        return "❌"


# ── Data Loaders ─────────────────────────────────────────────────────────────

def load_k6_summary(results_dir):
    """Load k6 summary JSON."""
    path = os.path.join(results_dir, "k6_summary.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    metrics = data.get("metrics", {})
    dur = metrics.get("http_req_duration", {}).get("values", {})
    reqs = metrics.get("http_reqs", {}).get("values", {})
    failed = metrics.get("http_req_failed", {}).get("values", {})

    # Custom metrics
    clean = metrics.get("waf_clean_latency", {}).get("values", {})
    attack = metrics.get("waf_attack_latency", {}).get("values", {})
    block_rate = metrics.get("waf_block_rate", {}).get("values", {})

    return {
        "p50": dur.get("p(50)", 0),
        "p95": dur.get("p(95)", 0),
        "p99": dur.get("p(99)", 0),
        "avg": dur.get("avg", 0),
        "min": dur.get("min", 0),
        "max": dur.get("max", 0),
        "med": dur.get("med", 0),
        "rps": reqs.get("rate", 0),
        "total_requests": reqs.get("count", 0),
        "error_rate": failed.get("rate", 0),
        "clean_p50": clean.get("p(50)", 0),
        "clean_p95": clean.get("p(95)", 0),
        "attack_p50": attack.get("p(50)", 0),
        "attack_p95": attack.get("p(95)", 0),
        "block_rate": block_rate.get("rate", 0),
    }


def load_detection_results(results_dir):
    """Load detection CSV."""
    path = os.path.join(results_dir, "detection_results.csv")
    if not os.path.exists(path):
        return None
    results = {}
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            results[row["payload_type"]] = {
                "total": int(row["total"]),
                "detected": int(row["detected"]),
                "bypassed": int(row["bypassed"]),
                "rate": float(row["detection_rate"]),
            }
    return results


def load_memory_csv(results_dir):
    """Load memory profile CSV."""
    path = os.path.join(results_dir, "memory.csv")
    if not os.path.exists(path):
        return None
    data = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append({
                "elapsed": int(row["elapsed_s"]),
                "rss_mb": float(row["rss_mb"]),
            })
    return data


def load_coraza_comparison(results_dir):
    """Load Coraza comparison markdown."""
    path = os.path.join(results_dir, "coraza_comparison.md")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()


def load_gotestwaf_report(results_dir):
    """Load GoTestWAF report."""
    path = os.path.join(results_dir, "gotestwaf", "gotestwaf_report.md")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()


def load_criterion_log(results_dir):
    """Parse criterion benchmark output."""
    path = os.path.join(results_dir, "criterion.log")
    if not os.path.exists(path):
        return None
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            # Criterion bencher format: test ... bench:   123 ns/iter (+/- 45)
            if "bench:" in line and "ns/iter" in line:
                parts = line.split("bench:")
                name = parts[0].strip().rstrip(".")
                time_part = parts[1].strip()
                # Extract ns value
                ns_str = time_part.split("ns/iter")[0].strip().replace(",", "")
                try:
                    ns = float(ns_str)
                    results.append({"name": name, "ns": ns, "us": ns / 1000, "ms": ns / 1_000_000})
                except ValueError:
                    pass
            # Also handle criterion's default output format
            elif "time:" in line.lower() and ("[" in line or "ns" in line.lower()):
                pass  # Criterion HTML reports are in target/criterion/
    return results if results else None


# ── ASCII Chart Generator ───────────────────────────────────────────────────

def ascii_bar_chart(items, max_width=40):
    """Generate an ASCII horizontal bar chart."""
    if not items:
        return ""
    max_val = max(v for _, v in items) or 1
    lines = []
    max_label = max(len(label) for label, _ in items)
    for label, value in items:
        bar_len = int(value / max_val * max_width)
        bar = "█" * bar_len
        lines.append(f"  {label:<{max_label}} │{bar} {value:.1f}")
    return "\n".join(lines)


def ascii_sparkline(data_points, width=60):
    """Generate ASCII sparkline for time series."""
    if not data_points or len(data_points) < 2:
        return "  (insufficient data)"
    chars = " ▁▂▃▄▅▆▇█"
    min_v = min(data_points)
    max_v = max(data_points)
    rng = max_v - min_v or 1

    # Resample to width
    step = max(1, len(data_points) // width)
    sampled = data_points[::step][:width]

    line = ""
    for v in sampled:
        idx = int((v - min_v) / rng * (len(chars) - 1))
        line += chars[idx]

    return f"  {min_v:.0f}MB [{line}] {max_v:.0f}MB"


# ── Report Sections ─────────────────────────────────────────────────────────

def generate_executive_summary(k6, detection, memory):
    """Generate the executive summary section."""
    lines = ["## Executive Summary", ""]

    checks = []

    # Latency
    if k6:
        s = status_emoji(k6["p50"], TARGETS["latency_p50_ms"])
        checks.append(f"{s} **Latency p50**: {k6['p50']:.2f}ms (target: <{TARGETS['latency_p50_ms']}ms)")
        s = status_emoji(k6["p95"], TARGETS["latency_p95_ms"])
        checks.append(f"{s} **Latency p95**: {k6['p95']:.2f}ms (target: <{TARGETS['latency_p95_ms']}ms)")
        s = status_emoji(k6["p99"], TARGETS["latency_p99_ms"])
        checks.append(f"{s} **Latency p99**: {k6['p99']:.2f}ms (target: <{TARGETS['latency_p99_ms']}ms)")
        s = status_emoji(k6["rps"], TARGETS["throughput_rps"], lower_is_better=False)
        checks.append(f"{s} **Throughput**: {k6['rps']:,.0f} req/s (target: >{TARGETS['throughput_rps']:,})")
        s = status_emoji(k6["error_rate"] * 100, 1.0)
        checks.append(f"{s} **Error rate**: {k6['error_rate']*100:.2f}%")
    else:
        checks.append("⏭️ **Load test**: skipped (k6 not available)")

    # Detection
    if detection:
        # Overall attack detection (exclude false_positive)
        attack_types = [v for k, v in detection.items() if k != "false_positive"]
        if attack_types:
            overall = sum(d["detected"] for d in attack_types) / max(1, sum(d["total"] for d in attack_types)) * 100
            s = status_emoji(overall, TARGETS["detection_overall"], lower_is_better=False)
            checks.append(f"{s} **Detection rate**: {overall:.1f}% (target: >{TARGETS['detection_overall']}%)")

        if "false_positive" in detection:
            fp = detection["false_positive"]["rate"]
            s = status_emoji(fp, TARGETS["false_positive_rate"])
            checks.append(f"{s} **False positive**: {fp:.1f}% (target: <{TARGETS['false_positive_rate']}%)")

        for key, target_key in [("sqli", "detection_sqli"), ("xss", "detection_xss")]:
            if key in detection:
                rate = detection[key]["rate"]
                s = status_emoji(rate, TARGETS[target_key], lower_is_better=False)
                checks.append(f"{s} **{key.upper()} detection**: {rate:.1f}% (target: >{TARGETS[target_key]}%)")
    else:
        checks.append("⏭️ **Detection test**: not available")

    # Memory
    if memory and len(memory) >= 2:
        peak = max(d["rss_mb"] for d in memory)
        s = status_emoji(peak, TARGETS["memory_mb"])
        checks.append(f"{s} **Peak memory**: {peak:.0f}MB (target: <{TARGETS['memory_mb']}MB)")
        growth = memory[-1]["rss_mb"] - memory[0]["rss_mb"]
        growth_pct = growth / max(1, memory[0]["rss_mb"]) * 100
        s = status_emoji(abs(growth_pct), 20)
        checks.append(f"{s} **Memory growth**: {growth:+.1f}MB ({growth_pct:+.1f}%)")
    else:
        checks.append("⏭️ **Memory profile**: not available")

    for c in checks:
        lines.append(f"- {c}")

    # Overall verdict
    passes = sum(1 for c in checks if "✅" in c)
    warns = sum(1 for c in checks if "⚠️" in c)
    fails = sum(1 for c in checks if "❌" in c)
    total = passes + warns + fails
    lines.append("")
    if fails == 0 and warns == 0:
        lines.append(f"> 🟢 **ALL {total} CHECKS PASSED**")
    elif fails == 0:
        lines.append(f"> 🟡 **{passes}/{total} passed, {warns} warnings**")
    else:
        lines.append(f"> 🔴 **{passes}/{total} passed, {warns} warnings, {fails} failures**")

    return "\n".join(lines)


def generate_latency_section(k6):
    """Generate latency analysis section."""
    if not k6:
        return "## Latency Analysis\n\n_Skipped (k6 not available)_"

    lines = ["## Latency Analysis", ""]
    lines.append("| Percentile | Value (ms) | Target (ms) | Status |")
    lines.append("|:-----------|----------:|:-----------:|:------:|")

    for pct, key, target in [
        ("p50", "p50", TARGETS["latency_p50_ms"]),
        ("p95", "p95", TARGETS["latency_p95_ms"]),
        ("p99", "p99", TARGETS["latency_p99_ms"]),
    ]:
        val = k6[key]
        s = status_emoji(val, target)
        lines.append(f"| {pct} | {val:.2f} | <{target} | {s} |")

    lines.append(f"| avg | {k6['avg']:.2f} | — | — |")
    lines.append(f"| min | {k6['min']:.2f} | — | — |")
    lines.append(f"| max | {k6['max']:.2f} | — | — |")

    # Clean vs Attack latency
    if k6.get("clean_p95") or k6.get("attack_p95"):
        lines.append("")
        lines.append("### Clean vs Attack Latency")
        lines.append("")
        lines.append("| Traffic Type | p50 (ms) | p95 (ms) |")
        lines.append("|:-------------|--------:|---------:|")
        lines.append(f"| Clean (legitimate) | {k6.get('clean_p50', 0):.2f} | {k6.get('clean_p95', 0):.2f} |")
        lines.append(f"| Attack (blocked) | {k6.get('attack_p50', 0):.2f} | {k6.get('attack_p95', 0):.2f} |")

    # Bar chart
    lines.append("")
    lines.append("```")
    chart_data = [
        ("p50", k6["p50"]),
        ("p95", k6["p95"]),
        ("p99", k6["p99"]),
        ("avg", k6["avg"]),
    ]
    lines.append(ascii_bar_chart(chart_data))
    lines.append("```")

    return "\n".join(lines)


def generate_throughput_section(k6):
    """Generate throughput section."""
    if not k6:
        return "## Throughput\n\n_Skipped (k6 not available)_"

    lines = ["## Throughput", ""]
    rps = k6["rps"]
    total = k6["total_requests"]
    err = k6["error_rate"] * 100

    s = status_emoji(rps, TARGETS["throughput_rps"], lower_is_better=False)
    lines.append(f"- {s} **Sustained rate**: {rps:,.0f} req/s (target: >{TARGETS['throughput_rps']:,})")
    lines.append(f"- Total requests: {total:,.0f}")
    lines.append(f"- Error rate: {err:.3f}%")

    if k6.get("block_rate", 0) > 0:
        lines.append(f"- WAF block rate (attacks): {k6['block_rate']*100:.1f}%")

    return "\n".join(lines)


def generate_detection_section(detection):
    """Generate detection accuracy section."""
    if not detection:
        return "## Detection Accuracy\n\n_Not available_"

    lines = ["## Detection Accuracy", ""]
    lines.append("| Payload Type | Total | Detected | Bypassed | Rate | Status |")
    lines.append("|:-------------|------:|---------:|---------:|-----:|:------:|")

    for ptype, data in detection.items():
        if ptype == "false_positive":
            continue
        s = status_emoji(data["rate"], 95, lower_is_better=False)
        lines.append(
            f"| {ptype} | {data['total']} | {data['detected']} | {data['bypassed']} | {data['rate']:.1f}% | {s} |"
        )

    if "false_positive" in detection:
        fp = detection["false_positive"]
        s = status_emoji(fp["rate"], TARGETS["false_positive_rate"])
        lines.append("")
        lines.append("### False Positive Analysis")
        lines.append("")
        lines.append(f"- Total legitimate requests: {fp['total']}")
        lines.append(f"- Incorrectly blocked: {fp['detected']}")
        lines.append(f"- {s} False positive rate: **{fp['rate']:.1f}%** (target: <{TARGETS['false_positive_rate']}%)")

    # Bar chart
    attack_items = [(k, v["rate"]) for k, v in detection.items() if k != "false_positive"]
    if attack_items:
        lines.append("")
        lines.append("```")
        lines.append(ascii_bar_chart(attack_items, max_width=50))
        lines.append("```")

    return "\n".join(lines)


def generate_memory_section(memory):
    """Generate memory analysis section."""
    if not memory or len(memory) < 2:
        return "## Memory Profile\n\n_Not available_"

    lines = ["## Memory Profile", ""]

    initial = memory[0]["rss_mb"]
    final = memory[-1]["rss_mb"]
    peak = max(d["rss_mb"] for d in memory)
    duration = memory[-1]["elapsed"]
    growth = final - initial
    growth_pct = growth / max(1, initial) * 100

    lines.append("| Metric | Value |")
    lines.append("|:-------|------:|")
    lines.append(f"| Initial RSS | {initial:.1f} MB |")
    lines.append(f"| Final RSS | {final:.1f} MB |")
    lines.append(f"| Peak RSS | {peak:.1f} MB |")
    lines.append(f"| Growth | {growth:+.1f} MB ({growth_pct:+.1f}%) |")
    lines.append(f"| Duration | {duration}s |")
    lines.append(f"| Samples | {len(memory)} |")

    s = status_emoji(peak, TARGETS["memory_mb"])
    lines.append(f"\n{s} Peak memory: **{peak:.0f} MB** (target: <{TARGETS['memory_mb']} MB)")

    leak_status = "✅ STABLE" if abs(growth_pct) < 20 else "⚠️ POSSIBLE LEAK"
    lines.append(f"\nLeak detection: **{leak_status}**")

    # Sparkline
    rss_values = [d["rss_mb"] for d in memory]
    lines.append("")
    lines.append("### Memory Over Time")
    lines.append("```")
    lines.append(ascii_sparkline(rss_values))
    lines.append("```")

    return "\n".join(lines)


def generate_criterion_section(criterion):
    """Generate micro-benchmark section."""
    if not criterion:
        return "## Micro-Benchmarks (Criterion)\n\n_Check `criterion.log` or `target/criterion/` for HTML reports._"

    lines = ["## Micro-Benchmarks (Criterion)", ""]
    lines.append("| Benchmark | Time (ns) | Time (μs) | Time (ms) |")
    lines.append("|:----------|----------:|----------:|----------:|")

    for bench in criterion:
        lines.append(f"| {bench['name']} | {bench['ns']:,.0f} | {bench['us']:,.1f} | {bench['ms']:,.3f} |")

    # Check against targets
    for bench in criterion:
        name = bench["name"].lower()
        ms = bench["ms"]
        if "transform" in name or "parser" in name:
            s = status_emoji(ms, 0.5)  # <500μs
            lines.append(f"\n{s} Parser: {ms*1000:.0f}μs (target: <500μs)")
        elif "owasp" in name or "rule" in name:
            s = status_emoji(ms, 3.0)  # <3ms
            lines.append(f"\n{s} Rule Engine: {ms:.2f}ms (target: <3ms)")

    return "\n".join(lines)


# ── Main Report Assembly ────────────────────────────────────────────────────

def generate_report(results_dir, output_path):
    """Assemble all sections into one report."""
    # Load data
    k6 = load_k6_summary(results_dir)
    detection = load_detection_results(results_dir)
    memory = load_memory_csv(results_dir)
    coraza = load_coraza_comparison(results_dir)
    gotestwaf = load_gotestwaf_report(results_dir)
    criterion = load_criterion_log(results_dir)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run_name = os.path.basename(results_dir)

    sections = []

    # Header
    sections.append(f"# 🛡️ SHIBUYA WAF — Benchmark Report")
    sections.append(f"")
    sections.append(f"**Date**: {now}  ")
    sections.append(f"**Run ID**: `{run_name}`  ")
    sections.append(f"**Results Dir**: `{results_dir}`")
    sections.append("")
    sections.append("---")
    sections.append("")

    # Executive summary
    sections.append(generate_executive_summary(k6, detection, memory))
    sections.append("")
    sections.append("---")
    sections.append("")

    # Latency
    sections.append(generate_latency_section(k6))
    sections.append("")
    sections.append("---")
    sections.append("")

    # Throughput
    sections.append(generate_throughput_section(k6))
    sections.append("")
    sections.append("---")
    sections.append("")

    # Detection
    sections.append(generate_detection_section(detection))
    sections.append("")
    sections.append("---")
    sections.append("")

    # Memory
    sections.append(generate_memory_section(memory))
    sections.append("")
    sections.append("---")
    sections.append("")

    # Micro-benchmarks
    sections.append(generate_criterion_section(criterion))
    sections.append("")
    sections.append("---")
    sections.append("")

    # Coraza comparison
    if coraza:
        sections.append(coraza)
        sections.append("")
        sections.append("---")
        sections.append("")

    # GoTestWAF
    if gotestwaf:
        sections.append("## GoTestWAF OWASP Coverage")
        sections.append("")
        sections.append(gotestwaf)
        sections.append("")
        sections.append("---")
        sections.append("")

    # Performance targets table
    sections.append("## Performance Target Matrix")
    sections.append("")
    sections.append("| Target | Requirement | Actual | Status |")
    sections.append("|:-------|:------------|-------:|:------:|")

    def add_target(name, req, actual, lower_better=True, fmt=".2f", unit=""):
        if actual is not None:
            s = status_emoji(actual, req, lower_better)
            sections.append(f"| {name} | {'<' if lower_better else '>'}{req}{unit} | {actual:{fmt}}{unit} | {s} |")
        else:
            sections.append(f"| {name} | {'<' if lower_better else '>'}{req}{unit} | — | ⏭️ |")

    add_target("Latency p50", 2, k6["p50"] if k6 else None, True, ".2f", "ms")
    add_target("Latency p95", 5, k6["p95"] if k6 else None, True, ".2f", "ms")
    add_target("Latency p99", 10, k6["p99"] if k6 else None, True, ".2f", "ms")
    add_target("Throughput", 10000, k6["rps"] if k6 else None, False, ",.0f", " rps")

    if memory and len(memory) >= 2:
        peak = max(d["rss_mb"] for d in memory)
        add_target("Memory RSS", 500, peak, True, ".0f", "MB")

    if detection:
        attack_types = [v for k, v in detection.items() if k != "false_positive"]
        if attack_types:
            overall = sum(d["detected"] for d in attack_types) / max(1, sum(d["total"] for d in attack_types)) * 100
            add_target("Detection overall", 95, overall, False, ".1f", "%")
        if "sqli" in detection:
            add_target("SQLi detection", 98, detection["sqli"]["rate"], False, ".1f", "%")
        if "xss" in detection:
            add_target("XSS detection", 98, detection["xss"]["rate"], False, ".1f", "%")
        if "false_positive" in detection:
            add_target("False positive", 2, detection["false_positive"]["rate"], True, ".1f", "%")

    sections.append("")

    # Footer
    sections.append("---")
    sections.append("")
    sections.append(f"_Generated by SHIBUYA Benchmark Suite at {now}_")

    # Write report
    report = "\n".join(sections)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(report)

    print(f"[REPORT] Written to {output_path}")
    print(f"[REPORT] Sections: {sum(1 for s in sections if s.startswith('##'))}")

    # Try to generate PNG graphs if matplotlib is available
    try:
        generate_png_graphs(results_dir, k6, detection, memory)
    except ImportError:
        print("[REPORT] matplotlib not available — skipping PNG graphs")
    except Exception as e:
        print(f"[REPORT] Graph generation failed: {e}")


def generate_png_graphs(results_dir, k6, detection, memory):
    """Generate PNG graphs using matplotlib (optional)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    graphs_dir = os.path.join(results_dir, "graphs")
    os.makedirs(graphs_dir, exist_ok=True)

    # 1. Latency bar chart
    if k6:
        fig, ax = plt.subplots(figsize=(8, 4))
        labels = ["p50", "p95", "p99", "avg"]
        values = [k6["p50"], k6["p95"], k6["p99"], k6["avg"]]
        targets = [TARGETS["latency_p50_ms"], TARGETS["latency_p95_ms"], TARGETS["latency_p99_ms"], 0]
        colors = ["#2ecc71" if v <= t and t > 0 else "#e67e22" if t > 0 else "#3498db" for v, t in zip(values, targets)]

        bars = ax.bar(labels, values, color=colors, width=0.5, edgecolor="white")
        for t_val, label in zip(targets, labels):
            if t_val > 0:
                ax.axhline(y=t_val, color="#e74c3c", linestyle="--", alpha=0.5, linewidth=0.8)

        ax.set_ylabel("Latency (ms)")
        ax.set_title("SHIBUYA WAF — Latency Distribution")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        fig.tight_layout()
        fig.savefig(os.path.join(graphs_dir, "latency.png"), dpi=150)
        plt.close(fig)
        print(f"[REPORT] Graph: latency.png")

    # 2. Detection accuracy
    if detection:
        attack_data = {k: v for k, v in detection.items() if k != "false_positive"}
        if attack_data:
            fig, ax = plt.subplots(figsize=(8, 4))
            labels = list(attack_data.keys())
            rates = [attack_data[k]["rate"] for k in labels]
            colors = ["#2ecc71" if r >= 95 else "#e67e22" if r >= 80 else "#e74c3c" for r in rates]

            ax.barh(labels, rates, color=colors, edgecolor="white")
            ax.axvline(x=95, color="#e74c3c", linestyle="--", alpha=0.5, label="95% target")
            ax.set_xlim(0, 105)
            ax.set_xlabel("Detection Rate (%)")
            ax.set_title("SHIBUYA WAF — Detection Accuracy")
            ax.legend()
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            fig.tight_layout()
            fig.savefig(os.path.join(graphs_dir, "detection.png"), dpi=150)
            plt.close(fig)
            print(f"[REPORT] Graph: detection.png")

    # 3. Memory over time
    if memory and len(memory) >= 5:
        fig, ax = plt.subplots(figsize=(10, 4))
        elapsed = [d["elapsed"] for d in memory]
        rss = [d["rss_mb"] for d in memory]

        ax.fill_between(elapsed, rss, alpha=0.3, color="#3498db")
        ax.plot(elapsed, rss, color="#2980b9", linewidth=1.5)
        ax.axhline(y=TARGETS["memory_mb"], color="#e74c3c", linestyle="--", alpha=0.5, label=f"Target: {TARGETS['memory_mb']}MB")
        ax.set_xlabel("Time (seconds)")
        ax.set_ylabel("RSS Memory (MB)")
        ax.set_title("SHIBUYA WAF — Memory Usage Over Time")
        ax.legend()
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        fig.tight_layout()
        fig.savefig(os.path.join(graphs_dir, "memory.png"), dpi=150)
        plt.close(fig)
        print(f"[REPORT] Graph: memory.png")


# ── CLI Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SHIBUYA WAF Benchmark Report Generator")
    parser.add_argument("--results-dir", required=True, help="Directory with benchmark results")
    parser.add_argument("--output", required=True, help="Output markdown report path")
    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"[ERROR] Results directory not found: {args.results_dir}")
        sys.exit(1)

    generate_report(args.results_dir, args.output)
