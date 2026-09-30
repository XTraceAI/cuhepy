#!/usr/bin/env python3
"""Standalone Matplotlib figures from retained E37 data and E39 serial models.

No new timings. Plotting uses a separate environment; numerical experiment
dependencies and native binaries remain frozen. SVG/PDF metadata is stable.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics

import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt
from matplotlib.lines import Line2D

ROOT = Path(__file__).resolve().parents[1]
COLORS = {"baseline_t1153_q40": "#4477AA", "same_field_narrow_lossless": "#CCBB44", "selected_field_q32": "#228833"}
LABELS = {"baseline_t1153_q40": "Original field, Q40", "same_field_narrow_lossless": "Original field, Q35/36", "selected_field_q32": "Selected field, Q32"}
VARIANTS = {"vector_gmp_byte": ("o", "GMP vector + byte body"), "vector_native_bit": ("s", "Native vector + bit body"),
            "polynomial_native_bit": ("^", "Native polynomial + bit body")}


def save(figure, directory, name):
    svg_path = directory / (name + ".svg")
    figure.savefig(svg_path, bbox_inches="tight", metadata={"Date": None})
    # Matplotlib emits trailing spaces inside path data; retain the separators
    # as newlines so generated vector artifacts also pass Git whitespace checks.
    svg_path.write_text("\n".join(line.rstrip() for line in svg_path.read_text().splitlines()) + "\n")
    figure.savefig(directory / (name + ".pdf"), bbox_inches="tight", metadata={"CreationDate": None, "ModDate": None})
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=ROOT / "benchmarks/results")
    parser.add_argument("--figure-dir", type=Path, default=ROOT / "docs/research/figures")
    args = parser.parse_args()
    args.figure_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.size": 10, "svg.hashsalt": "cuhepy-verification-frontier-20260930", "pdf.fonttype": 42})
    figure, axes = plt.subplots(1, 2, figsize=(10, 4.1), sharey=True)
    source_files = []
    for ax, dataset in zip(axes, ("mushroom", "semeion"), strict=True):
        observations = {}
        for seed in (3001, 3002):
            path = args.results_dir / f"verification_frontier_{dataset}_{seed}_20260930.json"
            source_files.append(path)
            report = json.loads(path.read_text())
            for case in report["result"]["cases"]:
                for variant in VARIANTS:
                    pair = observations.setdefault((case["layout"], variant), [])
                    pair.extend(sample["variants"][variant] for sample in case["samples"])
        for (profile, variant), samples in observations.items():
            x = (samples[0]["query_body_bytes"] + samples[0]["response_body_bytes"]) / 1024
            values = [sample["local_online_s_stage_sum"] * 1000 for sample in samples]
            y = statistics.median(values)
            ax.errorbar(x, y, yerr=[[y - min(values)], [max(values) - y]], marker=VARIANTS[variant][0], color=COLORS[profile],
                        linestyle="none", capsize=3, markersize=7, alpha=.9)
        ax.set_title("Mushroom: 7,996 × 126" if dataset == "mushroom" else "Semeion: 1,465 × 256")
        ax.set_xlabel("Query + response coefficient bodies (KiB)")
        ax.grid(alpha=.2)
    axes[0].set_ylabel("Paired local stage sum (ms)")
    handles = [Line2D([0], [0], color=color, lw=2, label=LABELS[profile]) for profile, color in COLORS.items()]
    handles.extend(Line2D([0], [0], color="black", marker=marker, linestyle="none", label=label) for marker, label in VARIANTS.values())
    figure.legend(handles=handles, loc="lower center", ncol=3, bbox_to_anchor=(.5, -.15), frameon=False)
    figure.suptitle("Retained CPU searches: median and observed min–max, 16 queries per point")
    figure.tight_layout()
    save(figure, args.figure_dir, "verification-frontier-local-20260930")

    path = args.results_dir / "verification_frontier_stages_20260930.csv"
    source_files.append(path)
    rows = list(csv.DictReader(path.open()))
    figure, axes = plt.subplots(1, 2, figsize=(10, 4.1), sharey=True)
    curves = (("baseline_t1153_q40", "vector_native_bit"), ("same_field_narrow_lossless", "vector_native_bit"),
              ("selected_field_q32", "vector_native_bit"), ("selected_field_q32", "polynomial_native_bit"))
    links = [10 ** (j / 20) for j in range(61)]
    for ax, dataset in zip(axes, ("mushroom", "semeion"), strict=True):
        for profile, variant in curves:
            row = next(r for r in rows if (r["dataset"], r["seed"], r["profile"], r["variant"]) == (dataset, "3001", profile, variant))
            local = float(row["median_local_s_stage_sum"])
            offline = (float(row["setup_s_stage_sum_model"]) + float(row["pool_s_stage_sum"])) / 9
            bytes_per_query = int(row["query_bytes"]) + int(row["response_bytes"])
            offline_bytes = int(row["seeded_index_packet_bytes"]) + 9 * int(row["seeded_answer_packet_bytes"])
            values = [1000 * (local + .04 + offline + 8 * (bytes_per_query + offline_bytes / 9) / (link * 1e6)) for link in links]
            label = LABELS[profile] + (", polynomial" if variant.startswith("polynomial") else ", vector")
            ax.plot(links, values, color=COLORS[profile], linestyle="--" if variant.startswith("polynomial") else "-", label=label)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("Equal upload / download rate (Mbps, modeled)")
        ax.set_title("Mushroom, split 3001" if dataset == "mushroom" else "Semeion, split 3001")
        ax.grid(alpha=.2, which="both")
    axes[0].set_ylabel("Amortized serial time per query (ms, modeled)")
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(handles, labels, loc="lower center", ncol=2, bbox_to_anchor=(.5, -.15), frameon=False)
    figure.suptitle("Nine-token body/stage model: full setup paid, 40 ms RTT; no network measurement")
    figure.tight_layout()
    save(figure, args.figure_dir, "verification-frontier-amortized-20260930")
    manifest = {"matplotlib": matplotlib.__version__,
                "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(__file__), *source_files)},
                "figure_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in args.figure_dir.glob("verification-frontier-*-20260930.*")},
                "scope": "Local stage-sum observations and serial body/stage models; no new measurement or confidence interval. "
                         "Pooled 16 retained queries per point, two declared splits; hardware/security/contract differences are not erased."}
    (args.results_dir / "verification_frontier_figures_20260930.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"figures": len(manifest["figure_sha256"]), "matplotlib": matplotlib.__version__}))


if __name__ == "__main__":
    main()
