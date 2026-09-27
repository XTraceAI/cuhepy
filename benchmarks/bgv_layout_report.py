#!/usr/bin/env python3
"""E16 analytical layout/precision/setup projections and paced-link validation.

Only recorded configurations and their local measurements are ranked. Setup
wire cost is a coefficient-only floor, not full registration/TLS/attestation.
The report is not a production router or a cryptographic parameter approval.
"""

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from bfv_client_matrix import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab.radix_planner import rank, break_even_queries, transport_validation, LAYOUTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('measurement', type=Path)
    parser.add_argument('--index-mode', choices=('owner', 'public'), default='owner')
    parser.add_argument('--json-out', type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(args.measurement.read_text())
    links = {'local': {}, '1Mbps': dict(upload_mbps=1, download_mbps=1, rtt_ms=40),
             '10Mbps': dict(upload_mbps=10, download_mbps=10, rtt_ms=40),
             '100Mbps': dict(upload_mbps=100, download_mbps=100, rtt_ms=40),
             '1Gbps': dict(upload_mbps=1000, download_mbps=1000, rtt_ms=40),
             '10up-100down': dict(upload_mbps=10, download_mbps=100, rtt_ms=40),
             '100up-10down': dict(upload_mbps=100, download_mbps=10, rtt_ms=40)}
    scenarios, switching = {}, {}
    for name, link in links.items():
        for state, resident in (('fresh', ()), ('g1-resident', ('g1',)), ('all-resident', tuple(LAYOUTS))):
            for horizon in (1, 100, 10000):
                rows = rank(source, index_mode=args.index_mode, **link, resident_layouts=resident,
                            allow_radix=True, epoch_queries=horizon)
                scenarios[f'{name}/{state}/{horizon}'] = dict(link=link, resident_layouts=resident,
                    epoch_queries=horizon, estimates=[asdict(e) for e in rows])
        rows = rank(source, index_mode=args.index_mode, **link, resident_layouts=('g1',), allow_radix=True)
        incumbent = min((e for e in rows if e.layout == 'g1'), key=lambda e: (e.steady_ms, e.variant))
        switching[name] = dict(incumbent=asdict(incumbent), alternatives=[dict(
            variant=e.variant, steady_ms=e.steady_ms, setup_ms_floor=e.setup_ms_floor,
            break_even_queries_floor=break_even_queries(e, incumbent)) for e in rows if e.layout != 'g1'])
    files = [Path(__file__).resolve(), REPO_ROOT/'experiments/bfv_search_lab/radix_planner.py',
             REPO_ROOT/'experiments/bfv_search_lab/radix_bgv.py']
    result = dict(kind='bgv_layout_analytical_projection', scope=__doc__, command=sys.argv,
        git_head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        measurement=str(args.measurement), measurement_sha256=hashlib.sha256(args.measurement.read_bytes()).hexdigest(),
        measurement_git_head=source['git_head'], num_vectors=source['num_vectors'], dimension=source['dimension'],
        index_mode=args.index_mode, scenarios=scenarios, switching_from_resident_g1=switching,
        separate_paced_link_validation=transport_validation(source, args.index_mode),
        source_sha256={str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+'\n')
    print(args.json_out)


if __name__ == '__main__':
    main()
