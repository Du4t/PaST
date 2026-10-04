#!/usr/bin/env python3
"""
FTFuzz STSR (State Transition Success Rate) Tracker

Scans fuzzing output directory for .ftstate.json sidecar files and computes
per-transition State Transition Success Rate.

STSR_i = N(PreHit_i AND PostHit_i) / N(PreHit_i)
BarrierPassRate_i = N(PreHit_i AND PostHit_i) / N(PreHit_i AND BarrierHit_i)

Seed classification (per-transition):
  Fail-Pre:                  !pre_hit
  Reach-Pre:                 pre_hit && !barrier_hit && !post_hit
  Near-Post:                 pre_hit && barrier_hit && !post_hit
  Reach-Post:                pre_hit && post_hit
  Invalid-Post-Without-Pre:  !pre_hit && post_hit

Usage:
  python3 monitor/stsr_tracker.py /path/to/ftfuzz_out/default/queue
  python3 monitor/stsr_tracker.py /path/to/ftfuzz_out/default/queue --state-map state_map.csv
  python3 monitor/stsr_tracker.py /path/to/ftfuzz_out/default/queue --json --output stsr_report.json
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict

# Add project root to path for state_classes
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from monitor.state_classes import classify_transition, normalize_state_class, CANONICAL_CLASSES

CLASS_NAMES = CANONICAL_CLASSES


def scan_ftstate_files(queue_dir):
    """Scan queue directory for .ftstate.json sidecar files."""
    seeds = []
    for fname in os.listdir(queue_dir):
        if fname.endswith('.ftstate.json'):
            fpath = os.path.join(queue_dir, fname)
            data = load_ftstate(fpath)
            if data:
                data['_sidecar_path'] = fpath
                seeds.append(data)
    return seeds


def load_ftstate(path):
    """Load a .ftstate.json sidecar file."""
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None


def compute_stsr(seeds, state_map_path=None):
    """Compute per-transition STSR metrics from .ftstate.json sidecars."""
    # Collect per-transition data
    transition_data = defaultdict(lambda: {
        'pre_reach_count': 0,
        'barrier_reach_count': 0,
        'post_reach_count': 0,
        'blocked_count': 0,
        'invalid_post_without_pre': 0,
        'class_distribution': defaultdict(int),
        'total_seeds': 0,
    })

    total_seeds = len(seeds)

    for seed in seeds:
        transitions = seed.get('transitions', {})
        for tid, tdata in transitions.items():
            pre_hit = tdata.get('pre_hit', False)
            barrier_hit = tdata.get('barrier_hit', False)
            post_hit = tdata.get('post_hit', False)

            cls = classify_transition(pre_hit, barrier_hit, post_hit)
            td = transition_data[tid]
            td['total_seeds'] += 1
            td['class_distribution'][cls] += 1

            if pre_hit:
                td['pre_reach_count'] += 1
            if pre_hit and barrier_hit:
                td['barrier_reach_count'] += 1
            if pre_hit and post_hit:
                td['post_reach_count'] += 1
            if pre_hit and barrier_hit and not post_hit:
                td['blocked_count'] += 1
            if not pre_hit and post_hit:
                td['invalid_post_without_pre'] += 1

    # Compute STSR per transition
    transition_stats = {}
    for tid, td in sorted(transition_data.items()):
        pre = td['pre_reach_count']
        post = td['post_reach_count']
        barrier = td['barrier_reach_count']

        stsr = post / pre if pre > 0 else 0.0
        barrier_pass_rate = post / barrier if barrier > 0 else 0.0

        transition_stats[tid] = {
            'pre_reach_count': pre,
            'barrier_reach_count': barrier,
            'post_reach_count': post,
            'blocked_count': td['blocked_count'],
            'stsr': round(stsr, 6),
            'barrier_pass_rate': round(barrier_pass_rate, 6),
            'invalid_post_without_pre': td['invalid_post_without_pre'],
            'state_distribution': dict(td['class_distribution']),
        }

    # Aggregate distance stats
    distances = [s.get('min_distance', 0) for s in seeds
                 if s.get('min_distance', 0) > 0 and s.get('min_distance', 0) < 0xFFFFFFFF]
    dist_stats = {}
    if distances:
        dist_stats = {
            'min': min(distances),
            'max': max(distances),
            'avg': round(sum(distances) / len(distances), 1),
            'target_hit_count': sum(1 for s in seeds if s.get('reached_target', False)),
        }

    # Load transition names from state_map if available
    transition_names = {}
    if state_map_path and os.path.exists(state_map_path):
        transition_names = load_transition_names(state_map_path)

    return {
        'total_seeds': total_seeds,
        'transitions': transition_stats,
        'distance_stats': dist_stats,
        'transition_names': transition_names,
    }


def load_transition_names(path):
    """Load transition_id -> name mapping from state_map.csv."""
    names = {}
    try:
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                tid = row.get('transition_id', '')
                if tid and tid not in names:
                    names[tid] = tid
    except (IOError, KeyError):
        pass
    return names


def print_report(metrics):
    """Print STSR report."""
    print("=" * 70)
    print("FTFuzz STSR Report (Per-Transition)")
    print("=" * 70)
    print(f"Total seeds: {metrics['total_seeds']}")
    print()

    for tid, stats in sorted(metrics['transitions'].items()):
        name = metrics.get('transition_names', {}).get(tid, tid)
        print(f"  Transition {tid} ({name}):")
        print(f"    PreState reached:   {stats['pre_reach_count']}")
        print(f"    Barrier reached:    {stats['barrier_reach_count']}")
        print(f"    PostState reached:  {stats['post_reach_count']}")
        print(f"    Blocked at barrier: {stats['blocked_count']}")
        print(f"    STSR:               {stats['stsr']:.4f}")
        print(f"    Barrier pass rate:  {stats['barrier_pass_rate']:.4f}")
        if stats['invalid_post_without_pre'] > 0:
            print(f"    Invalid post w/o pre: {stats['invalid_post_without_pre']}")
        print(f"    Distribution: {stats['state_distribution']}")
        print()

    ds = metrics.get('distance_stats', {})
    if ds:
        print("Distance Statistics:")
        print(f"  Min: {ds['min']}, Max: {ds['max']}, Avg: {ds['avg']}")
        print(f"  Target hits: {ds.get('target_hit_count', 0)}")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="FTFuzz STSR Tracker")
    parser.add_argument("queue_dir", help="Path to fuzzing queue directory")
    parser.add_argument("--state-map", default=None,
                        help="Path to state_map.csv for transition names")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON instead of text")
    parser.add_argument("--output", default=None,
                        help="Write JSON report to this file")
    args = parser.parse_args()

    if not os.path.isdir(args.queue_dir):
        print(f"[ERROR] Queue directory not found: {args.queue_dir}", file=sys.stderr)
        sys.exit(1)

    seeds = scan_ftstate_files(args.queue_dir)
    if not seeds:
        # Fallback to .state sidecars if no .ftstate.json found
        from stsr_tracker_legacy import scan_sidecar_files, compute_stsr_legacy
        seeds_legacy = scan_sidecar_files(args.queue_dir)
        if not seeds_legacy:
            print("[WARN] No .ftstate.json or .state sidecar files found", file=sys.stderr)
            sys.exit(0)
        print("[INFO] No .ftstate.json found, falling back to .state sidecars", file=sys.stderr)
        metrics = compute_stsr_legacy(seeds_legacy, args.state_map)
    else:
        metrics = compute_stsr(seeds, args.state_map)

    if args.json or args.output:
        json_str = json.dumps(metrics, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_str)
            print(f"Report written to {args.output}")
        else:
            print(json_str)
    else:
        print_report(metrics)


if __name__ == "__main__":
    main()
