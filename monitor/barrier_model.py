#!/usr/bin/env python3
"""
FTFuzz Barrier Model

Analyzes barrier conditions that block state transitions.
Reads .ftstate.json sidecar files to identify which transitions are blocked
and generates mutation strategy recommendations.

Usage:
  python3 monitor/barrier_model.py /path/to/ftfuzz_out/default/queue
  python3 monitor/barrier_model.py /path/to/ftfuzz_out/default/queue --state-map state_map.csv
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from monitor.state_classes import classify_transition, normalize_state_class


def load_ftstate_files(queue_dir):
    """Load all .ftstate.json sidecar files from queue."""
    seeds = []
    for fname in os.listdir(queue_dir):
        if fname.endswith('.ftstate.json'):
            fpath = os.path.join(queue_dir, fname)
            try:
                with open(fpath, 'r') as f:
                    data = json.load(f)
                    data['_sidecar_path'] = fpath
                    seeds.append(data)
            except (IOError, json.JSONDecodeError):
                pass
    return seeds


def load_state_map(path):
    """Load barrier definitions from state_map.csv."""
    barriers = []
    try:
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['role'] == 'barrier':
                    barriers.append({
                        'state_id': int(row['state_id']),
                        'transition_id': row['transition_id'],
                        'file': row['file'],
                        'line': int(row['line']),
                        'function': row['function'],
                        'bb_id': int(row['bb_id']),
                    })
    except (IOError, KeyError, ValueError):
        pass
    return barriers


def analyze_barriers(queue_dir, state_map_path=None):
    """Analyze barrier conditions from .ftstate.json sidecar metadata."""
    seeds = load_ftstate_files(queue_dir)

    # Per-transition barrier analysis
    transition_stats = defaultdict(lambda: {
        'blocked_at_barrier': 0,  # Near-Post
        'passed_barrier': 0,      # Reach-Post
        'reach_pre_only': 0,      # Reach-Pre
        'fail_pre': 0,            # Fail-Pre
        'invalid': 0,             # Invalid-Post-Without-Pre
    })

    for seed in seeds:
        transitions = seed.get('transitions', {})
        for tid, tdata in transitions.items():
            pre = tdata.get('pre_hit', False)
            bar = tdata.get('barrier_hit', False)
            post = tdata.get('post_hit', False)
            ts = transition_stats[tid]

            if pre and post:
                ts['passed_barrier'] += 1
            elif pre and bar and not post:
                ts['blocked_at_barrier'] += 1
            elif pre and not bar and not post:
                ts['reach_pre_only'] += 1
            elif not pre and post:
                ts['invalid'] += 1
            else:
                ts['fail_pre'] += 1

    # Load barrier definitions
    barriers = []
    if state_map_path and os.path.exists(state_map_path):
        barriers = load_state_map(state_map_path)

    # Compute overall barrier pass rate
    total_blocked = sum(ts['blocked_at_barrier'] for ts in transition_stats.values())
    total_passed = sum(ts['passed_barrier'] for ts in transition_stats.values())
    barrier_pass_rate = total_passed / (total_blocked + total_passed) if (total_blocked + total_passed) > 0 else 0.0

    # Find most blocked transitions
    transition_ranking = []
    for tid, ts in sorted(transition_stats.items()):
        reached_pre = ts['reach_pre_only'] + ts['blocked_at_barrier'] + ts['passed_barrier']
        transition_ranking.append({
            'transition_id': tid,
            'reached_pre': reached_pre,
            'blocked_at_barrier': ts['blocked_at_barrier'],
            'passed_barrier': ts['passed_barrier'],
            'pass_rate': ts['passed_barrier'] / (ts['blocked_at_barrier'] + ts['passed_barrier'])
                if (ts['blocked_at_barrier'] + ts['passed_barrier']) > 0 else 0.0,
        })
    transition_ranking.sort(key=lambda x: x['blocked_at_barrier'], reverse=True)

    return {
        'total_seeds': len(seeds),
        'total_blocked_at_barrier': total_blocked,
        'total_passed_barrier': total_passed,
        'barrier_pass_rate': round(barrier_pass_rate, 6),
        'transition_stats': dict(transition_stats),
        'transition_ranking': transition_ranking[:10],
        'barriers': barriers,
        'recommendation': generate_recommendation(total_blocked, total_passed, barriers, transition_ranking),
    }


def generate_recommendation(blocked, passed, barriers, ranking):
    """Generate mutation strategy recommendations."""
    recs = []

    if blocked > passed * 2:
        recs.append("High barrier block rate. Consider:")
        recs.append("  - Increase energy for Near-Post seeds to explore barrier conditions")
        recs.append("  - Enable CmpLog-style feedback for barrier comparisons")

    for r in ranking[:3]:
        if r['blocked_at_barrier'] > 0:
            recs.append(
                f"  Transition {r['transition_id']}: "
                f"{r['blocked_at_barrier']} blocked, {r['passed_barrier']} passed "
                f"(rate={r['pass_rate']:.3f})"
            )

    for b in barriers:
        recs.append(
            f"  Barrier at {b['file']}:{b['line']} in {b['function']} "
            f"(BB {b['bb_id']}, transition {b['transition_id']})"
        )

    if not recs:
        recs.append("No significant barrier blocking detected.")

    return recs


def print_report(analysis):
    """Print barrier analysis report."""
    print("=" * 70)
    print("FTFuzz Barrier Model Report")
    print("=" * 70)
    print(f"Total seeds:           {analysis['total_seeds']}")
    print(f"Blocked at barrier:    {analysis['total_blocked_at_barrier']}")
    print(f"Passed barrier:        {analysis['total_passed_barrier']}")
    print(f"Barrier pass rate:     {analysis['barrier_pass_rate']:.4f}")
    print()

    if analysis['transition_ranking']:
        print("Most Blocked Transitions:")
        for r in analysis['transition_ranking']:
            print(f"  {r['transition_id']}: blocked={r['blocked_at_barrier']}, "
                  f"passed={r['passed_barrier']}, rate={r['pass_rate']:.3f}")
        print()

    if analysis['barriers']:
        print("Defined Barriers:")
        for b in analysis['barriers']:
            print(f"  {b['transition_id']}: {b['file']}:{b['line']} "
                  f"in {b['function']} (BB {b['bb_id']})")
        print()

    print("Recommendations:")
    for rec in analysis['recommendation']:
        print(f"  {rec}")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="FTFuzz Barrier Model")
    parser.add_argument("queue_dir", help="Path to fuzzing queue directory")
    parser.add_argument("--state-map", default=None,
                        help="Path to state_map.csv for barrier definitions")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON instead of text")
    args = parser.parse_args()

    if not os.path.isdir(args.queue_dir):
        print(f"[ERROR] Queue directory not found: {args.queue_dir}", file=sys.stderr)
        sys.exit(1)

    analysis = analyze_barriers(args.queue_dir, args.state_map)

    if args.json:
        print(json.dumps(analysis, indent=2, default=str))
    else:
        print_report(analysis)


if __name__ == "__main__":
    main()
