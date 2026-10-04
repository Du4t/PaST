#!/usr/bin/env python3
"""
FTFuzz Duplicate BB Key Checker

Detects duplicate file:line:function keys in bb_map.csv that could
cause ambiguous source-location matching in Pass 2 of TargetDistancePass.

When multiple basic blocks share the same file:line:function key,
Pass 2's LocationToBBId map will only retain one of them, potentially
missing the correct BB ID for distance instrumentation.

Usage:
  python3 -m monitor.duplicate_bb_key_checker /tmp/ftfuzz_dgf/libxml2/bb_map.csv
  python3 -m monitor.duplicate_bb_key_checker --bb-map /tmp/ftfuzz_dgf/bb_map.csv --report /tmp/report.txt
"""

import argparse
import csv
import os
import sys
from collections import defaultdict


def check_duplicate_keys(bb_map_path, report_path=None):
    """Check for duplicate file:line:function keys in bb_map.csv.

    Returns:
        dict with keys: total_bbs, unique_keys, duplicate_keys,
                        duplicate_bb_count, top_duplicates, duplicates
    """
    if not os.path.exists(bb_map_path):
        print(f"[ERROR] bb_map.csv not found: {bb_map_path}", file=sys.stderr)
        return None

    key_to_bbs = defaultdict(list)
    total_bbs = 0
    no_source = 0

    with open(bb_map_path, 'r') as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if len(row) < 4:
                continue
            try:
                bb_id = int(row[0])
                file_ = row[1].strip()
                line = int(row[2])
                func = row[3].strip()
            except (ValueError, IndexError):
                continue

            total_bbs += 1

            if not file_ or line == 0:
                no_source += 1
                continue

            key = f"{file_}:{line}:{func}"
            key_to_bbs[key].append(bb_id)

    unique_keys = len(key_to_bbs)
    duplicates = {k: v for k, v in key_to_bbs.items() if len(v) > 1}
    duplicate_keys = len(duplicates)
    duplicate_bb_count = sum(len(v) for v in duplicates.values())

    # Sort by number of BBs per key (descending)
    top_duplicates = sorted(duplicates.items(), key=lambda x: -len(x[1]))[:20]

    result = {
        'total_bbs': total_bbs,
        'no_source': no_source,
        'unique_keys': unique_keys,
        'duplicate_keys': duplicate_keys,
        'duplicate_bb_count': duplicate_bb_count,
        'duplicate_percentage': (duplicate_bb_count / total_bbs * 100) if total_bbs > 0 else 0,
        'top_duplicates': top_duplicates,
        'duplicates': duplicates,
    }

    # Print report
    print(f"BB Map Duplicate Key Report: {bb_map_path}")
    print(f"{'='*60}")
    print(f"Total BBs:              {total_bbs}")
    print(f"BBs without source:     {no_source}")
    print(f"Unique location keys:   {unique_keys}")
    print(f"Duplicate keys:         {duplicate_keys}")
    print(f"BBs in duplicate keys:  {duplicate_bb_count} ({result['duplicate_percentage']:.1f}%)")

    if top_duplicates:
        print(f"\nTop {len(top_duplicates)} duplicate locations:")
        for key, bb_ids in top_duplicates:
            # Extract short name for display
            parts = key.split(':')
            if len(parts) >= 3:
                short_file = os.path.basename(parts[0])
                display = f"{short_file}:{':'.join(parts[1:])}"
            else:
                display = key
            print(f"  {display} -> {len(bb_ids)} BBs: {bb_ids[:8]}{'...' if len(bb_ids) > 8 else ''}")

    if duplicate_keys > 0:
        print(f"\n[WARN] {duplicate_keys} duplicate file:line:function keys found.")
        print("Pass 2 source-location matching is potentially unsafe for these keys.")
        print("Recommendation: use occurrence index or column number in Pass 2 matching.")
    else:
        print("\n[OK] No duplicate keys found. Pass 2 matching is safe.")

    # Write report file if requested
    if report_path:
        with open(report_path, 'w') as f:
            f.write(f"BB Map Duplicate Key Report\n")
            f.write(f"{'='*60}\n")
            f.write(f"Source: {bb_map_path}\n")
            f.write(f"Total BBs: {total_bbs}\n")
            f.write(f"Unique keys: {unique_keys}\n")
            f.write(f"Duplicate keys: {duplicate_keys}\n")
            f.write(f"Duplicate BB count: {duplicate_bb_count}\n\n")

            if top_duplicates:
                f.write("Top duplicate locations:\n")
                for key, bb_ids in top_duplicates:
                    f.write(f"  {key} -> {bb_ids}\n")
                f.write("\nAll duplicates:\n")
                for key, bb_ids in sorted(duplicates.items()):
                    f.write(f"  {key} -> {bb_ids}\n")

        print(f"\nReport written to: {report_path}")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="FTFuzz Duplicate BB Key Checker",
    )
    parser.add_argument("bb_map", nargs="?", default=None,
                        help="Path to bb_map.csv")
    parser.add_argument("--bb-map", dest="bb_map_flag", default=None,
                        help="Path to bb_map.csv (alternative)")
    parser.add_argument("--report", default=None,
                        help="Path to write detailed report")
    args = parser.parse_args()

    bb_map_path = args.bb_map or args.bb_map_flag
    if not bb_map_path:
        bb_map_path = os.environ.get("FTFUZZ_BB_MAP_FILE",
                                     "/tmp/ftfuzz_dgf/libxml2/bb_map.csv")

    result = check_duplicate_keys(bb_map_path, args.report)
    if result is None:
        sys.exit(1)

    # Exit with error if duplicates found (useful for CI)
    if result['duplicate_keys'] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
