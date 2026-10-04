#!/usr/bin/env python3
"""
FTFuzz Window Scoring — byte-level window stability and difference scoring.

Used by byte_window_infer.py to score sliding windows across seed buckets.
"""

import math
from collections import Counter


def normalized_entropy(window_bytes_list):
    """Compute 1 - normalized byte entropy. High = stable."""
    if not window_bytes_list:
        return 0.0
    counter = Counter(window_bytes_list)
    total = len(window_bytes_list)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p) if p > 0 else 0
    max_entropy = math.log2(min(total, 256))
    if max_entropy == 0:
        return 1.0
    return 1.0 - entropy / max_entropy


def compute_preserve_score(stability_score, coverage_support, max_support, semantic_boost=0.0):
    coverage_norm = coverage_support / max(max_support, 1)
    return 0.6 * stability_score + 0.2 * coverage_norm + 0.2 * semantic_boost


def compute_focus_score(difference_score, state_correlation_score, semantic_boost=0.0):
    return 0.5 * difference_score + 0.3 * state_correlation_score + 0.2 * semantic_boost


def byte_difference_score(bytes_a, bytes_b):
    """Normalized byte-level difference between two byte strings."""
    if not bytes_a or not bytes_b:
        return 0.0
    max_len = max(len(bytes_a), len(bytes_b))
    if max_len == 0:
        return 0.0
    diffs = 0
    min_len = min(len(bytes_a), len(bytes_b))
    for i in range(min_len):
        if bytes_a[i] != bytes_b[i]:
            diffs += 1
    diffs += abs(len(bytes_a) - len(bytes_b))
    return diffs / max_len


def extract_window_bytes(seed_bytes_list, start, end):
    """Extract window byte slices from a list of seed bytes."""
    windows = []
    for sb in seed_bytes_list:
        if start < len(sb):
            w_end = min(end, len(sb))
            windows.append(sb[start:w_end])
    return windows


def extract_windows_from_seeds(seed_data_list, window_size, stride, max_seed_size):
    """
    Extracts all sliding windows from seed byte data.

    seed_data_list: list of dicts with 'seed_path', 'size', optional 'bytes' (lazy loaded)
    Returns: list of (start, end, seed_idx, window_bytes)
    """
    windows = []
    for idx, sd in enumerate(seed_data_list):
        try:
            with open(sd['seed_path'], 'rb') as f:
                data = f.read(max_seed_size)
        except (IOError, OSError):
            continue
        size = len(data)
        if size < window_size:
            windows.append((0, size, idx, data))
        else:
            for start in range(0, size - window_size + 1, stride):
                end = start + window_size
                windows.append((start, end, idx, data[start:end]))
            # Also cover the tail
            if (size - window_size) % stride != 0:
                start = ((size - window_size) // stride) * stride
                if start + window_size < size:
                    start = size - window_size
                windows.append((start, size, idx, data[start:size]))
    return windows


def score_preserve_windows(progress_seeds, window_size=16, stride=8,
                           max_seed_size=4096, semantic_hint_bytes=None):
    """
    Score sliding windows for preservation.
    progress_seeds: list of seed dicts from Reach-Pre/Blocked-at-Barrier/etc.
    Returns list of scored windows.
    """
    if not progress_seeds:
        return []

    windows = extract_windows_from_seeds(progress_seeds, window_size, stride, max_seed_size)
    if not windows:
        return []

    # Group by (start, end)
    window_groups = {}
    for start, end, seed_idx, wbytes in windows:
        key = (start, end)
        window_groups.setdefault(key, []).append((seed_idx, wbytes))

    scored = []
    max_support = len(progress_seeds)
    for (start, end), entries in window_groups.items():
        byte_slices = [e[1] for e in entries]
        # For each position within window, compute stability
        pos_stabilities = []
        for pos in range(min(len(b) for b in byte_slices)):
            pos_bytes = [b[pos:pos+1] for b in byte_slices if pos < len(b)]
            pos_stabilities.append(normalized_entropy(pos_bytes))
        stability = sum(pos_stabilities) / max(len(pos_stabilities), 1)

        coverage = len(set(e[0] for e in entries))
        sem_boost = 0.0
        if semantic_hint_bytes:
            window_region = byte_slices[0] if byte_slices else b''
            for hint_b in semantic_hint_bytes:
                if hint_b in window_region:
                    sem_boost = 0.3
                    break

        score = compute_preserve_score(stability, coverage, max_support, sem_boost)
        scored.append({
            'start': start, 'end': end, 'length': end - start,
            'score': round(score, 4),
            'stability': round(stability, 4),
            'coverage': coverage,
            'max_support': max_support,
            'semantic_boost': round(sem_boost, 2),
        })

    scored.sort(key=lambda x: x['score'], reverse=True)
    return scored


def score_focus_windows(bucket_a_seeds, bucket_b_seeds, window_size=16, stride=8,
                        max_seed_size=4096, semantic_hint_bytes=None):
    """
    Score sliding windows for barrier focus.
    Compares windows between two buckets (e.g., Reach-Pre vs Blocked-at-Barrier).
    """
    if not bucket_a_seeds or not bucket_b_seeds:
        return []

    wins_a = extract_windows_from_seeds(bucket_a_seeds, window_size, stride, max_seed_size)
    wins_b = extract_windows_from_seeds(bucket_b_seeds, window_size, stride, max_seed_size)

    # Group windows from both buckets
    all_positions = set()
    for start, end, _, _ in wins_a + wins_b:
        all_positions.add((start, end))

    scored = []
    total_seeds = max(len(bucket_a_seeds), len(bucket_b_seeds))
    for (start, end) in all_positions:
        bytes_a = [w[3] for w in wins_a if w[0] == start and w[1] == end]
        bytes_b = [w[3] for w in wins_b if w[0] == start and w[1] == end]

        if not bytes_a:
            bytes_a = [b'\x00' * (end - start)]
        if not bytes_b:
            bytes_b = [b'\x00' * (end - start)]

        # Compute average difference
        diffs = []
        for ba in bytes_a[:20]:  # limit for performance
            for bb in bytes_b[:20]:
                diffs.append(byte_difference_score(ba, bb))
        avg_diff = sum(diffs) / max(len(diffs), 1)

        # State correlation: does bucket B (more progressed) differ from bucket A?
        corr_score = avg_diff  # higher difference → more likely barrier-related

        sem_boost = 0.0
        if semantic_hint_bytes and (bytes_a or bytes_b):
            sample = (bytes_a[0] if bytes_a else bytes_b[0])
            for hint_b in (semantic_hint_bytes or []):
                if hint_b in sample:
                    sem_boost = 0.3
                    break

        coverage = len(set(w[2] for w in wins_a if w[0] == start and w[1] == end) |
                       set(w[2] for w in wins_b if w[0] == start and w[1] == end))

        score = compute_focus_score(avg_diff, corr_score, sem_boost)
        scored.append({
            'start': start, 'end': end, 'length': end - start,
            'score': round(score, 4),
            'difference': round(avg_diff, 4),
            'correlation': round(corr_score, 4),
            'coverage': coverage,
            'semantic_boost': round(sem_boost, 2),
        })

    scored.sort(key=lambda x: x['score'], reverse=True)
    return scored


def merge_ranges(scored_windows, gap_threshold=8, max_ranges=32):
    """Merge adjacent/overlapping scored windows into ranges."""
    if not scored_windows:
        return []

    sorted_ws = sorted(scored_windows, key=lambda w: w['start'])
    merged = []
    current = dict(sorted_ws[0])
    current['_count'] = 1

    for w in sorted_ws[1:]:
        if current['end'] + gap_threshold >= w['start']:
            # Merge
            current['end'] = max(current['end'], w['end'])
            current['length'] = current['end'] - current['start']
            current['score'] = max(current['score'], w['score'])
            current['_count'] += 1
        else:
            merged.append(current)
            current = dict(w)
            current['_count'] = 1
            if len(merged) >= max_ranges:
                break
    merged.append(current)

    for m in merged:
        m.pop('_count', None)

    return sorted(merged, key=lambda x: x['score'], reverse=True)
