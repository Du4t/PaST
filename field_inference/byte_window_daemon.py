#!/usr/bin/env python3
"""
FTFuzz Byte-Window Grounding Daemon (Stage 2.1-fix)

Runs during fuzzing, periodically:
  1. Loads queue seeds + .ftstate.json sidecars
  2. Maps seeds -> policy_groups via state_map
  3. Infers preserve_ranges / focus_ranges from real seed buckets
  4. Grounds policy_store_v2 with ranges (atomically)
  5. Mutator hot-reloads the updated store

Usage:
  python3 field_inference/byte_window_daemon.py \\
      --policy-store policy_store_v2.json \\
      --queue-dir /path/to/queue \\
      --state-map state_map_auto.csv \\
      --out grounded_policy_store_v2.json \\
      --interval 60 --daemon
"""

import argparse, csv, json, os, re, sys, time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from field_inference.window_scoring import (
    score_preserve_windows, score_focus_windows, merge_ranges
)

CANONICAL_CLASSES = [
    'Fail-Pre', 'Reach-Pre', 'Blocked-at-Barrier',
    'Barrier-Reached', 'Progressed-Through-Barrier', 'Reach-Post',
    'Invalid-Post-Without-Pre',
]
ALIASES = {
    'near-post': 'Barrier-Reached', 'nearpost': 'Barrier-Reached',
    'blocked': 'Blocked-at-Barrier',
    'reach_pre': 'Reach-Pre', 'reach_post': 'Reach-Post',
    'fail_pre': 'Fail-Pre',
}


def atomic_write(path, data):
    tmp = path + '.tmp'
    raw_json = json.dumps(data, indent=2, default=str)
    if os.environ.get('FTFUZZ_INPUT_FORMAT', 'text') == 'binary':
        raw_json = re.sub(
            r'\\u00([0-9a-fA-F]{2})',
            lambda m: '\\x{:02x}'.format(int(m.group(1), 16)),
            raw_json
        )
    with open(tmp, 'w') as f:
        f.write(raw_json)
    os.replace(tmp, path)


def load_json(path):
    if not os.path.exists(path): return None
    with open(path) as f:
        text = f.read()
    # Handle \xHH hex escapes (binary format compat)
    text = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: '\\u00' + m.group(1).upper(), text)
    try: return json.loads(text)
    except json.JSONDecodeError:
        return json.JSONDecoder().raw_decode(text)[0]


def load_state_map(path):
    state_to_tid = {}
    if not path or not os.path.exists(path): return state_to_tid
    with open(path) as f:
        for row in csv.DictReader(f):
            sid = int(row['state_id'])
            if sid not in state_to_tid:
                state_to_tid[sid] = row['transition_id']
    return state_to_tid


def _decode_scaffold_bytes(scaffold_text):
    """Decode scaffold_template text to concrete bytes.

    For binary formats: the template may be hex-encoded (e.g. "7f454c46..." or
    "0xFF 0x4F ...") or may contain \\xHH escape sequences.
    For text formats: the template is raw text (XML, etc.) — use as-is.

    Returns bytes on success, empty bytes on failure.
    """
    if not scaffold_text:
        return b''

    # Strategy 1: Try to handle \xHH escape sequences (JSON-encoded hex bytes)
    # These may come from the policy store JSON with \\xHH sequences
    if '\\x' in scaffold_text:
        try:
            # Replace \xHH with actual bytes
            result = bytearray()
            i = 0
            while i < len(scaffold_text):
                if scaffold_text[i:i+2] == '\\x' and i + 3 < len(scaffold_text):
                    try:
                        result.append(int(scaffold_text[i+2:i+4], 16))
                        i += 4
                    except (ValueError, IndexError):
                        result.append(ord(scaffold_text[i]))
                        i += 1
                elif scaffold_text[i:i+2] == '\\u' and i + 5 < len(scaffold_text):
                    try:
                        result.append(int(scaffold_text[i+2:i+6], 16))
                        i += 6
                    except (ValueError, IndexError):
                        result.append(ord(scaffold_text[i]))
                        i += 1
                elif scaffold_text[i:i+2] == '\\n':
                    result.append(ord('\n'))
                    i += 2
                elif scaffold_text[i:i+2] == '\\t':
                    result.append(ord('\t'))
                    i += 2
                elif scaffold_text[i:i+2] == '\\\\':
                    result.append(ord('\\'))
                    i += 2
                else:
                    result.append(ord(scaffold_text[i]))
                    i += 1
            return bytes(result)
        except Exception:
            pass

    # Strategy 2: Check if this looks like hex-encoded binary (mostly hex chars
    # after stripping whitespace/0x prefixes)
    stripped = re.sub(r'[\s,;]+', '', scaffold_text)
    stripped = re.sub(r'0[xX]', '', stripped)
    if len(stripped) >= 2 and all(c in '0123456789ABCDEFabcdef' for c in stripped):
        try:
            if len(stripped) % 2 != 0:
                stripped = '0' + stripped
            return bytes.fromhex(stripped)
        except (ValueError, TypeError):
            pass

    # Strategy 3: Text format — use the template text as-is
    # Check if it looks like text (not purely hex bytes)
    is_text = False
    if scaffold_text.strip().startswith(('<?xml', '<!', '<', '{', '[', '(', '#', '//', '/*')):
        is_text = True
    # Also check: if more than 40% non-hex chars, treat as text
    non_hex = sum(1 for c in scaffold_text if c not in '0123456789ABCDEFabcdef \t\n\r,;0xX')
    if non_hex > len(scaffold_text) * 0.4:
        is_text = True

    if is_text:
        return scaffold_text.encode('utf-8')

    # Strategy 4: Last resort — encode as latin-1 (preserves all byte values)
    # This handles the case where scaffold_text already contains raw binary bytes
    # from a previous hex-decode step
    try:
        return scaffold_text.encode('latin-1')
    except Exception:
        return b''


def _normalize(sc):
    if not sc: return 'Fail-Pre'
    return ALIASES.get(sc.lower().replace('_', '-'), sc)


def build_buckets(queue_dir, state_to_tid, t2pg, max_per_bucket=50):
    """Build per-PG seed buckets from current queue state."""
    buckets = defaultdict(lambda: defaultdict(list))
    seed_files = [f for f in os.listdir(queue_dir)
                  if f.startswith('id:') and not f.endswith(('.ftstate.json', '.state'))]
    stats = {'seeds': len(seed_files), 'sidecars': 0, 'mapped': 0}

    for seed_name in seed_files:
        seed_path = os.path.join(queue_dir, seed_name)
        sidecar_path = seed_path + '.ftstate.json'
        if not os.path.exists(sidecar_path): continue
        stats['sidecars'] += 1

        try:
            with open(sidecar_path) as f: sc = json.load(f)
        except Exception:
            continue

        # Find best state per PG
        pg_best = {}
        for sid_str, info in sc.get('transitions', {}).items():
            tid = state_to_tid.get(int(sid_str), '')
            gid = t2pg.get(tid, '')
            if not gid: continue
            sc_name = _normalize(info.get('state_class', 'Fail-Pre'))
            rank = {'Fail-Pre': 0, 'Reach-Pre': 1, 'Barrier-Reached': 2,
                    'Blocked-at-Barrier': 3, 'Reach-Post': 4}.get(sc_name, 0)
            if gid not in pg_best or rank > pg_best[gid][1]:
                pg_best[gid] = (sc_name, rank)

        stats['mapped'] += 1
        for gid in t2pg.values():
            if gid not in pg_best:
                pg_best[gid] = ('Fail-Pre', 0)

        try:
            with open(seed_path, 'rb') as f:
                seed_bytes = f.read(4096)
        except IOError:
            seed_bytes = b''

        for gid, (sc, _) in pg_best.items():
            bucket = buckets[gid][sc]
            if len(bucket) < max_per_bucket:
                bucket.append({
                    'seed_path': seed_path, 'seed_name': seed_name,
                    'sidecar_path': sidecar_path, 'state_class': sc,
                    'size': len(seed_bytes),
                })

    return dict(buckets), stats


def infer_and_ground(policy_store_path, queue_dir, state_map_path, output_path,
                     window_size=32, stride=16, min_support=3):
    """Infer byte windows, filter symbols, compile edit IR, write grounded store."""
    ps = load_json(policy_store_path)
    if not ps or not ps.get('policy_groups'):
        print('[BW_DAEMON] No policy groups yet, skipping')
        return None

    # ---- Step 0: Filter internal symbols + compile semantic edit plan ----
    try:
        from policy.internal_symbol_filter import filter_policy_store
        ps, filter_report = filter_policy_store(ps)
        n_filtered = sum(len(r['filtered_internal_symbols']) for r in filter_report.values())
        n_ops = sum(len(r['semantic_edit_plan']['edit_ops']) for r in filter_report.values())
        if n_filtered > 0:
            print(f'[BW_DAEMON] Filtered {n_filtered} internal symbols, compiled {n_ops} edit ops')
    except Exception as e:
        print(f'[BW_DAEMON] Filter skipped: {e}')

    state_to_tid = load_state_map(state_map_path)
    t2pg = ps.get('transition_to_policy_group', {})
    buckets, stats = build_buckets(queue_dir, state_to_tid, t2pg)

    if stats['sidecars'] < 5:
        print(f'[BW_DAEMON] Only {stats["sidecars"]} sidecars, need >=5, skipping')
        return None

    print(f'[BW_DAEMON] {stats["seeds"]} seeds, {stats["sidecars"]} sidecars, {stats["mapped"]} mapped')

    # Increment version
    old_version = ps.get('store_version', 0)
    ps['store_version'] = old_version + 1

    synthetic = True
    for gid, g in ps.get('policy_groups', {}).items():
        bg = buckets.get(gid, {})
        tokens = g.get('mutation_actions', {}).get('dictionary_tokens', [])
        token_bytes = []
        for t in tokens:
            tok = t.get('token', '') if isinstance(t, dict) else str(t)
            token_bytes.append(tok.encode()[:16] if tok else b'')
        token_bytes = [t for t in token_bytes if t]

        # Preserve: stability across progressed seeds
        progress = bg.get('Reach-Pre', []) + bg.get('Barrier-Reached', []) + \
                   bg.get('Blocked-at-Barrier', [])
        preserve_ranges = []
        if len(progress) >= min_support:
            pc = score_preserve_windows(progress, window_size, stride, 4096, token_bytes)
            pc = [w for w in pc if w['score'] >= 0.50 and w['coverage'] >= min_support]
            preserve_ranges = merge_ranges(pc, stride, 8)

        # Focus: compare class pairs
        focus_ranges = []
        pairs = [
            (bg.get('Fail-Pre', []), bg.get('Reach-Pre', []), 'fail_vs_reach'),
            (bg.get('Reach-Pre', []), bg.get('Barrier-Reached', []), 'reach_vs_barrier'),
            (bg.get('Reach-Pre', []), bg.get('Blocked-at-Barrier', []), 'reach_vs_blocked'),
        ]
        for bucket_a, bucket_b, pair_name in pairs:
            if len(bucket_a) >= min_support and len(bucket_b) >= min_support:
                fc = score_focus_windows(bucket_a, bucket_b, window_size, stride, 4096, token_bytes)
                fc = [w for w in fc if w['score'] >= 0.40 and w['coverage'] >= min_support]
                for w in fc: w['pair'] = pair_name
                focus_ranges.extend(fc)

        focus_ranges = merge_ranges(focus_ranges, stride, 8)
        insert_ranges = []
        for fr in focus_ranges[:8]:
            insert_ranges.append({
                'start': fr['start'], 'end': fr['end'], 'length': fr['length'],
                'tokens': [t.get('token','') if isinstance(t,dict) else str(t) for t in tokens[:5]],
                'confidence': round(fr['score'] * 0.9, 4),
            })

        # Clean and inject
        ma = dict(g.get('mutation_actions', {}))
        ma['preserve_ranges'] = [{'start': r['start'], 'end': r['end'],
                                  'length': r['length'], 'role': 'pre_state_preserving',
                                  'confidence': r['score']} for r in preserve_ranges]
        ma['focus_ranges'] = [{'start': r['start'], 'end': r['end'],
                               'length': r['length'], 'role': 'barrier_related',
                               'confidence': r['score']} for r in focus_ranges]
        ma['preferred_insert_ranges'] = insert_ranges

        has = bool(ma['preserve_ranges'] or ma['focus_ranges'])
        if has:
            synthetic = False
            ma['operator_weights'] = {
                'dictionary_insert': 0.20, 'region_focus': 0.30,
                'fallback_havoc': 0.15, 'preserve_aware_havoc': 0.25,
                'numeric_boundary': 0.05, 'repair': 0.05,
            }
        else:
            # No byte patterns found in seed corpus — fallback to scaffold_template bytes.
            # Extract scaffold bytes from action_chain and use them as grounding basis
            # so the mutator can instantiate a valid seed directly.
            achain = g.get('action_chain', {})
            scaffold_text = achain.get('scaffold_template', '')
            if scaffold_text:
                # Convert scaffold text to byte ranges.
                # For text format: use as-is (text bytes).
                # For binary format: decode hex escapes in the scaffold text.
                scaffold_bytes = _decode_scaffold_bytes(scaffold_text)
                if scaffold_bytes:
                    scaffold_len = len(scaffold_bytes)
                    # Create a preserve_range covering the full scaffold
                    ma['preserve_ranges'] = [{
                        'start': 0, 'end': scaffold_len,
                        'length': scaffold_len,
                        'role': 'scaffold_fallback',
                        'confidence': 0.60,
                    }]
                    # Create focus_ranges on key structural bytes (first 32 bytes)
                    focus_end = min(32, scaffold_len)
                    ma['focus_ranges'] = [{
                        'start': 0, 'end': focus_end,
                        'length': focus_end,
                        'role': 'scaffold_structure',
                        'confidence': 0.55,
                        'pair': 'scaffold_fallback',
                    }]
                    # Mark as synthetic but provide operator weights that prioritize
                    # chain+scaffold execution over random havoc
                    ma['operator_weights'] = {
                        'dictionary_insert': 0.10, 'dsl_actions': 0.60,
                        'fallback_havoc': 0.05, 'region_focus': 0.10,
                        'preserve_aware_havoc': 0.10, 'numeric_boundary': 0.03,
                        'repair': 0.02,
                    }
                    print(f'[BW_DAEMON] {gid}: scaffold_fallback len={scaffold_len}, '
                          f'no seed patterns found, using scaffold bytes for grounding')
                else:
                    print(f'[BW_DAEMON] {gid}: scaffold_template exists but could not decode bytes')

        g['mutation_actions'] = ma

        n_pres = len(ma['preserve_ranges'])
        n_foc = len(ma['focus_ranges'])
        print(f'[BW_DAEMON] {gid}: preserve={n_pres} focus={n_foc} insert={len(insert_ranges)}')

    meta = dict(ps.get('metadata', {}))
    meta['grounded'] = True
    meta['synthetic'] = synthetic
    meta['grounded_by'] = 'byte_window_daemon.py'
    meta['grounded_at_unix_ms'] = int(time.time() * 1000)
    ps['metadata'] = meta

    atomic_write(output_path, ps)
    print(f'[BW_DAEMON] Wrote v{ps["store_version"]} synthetic={synthetic}')
    return ps


def run_daemon(policy_store_path, queue_dir, state_map_path, output_path,
               interval=60, window_size=32, stride=16, min_support=3):
    print(f'[BW_DAEMON] Starting, interval={interval}s')
    while True:
        try:
            infer_and_ground(policy_store_path, queue_dir, state_map_path,
                           output_path, window_size, stride, min_support)
        except Exception as e:
            print(f'[BW_DAEMON] Error: {e}')
        time.sleep(interval)


def main():
    p = argparse.ArgumentParser(description='Byte-Window Grounding Daemon')
    p.add_argument('--policy-store', required=True)
    p.add_argument('--queue-dir', required=True)
    p.add_argument('--state-map', required=True)
    p.add_argument('--out', required=True, help='grounded_policy_store_v2.json')
    p.add_argument('--interval', type=int, default=60)
    p.add_argument('--window-size', type=int, default=32)
    p.add_argument('--stride', type=int, default=16)
    p.add_argument('--min-support', type=int, default=3)
    p.add_argument('--daemon', action='store_true')
    p.add_argument('--once', action='store_true')
    args = p.parse_args()

    if args.daemon:
        run_daemon(args.policy_store, args.queue_dir, args.state_map, args.out,
                   args.interval, args.window_size, args.stride, args.min_support)
    else:
        infer_and_ground(args.policy_store, args.queue_dir, args.state_map, args.out,
                        args.window_size, args.stride, args.min_support)


if __name__ == '__main__':
    main()
