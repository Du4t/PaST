#!/usr/bin/env python3
"""
FTFuzz Policy Store — atomic versioned policy artifact management.

Usage:
  python3 policy/policy_store.py --get-active /path/to/policy_store.json
  python3 policy/policy_store.py --bump-version /path/to/policy_store.json
"""

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
import glob as globmod

POLICY_DIR = os.environ.get("FTFUZZ_POLICY_DIR", "/tmp/ftfuzz_policies")
CURRENT_POLICY_FILE = os.path.join(POLICY_DIR, "current_policy.json")
VERSION_FILE = os.path.join(POLICY_DIR, "current_version.txt")
os.makedirs(POLICY_DIR, exist_ok=True)


def _atomic_write_json(path, data):
    dir_name = os.path.dirname(path) or '.'
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".json.tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.rename(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_write(path, data):
    """Write JSON atomically."""
    _atomic_write_json(path, data)


def load_store(path):
    """Load policy store; return None if missing or corrupt."""
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None


def bump_version(path):
    """Increment store_version atomically."""
    store = load_store(path)
    if not store:
        print(f'[ERROR] Cannot load store: {path}', file=sys.stderr)
        sys.exit(1)
    store['store_version'] = store.get('store_version', 0) + 1
    store['updated_at'] = datetime.now(timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%SZ')
    _atomic_write_json(path, store)
    print(f'store_version -> {store["store_version"]}')


def get_active(path):
    """Print active transition info."""
    store = load_store(path)
    if not store:
        print(f'[ERROR] Cannot load store: {path}', file=sys.stderr)
        sys.exit(1)
    active_tid = store.get('active_transition', 'N/A')
    active_ver = store.get('active_policy_version', 0)
    store_ver = store.get('store_version', 0)
    policy = store.get('policies', {}).get(active_tid, {})
    tokens = policy.get('mutation_actions', {}).get('dictionary_tokens', [])
    print(f'store_version={store_ver} active={active_tid} '
          f'policy_version={active_ver} tokens={len(tokens)} '
          f'enabled={policy.get("enabled", False)}')


# Legacy compatibility
def write_policy(policy):
    if "version" not in policy:
        policy["version"] = 1
    _atomic_write_json(CURRENT_POLICY_FILE, policy)
    _atomic_write_json(VERSION_FILE, str(policy["version"]))


def read_policy():
    try:
        with open(CURRENT_POLICY_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def read_version():
    try:
        with open(VERSION_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def validate_policy(policy):
    schema_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "mutation_policy_schema.json",
    )
    try:
        import jsonschema
        with open(schema_path, "r") as f:
            schema = json.load(f)
        jsonschema.validate(instance=policy, schema=schema)
        return True, None
    except ImportError:
        required_fields = [
            "policy_id", "version", "enabled", "target_transition",
        ]
        for field in required_fields:
            if field not in policy:
                return False, f"Missing required field: {field}"
        return True, None
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description='FTFuzz Policy Store Manager')
    parser.add_argument('path', nargs='?', help='Path to policy_store.json')
    parser.add_argument('--bump-version', action='store_true')
    parser.add_argument('--get-active', action='store_true')
    args = parser.parse_args()

    if args.bump_version and args.path:
        bump_version(args.path)
    elif args.get_active and args.path:
        get_active(args.path)
    elif args.path:
        get_active(args.path)
    else:
        print("Usage: policy_store.py [--bump-version|--get-active] <path>")


if __name__ == '__main__':
    main()
