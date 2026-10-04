import struct
import sys
import os
import json


class SnapshotReader:
    def __init__(self, shm_key=0xAFF00001):
        self.shm_key = shm_key
        self.shm_data = None

    def attach_shm(self):
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c"))

        shmid = libc.shmget(self.shm_key, 0, 0)
        if shmid < 0:
            return False

        addr = libc.shmat(shmid, None, 0)
        if addr == -1:
            return False

        self.shm_addr = addr
        self.shmid = shmid
        return True

    def read_from_jsonl(self, jsonl_path):
        records = []
        with open(jsonl_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records

    @staticmethod
    def dump_cmp_records(records, output_path):
        with open(output_path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    @staticmethod
    def dump_snapshot_records(records, output_path):
        with open(output_path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Dump FTFuzz shared memory snapshots")
    parser.add_argument("--input", required=True, help="Input JSONL file")
    parser.add_argument("--output", required=True, help="Output JSONL file")
    parser.add_argument("--type", choices=["cmp", "snapshot", "all"], default="all")
    args = parser.parse_args()

    reader = SnapshotReader()
    records = reader.read_from_jsonl(args.input)
    reader.dump_cmp_records(records, args.output)
    print(f"Dumped {len(records)} records to {args.output}")
