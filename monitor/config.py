import os
import json
import time

FTFUZZ_POLICY_DIR = os.environ.get("FTFUZZ_POLICY_DIR", "/tmp/ftfuzz_policies")
OUTPUT_DIR = os.environ.get("FTFUZZ_OUTPUT_DIR", "/tmp/ftfuzz_monitor_output")

os.makedirs(OUTPUT_DIR, exist_ok=True)


class Config:
    STSR_WINDOW_SIZE = int(os.environ.get("FTFUZZ_STSR_WINDOW", "1000"))
    STSR_THRESHOLD = float(os.environ.get("FTFUZZ_STSR_THRESHOLD", "0.05"))
    PLATEAU_WINDOW = int(os.environ.get("FTFUZZ_PLATEAU_WINDOW", "5000"))
    PLATEAU_THRESHOLD = float(os.environ.get("FTFUZZ_PLATEAU_THRESHOLD", "0.01"))
    POLL_INTERVAL = float(os.environ.get("FTFUZZ_POLL_INTERVAL", "1.0"))
    BARRIER_BIAS_THRESHOLD = float(os.environ.get("FTFUZZ_BARRIER_BIAS", "0.9"))
    MAX_BARRIERS = int(os.environ.get("FTFUZZ_MAX_BARRIERS", "4096"))
    MAX_TRANSITIONS = int(os.environ.get("FTFUZZ_MAX_TRANSITIONS", "1024"))
