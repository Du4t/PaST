import json
import os
import time

from .config import Config, OUTPUT_DIR
from .stsr_tracker import STSRTracker


class BarrierMonitor:
    def __init__(self, config=None):
        self.config = config or Config()
        self.stsr_tracker = STSRTracker(config)
        self.barrier_reports = {}
        self.cmp_records = []
        self.distance_history = {}

    def load_cmp_records(self, jsonl_path):
        self.cmp_records = []
        with open(jsonl_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self.cmp_records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    def update_counters(self, transition_id, pre_hits, post_hits, barrier_id=None,
                        barrier_hit_count=0, distance=0, branch_bias=0.0):
        self.stsr_tracker.update(transition_id, pre_hits, post_hits)
        stsr = self.stsr_tracker.record_stsr(transition_id)

        if barrier_id is not None:
            if barrier_id not in self.distance_history:
                self.distance_history[barrier_id] = []
            self.distance_history[barrier_id].append(distance)

        is_stuck = self.stsr_tracker.is_stuck(transition_id)
        is_plateau = self._check_plateau(barrier_id)

        self.barrier_reports[transition_id] = {
            "transition_id": transition_id,
            "barrier_id": barrier_id,
            "pre_hits": pre_hits,
            "post_hits": post_hits,
            "stsr": round(stsr, 6),
            "branch_bias": round(branch_bias, 4),
            "plateau": is_plateau,
            "stuck": is_stuck,
            "distance": distance,
        }

        return self.barrier_reports[transition_id]

    def _check_plateau(self, barrier_id):
        if barrier_id is None or barrier_id not in self.distance_history:
            return False
        history = self.distance_history[barrier_id]
        if len(history) < 10:
            return False
        recent = history[-10:]
        min_d = min(recent)
        max_d = max(recent)
        if max_d - min_d <= self.config.PLATEAU_THRESHOLD * max_d + 1:
            return True
        return False

    def compute_branch_bias(self, barrier_id):
        taken = 0
        total = 0
        for rec in self.cmp_records:
            if rec.get("barrier_id") == barrier_id:
                total += 1
                if rec.get("outcome", 0) != 0:
                    taken += 1
        if total == 0:
            return 0.0
        return max(taken, total - taken) / total

    def get_active_barriers(self):
        active = []
        for tid, report in self.barrier_reports.items():
            if report.get("stuck", False) or report.get("plateau", False):
                active.append(report)
        return sorted(active, key=lambda r: r.get("stsr", 1.0))

    def export_reports(self, output_dir=None):
        output_dir = output_dir or OUTPUT_DIR
        os.makedirs(output_dir, exist_ok=True)

        report_path = os.path.join(output_dir, "barrier_report.json")
        with open(report_path, "w") as f:
            json.dump({
                "timestamp": time.time(),
                "active_barriers": self.get_active_barriers(),
                "all_reports": dict(self.barrier_reports),
                "stsr_state": self.stsr_tracker.export_state(),
            }, f, indent=2)

        return report_path


if __name__ == "__main__":
    monitor = BarrierMonitor()

    monitor.update_counters("T_001", 1000, 5, barrier_id="B_017",
                            barrier_hit_count=950, distance=10, branch_bias=0.97)
    monitor.update_counters("T_001", 5000, 12, barrier_id="B_017",
                            barrier_hit_count=4500, distance=10, branch_bias=0.97)
    monitor.update_counters("T_001", 10000, 18, barrier_id="B_017",
                            barrier_hit_count=9000, distance=10, branch_bias=0.96)

    report_path = monitor.export_reports()
    print(f"Barrier report exported to {report_path}")
    print(json.dumps(monitor.get_active_barriers(), indent=2))
