import os
import glob as globmod
import struct
import json


class SeedSelector:
    def __init__(self, findings_dir=None):
        self.findings_dir = findings_dir
        self.groups = {
            "fail_pre": [],
            "reach_pre": [],
            "near_post": [],
            "reach_post": [],
        }

    def classify_seed(self, seed_path, pre_hits=0, post_hits=0, distance=9999):
        seed_name = os.path.basename(seed_path)
        if post_hits > 0:
            self.groups["reach_post"].append({
                "path": seed_path,
                "name": seed_name,
                "pre_hits": pre_hits,
                "post_hits": post_hits,
                "distance": distance,
            })
        elif pre_hits > 0 and distance < 5:
            self.groups["near_post"].append({
                "path": seed_path,
                "name": seed_name,
                "pre_hits": pre_hits,
                "post_hits": post_hits,
                "distance": distance,
            })
        elif pre_hits > 0:
            self.groups["reach_pre"].append({
                "path": seed_path,
                "name": seed_name,
                "pre_hits": pre_hits,
                "post_hits": post_hits,
                "distance": distance,
            })
        else:
            self.groups["fail_pre"].append({
                "path": seed_path,
                "name": seed_name,
                "pre_hits": pre_hits,
                "post_hits": post_hits,
                "distance": distance,
            })

    def classify_from_queue_dir(self, queue_dir, pre_state_ids=None, post_state_ids=None):
        pre_state_ids = pre_state_ids or []
        post_state_ids = post_state_ids or []

        seeds = globmod.glob(os.path.join(queue_dir, "id:*"))
        for seed_path in sorted(seeds):
            seed_name = os.path.basename(seed_path)
            pre_hits = 0
            post_hits = 0
            distance = 9999

            if any(tag in seed_name for tag in ["+cov"]):
                pre_hits = 1

            self.classify_seed(seed_path, pre_hits, post_hits, distance)

        return self.groups

    def get_seeds_for_inference(self):
        result = []
        if self.groups["reach_pre"]:
            result.extend(self.groups["reach_pre"])
        elif self.groups["fail_pre"]:
            result.extend(self.groups["fail_pre"][:5])
        if self.groups["near_post"]:
            result.extend(self.groups["near_post"])
        if self.groups["reach_post"]:
            result.extend(self.groups["reach_post"])
        return result

    def export_groups(self, output_path=None):
        data = {}
        for group_name, seeds in self.groups.items():
            data[group_name] = [s["name"] for s in seeds]

        if output_path:
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)

        return data
