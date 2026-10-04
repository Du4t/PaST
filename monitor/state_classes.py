"""
FTFuzz State Class Definitions

Canonical state class names, normalization, and ranking for the
Runtime Barrier-Driven State Transition Model.

Canonical classes (in order of progress toward target):
  Fail-Pre:                    Execution does not reach PreState
  Reach-Pre:                   PreState reached, Barrier not reached
  Barrier-Reached:             PreState + Barrier reached, PostState not reached
  Reach-Post:                  PreState + PostState reached
  Invalid-Post-Without-Pre:    PostState reached without PreState (validation warning)

Backward compatibility:
  "Near-Post" is an alias for "Barrier-Reached".
  All new outputs use canonical names.
"""

# Canonical class names (Stage 1.8: added branch-aware classes)
CANONICAL_CLASSES = [
    "Fail-Pre",
    "Reach-Pre",
    "Barrier-Reached",
    "Blocked-at-Barrier",
    "Progressed-Through-Barrier",
    "Reach-Post",
    "Invalid-Post-Without-Pre",
]

# Alias map: old name -> canonical name
ALIASES = {
    "Near-Post": "Barrier-Reached",
    "near_post": "Barrier-Reached",
    "NearPost": "Barrier-Reached",
    # Stage 1.8 branch-aware aliases
    "Blocked-at-Barrier": "Blocked-at-Barrier",
    "Progressed-Through-Barrier": "Progressed-Through-Barrier",
}

# Rank: higher = more progress toward target
CLASS_RANK = {
    "Fail-Pre": 0,
    "Reach-Pre": 1,
    "Barrier-Reached": 2,
    "Blocked-at-Barrier": 3,
    "Progressed-Through-Barrier": 4,
    "Reach-Post": 5,
    "Invalid-Post-Without-Pre": -1,
}

# Classification function
def classify_transition(pre_hit, barrier_hit, post_hit,
                        target_edge_taken=None, target_edge_tracking_available=False):
    """Classify a transition state into canonical class.

    Stage 1.8: when target edge tracking is available, distinguish
    Blocked-at-Barrier from Progressed-Through-Barrier.

    Args:
        pre_hit: bool, whether PreState was reached
        barrier_hit: bool, whether Barrier was reached
        post_hit: bool, whether PostState was reached
        target_edge_taken: bool or None, whether the target edge was taken
        target_edge_tracking_available: bool, whether edge tracking data exists

    Returns:
        Canonical state class name string.
    """
    if pre_hit and post_hit:
        return "Reach-Post"
    elif pre_hit and barrier_hit and not post_hit:
        if target_edge_tracking_available and target_edge_taken is not None:
            if target_edge_taken:
                return "Progressed-Through-Barrier"
            else:
                return "Blocked-at-Barrier"
        return "Barrier-Reached"
    elif pre_hit and not barrier_hit and not post_hit:
        return "Reach-Pre"
    elif not pre_hit and post_hit:
        return "Invalid-Post-Without-Pre"
    else:
        return "Fail-Pre"


def normalize_state_class(name):
    """Normalize a state class name to canonical form.

    Handles backward compatibility aliases like 'Near-Post' -> 'Barrier-Reached'.

    Args:
        name: state class name string

    Returns:
        Canonical state class name string.
    """
    if name in CANONICAL_CLASSES:
        return name
    if name in ALIASES:
        return ALIASES[name]
    # Unknown class - return as-is with warning
    return name


def state_class_rank(name):
    """Get the progress rank of a state class.

    Higher rank means more progress toward the target.

    Args:
        name: state class name (canonical or alias)

    Returns:
        Integer rank, or -2 for unknown classes.
    """
    canonical = normalize_state_class(name)
    return CLASS_RANK.get(canonical, -2)


def best_state_class(class_list):
    """Find the best (highest-rank) state class from a list.

    Args:
        class_list: list of state class name strings

    Returns:
        Canonical name of the best class, or "Fail-Pre" if empty.
    """
    if not class_list:
        return "Fail-Pre"
    best = max(class_list, key=lambda c: state_class_rank(c))
    return normalize_state_class(best)


def class_to_dirname(name):
    """Convert a canonical class name to a directory-safe name.

    Args:
        name: canonical state class name

    Returns:
        Lowercase, hyphen-to-underscore directory name.
    """
    return normalize_state_class(name).replace("-", "_").lower()


def dirname_to_class(dirname):
    """Convert a directory name back to canonical class name.

    Args:
        dirname: directory name like 'barrier_reached'

    Returns:
        Canonical state class name like 'Barrier-Reached'
    """
    mapping = {class_to_dirname(c): c for c in CANONICAL_CLASSES}
    return mapping.get(dirname, dirname)
