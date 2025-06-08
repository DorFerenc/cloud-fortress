"""
cli/diff_report.py

Load two JSON reports (old & new), compute added/removed/modified entries
in assets, meta-data, and alerts—**ignoring the 'time' field on alerts**—
and build a “diff” payload.
"""

import json

def load_report(path):
    """Load a JSON report from `path`, or return empty sections if missing."""
    try:
        return json.load(open(path))
    except FileNotFoundError:
        return {"assets": [], "meta-data": [], "alerts": []}

def _normalize_key(val):
    """
    If val is list or dict, JSON-serialize it (sorted keys) to a string.
    Otherwise convert to string.
    """
    if isinstance(val, (list, dict)):
        return json.dumps(val, sort_keys=True)
    return str(val)

def index_by_id(items, id_key):
    """
    Build a { normalized_id_value → item } map.
    Uses _normalize_key to ensure hashability.
    """
    idx = {}
    for item in items:
        raw = item.get(id_key)
        key = _normalize_key(raw)
        idx[key] = item
    return idx

def diff_section(old_list, new_list, id_key):
    """
    Compare two lists of dicts by id_key, returning (added, removed, modified).
    """
    old_idx = index_by_id(old_list, id_key)
    new_idx = index_by_id(new_list, id_key)

    added =   [ new_idx[k] for k in new_idx if k not in old_idx ]
    removed = [ old_idx[k] for k in old_idx if k not in new_idx ]
    modified = [
        new_idx[k] for k in new_idx
        if k in old_idx and new_idx[k] != old_idx[k]
    ]
    return added, removed, modified

def build_diff_payload(old, new):
    """
    Build a diff payload containing added/removed/modified for each section,
    but strip out 'time' from alerts before diffing so timestamps don't
    trigger spurious modifications.
    """
    # 1) Assets
    a_add, a_rem, a_mod = diff_section(
        old["assets"], new["assets"], "asset-id"
    )

    # 2) Meta-data
    m_add, m_rem, m_mod = diff_section(
        old["meta-data"], new["meta-data"], "meta-id"
    )

    # 3) Alerts: ignore 'time' differences
    def key_for_alert(a):
        # use alert_name + host + port to uniquely identify
        return f"{a['alert_name']}|{a['host']}|{a['port']}"

    old_map = { key_for_alert(a): a for a in old["alerts"] }
    new_map = { key_for_alert(a): a for a in new["alerts"] }

    added = [ new_map[k] for k in new_map if k not in old_map ]
    removed = [ old_map[k] for k in old_map if k not in new_map ]

    # Modified = same key exists and some _other_ field changed
    modified = []
    for k in new_map:
        if k in old_map:
            old_a, new_a = old_map[k], new_map[k]
            # compare everything _except_ time
            o2 = {x: old_a[x] for x in old_a if x != "time"}
            n2 = {x: new_a[x] for x in new_a if x != "time"}
            if o2 != n2:
                modified.append(new_a)

    return {
      "assets":    {"added": a_add,    "removed": a_rem,    "modified": a_mod},
      "meta-data": {"added": m_add,    "removed": m_rem,    "modified": m_mod},
      "alerts":    {"added": added,    "removed": removed,  "modified": modified}
    }
