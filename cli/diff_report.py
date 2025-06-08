import json

def load_report(path):
    try:
        return json.load(open(path))
    except FileNotFoundError:
        # First run: no cache yet
        return {"assets": [], "meta-data": [], "alerts": []}

def index_by_id(list_of_objs, id_key):
    """Build a { id → object } map."""
    return { obj[id_key]: obj for obj in list_of_objs }

def diff_section(old_list, new_list, id_key):
    old_idx = index_by_id(old_list, id_key)
    new_idx = index_by_id(new_list, id_key)

    added   = [ new_idx[i] for i in new_idx   if i not in old_idx   ]
    removed = [ old_idx[i] for i in old_idx   if i not in new_idx   ]
    # “Modified” = same ID but object differs
    modified = [
        new_idx[i] for i in new_idx
        if i in old_idx and new_idx[i] != old_idx[i]
    ]
    return added, removed, modified

def build_diff_payload(old, new):
    a_add, a_rem, a_mod = diff_section(old["assets"], new["assets"], "asset-id")
    m_add, m_rem, m_mod = diff_section(old["meta-data"], new["meta-data"], "meta-id")
    alert_add, alert_rem, alert_mod = diff_section(old["alerts"], new["alerts"], "alert_name")
    # or use an alert-id if you add one

    return {
      "assets":   {"added": a_add,   "removed": a_rem,   "modified": a_mod},
      "meta-data":{"added": m_add,   "removed": m_rem,   "modified": m_mod},
      "alerts":   {"added": alert_add,"removed": alert_rem,"modified": alert_mod}
    }
