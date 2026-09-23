from test_data import *
from policy import POLICY


def json_search(key, input_object, role=None):
    """
    Recursively search for a key in nested dicts and lists.
    Enforce role-based access control based on policy.py.
    """
    ret_val = []

    def _search(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key:
                    if _is_authorized(key, role):
                        ret_val.append({k: v})
                if isinstance(v, (dict, list)):
                    _search(v)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    _search(item)

    _search(input_object)
    return ret_val


def _is_authorized(key, role):
    """
    Check if the given role is authorized to access the key.
    If no role is provided, allow all (preserve original behavior).
    If role is provided, enforce policy: default-deny for keys in POLICY.
    Keys not in POLICY are not sensitive and are always allowed.
    """
    if role is None:
        return True  # No role provided = preserve original behavior
    if key not in POLICY:
        return True  # Key not in policy = not sensitive = allow
    return role in POLICY[key]
