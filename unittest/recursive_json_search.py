from policy import POLICY


DEFAULT_ROLE = "viewer"


def is_role_allowed(key, role):
    allowed_roles = POLICY.get(key)
    if allowed_roles is None:
        return True

    effective_role = role or DEFAULT_ROLE
    return effective_role in allowed_roles


def json_search(key, input_object, role=None):
    ret_val = []

    if isinstance(input_object, dict):
        for k, v in input_object.items():
            if k == key and is_role_allowed(key, role):
                ret_val.append({k: v})

            if isinstance(v, (dict, list)):
                ret_val.extend(json_search(key, v, role=role))

    elif isinstance(input_object, list):
        for item in input_object:
            if isinstance(item, (dict, list)):
                ret_val.extend(json_search(key, item, role=role))

    return ret_val


if __name__ == "__main__":
    from test_data import data

    print(json_search("issueSummary", data))
