# Security Requirements and Threat Model for `json_search()`

## 1. Scope

The `json_search()` function recursively searches for a specified key in JSON-like data structures containing dictionaries and lists.

The function is assumed to be used by different roles in a monitoring API:

* `admin`
* `operator`
* `viewer`

The security objective is to ensure that a user can only receive data fields that are authorized for their role.

---

# 2. Assets

The JSON data searched by `json_search()` may contain both normal monitoring information and sensitive information.

Examples of assets include:

| Asset                      | Description                                                | Sensitivity |
| -------------------------- | ---------------------------------------------------------- | ----------- |
| Device identifiers         | Device names, IDs, addresses, or other identifiers         | Medium      |
| Monitoring data            | CPU, memory, status, interface information, etc.           | Low/Medium  |
| API keys                   | API authentication keys                                    | High        |
| SNMP credentials           | SNMP authentication strings or related credentials         | High        |
| Authentication information | Passwords, tokens, or other authentication data if present | High        |
| Role/access information    | Information determining which fields a role can access     | High        |

The most important security assets are authentication-related values such as `apiKey` and SNMP authentication strings.

---

# 3. Actors and Roles

The system has three main roles.

## 3.1 Admin

The `admin` role is a privileged monitoring user.

The admin may access fields that are restricted from lower-privileged roles, including sensitive authentication-related fields when permitted by `policy.py`.

## 3.2 Operator

The `operator` role can access operational monitoring information required for normal administration and monitoring activities.

Sensitive authentication fields should only be returned if explicitly permitted by the access-control policy.

## 3.3 Viewer

The `viewer` role is a lower-privileged user.

The viewer should only receive fields explicitly allowed by the policy and must not receive sensitive authentication information such as `apiKey` when that field is restricted.

## 3.4 Malicious or Unauthorized User

An attacker may attempt to call `json_search()` with the name of a sensitive field, for example:

```text
apiKey
```

The attacker may attempt to exploit the recursive search function to retrieve data that their role is not authorized to access.

---

# 4. Trust Boundary

The main trust boundary is between the caller's role and the JSON data returned by `json_search()`.

Conceptually:

```text
+-------------------+
| Caller / API User |
|                   |
| admin             |
| operator          |
| viewer            |
+---------+---------+
          |
          | role + search request
          v
+-------------------+
|   json_search()   |
|                   |
| Recursive Search  |
|       +           |
| Access Control    |
+---------+---------+
          |
          | authorized results only
          v
+-------------------+
| Monitoring JSON   |
| Data              |
|                   |
| normal fields     |
| sensitive fields  |
+-------------------+
```

The role provided to `json_search()` must not be treated as sufficient authorization by itself. The function must check the requested key against the access-control policy before returning matching values.

---

# 5. Security Goals

The security goals for `json_search()` are:

1. Prevent unauthorized users from receiving sensitive fields.
2. Enforce role-based access control consistently during recursive searches.
3. Ensure that nested dictionaries and lists cannot bypass access-control checks.
4. Return only results that the requested role is authorized to access.
5. Preserve the normal recursive search functionality for authorized fields.
6. Avoid exposing sensitive information through recursive results.

---

# 6. STRIDE Threat Model

The following threats are considered using the STRIDE framework.

## 6.1 Spoofing

### Threat

An unauthorized caller may attempt to claim a more privileged role, such as using:

```text
role="admin"
```

instead of their actual role.

### Impact

If the caller's role is trusted without proper validation by the surrounding application, the caller could potentially receive restricted information.

### Mitigation

`json_search()` must use the role according to the application's access-control policy.

The function should not provide unrestricted access merely because a caller supplies a privileged role value.

Authentication and validation of the user's actual role should occur at the appropriate application/API boundary.

---

## 6.2 Tampering

### Threat

An attacker may attempt to modify the requested key or input structure to bypass access-control checks.

For example, an attacker may place a sensitive field such as:

```json
{
    "device": {
        "credentials": {
            "apiKey": "SECRET"
        }
    }
}
```

inside a deeply nested dictionary or list.

### Impact

If access control is applied only to top-level data, the attacker may retrieve restricted data through nested structures.

### Mitigation

Access-control checks must be applied to every matched key regardless of its nesting depth.

Recursive traversal of dictionaries and lists must not bypass the security policy.

---

## 6.3 Repudiation

### Threat

A user may request sensitive information through `json_search()`, but there may be no record of which role requested the information.

### Impact

It may be difficult to determine whether sensitive data was accessed appropriately.

### Mitigation

When `json_search()` is integrated into an application or API, security-relevant requests should be logged by the appropriate application layer.

The log should record information such as:

* requesting role
* requested key
* timestamp
* result of the authorization check

Sensitive values themselves should not be unnecessarily written to logs.

---

## 6.4 Information Disclosure

### Threat

A low-privileged user such as `viewer` requests a sensitive field:

```text
json_search("apiKey", data, role="viewer")
```

If the function returns the matching value without checking the policy, the API key can be disclosed.

### Impact

Disclosure of API keys, SNMP credentials, or other authentication information could allow unauthorized access to monitoring infrastructure.

### Mitigation

`json_search()` must enforce the role-based access-control policy before returning matching data.

For example, if `viewer` is not authorized to access `apiKey`, the expected result is:

```python
[]
```

instead of the sensitive value.

This check must also work when the sensitive field appears inside nested dictionaries or lists.

---

## 6.5 Denial of Service

### Threat

An attacker may provide very deeply nested or unusually large JSON-like input to cause excessive recursive processing.

### Impact

The function may consume excessive CPU or memory, potentially degrading the monitoring service.

### Mitigation

The application using `json_search()` should impose reasonable limits on input size and nesting depth.

Where appropriate, the recursive implementation should also avoid unnecessary repeated processing.

For this lab, the primary focus remains access control and information disclosure.

---

## 6.6 Elevation of Privilege

### Threat

A lower-privileged role may attempt to obtain information intended only for a higher-privileged role.

For example:

```text
viewer -> request apiKey
```

If the function returns the restricted field, the viewer effectively bypasses the intended access-control policy.

### Impact

This represents an authorization bypass and privilege escalation.

### Mitigation

Every search result must be checked against the policy associated with the caller's role.

A user must not receive a field merely because the field exists in the JSON data.

The security rule is:

> A role may receive a field only when that role is authorized to access the field according to `policy.py`.

---

# 7. Security Requirements

## SR-01: Role-Based Access Control

`json_search()` shall support a role parameter:

```python
json_search(key, input_object, role=None)
```

The function shall use the role to enforce the access-control policy.

---

## SR-02: Deny Unauthorized Fields

If a role is not authorized to access a requested field, `json_search()` shall return no matching results for that field.

Example:

```python
json_search("apiKey", data, role="viewer")
```

Expected result when `viewer` is not authorized:

```python
[]
```

---

## SR-03: Recursive Access Control

Access-control checks shall apply to fields at every nesting level.

For example, the following must not bypass authorization:

```json
{
    "devices": [
        {
            "credentials": {
                "apiKey": "SECRET"
            }
        }
    ]
}
```

A restricted `apiKey` must remain protected even when it is located inside a list or deeply nested dictionary.

---

## SR-04: Preserve Authorized Search

If a role is authorized to access a requested field, `json_search()` shall return all matching authorized results.

For example, an authorized request for:

```text
hostname
```

should still recursively find matching `hostname` fields in nested dictionaries and lists.

---

## SR-05: No Security Bypass Through Lists

The same authorization policy shall apply to dictionary values and objects contained inside lists.

An attacker must not be able to bypass access control simply by placing a restricted field inside a list.

---

## SR-06: Default-Deny for Unknown or Missing Roles

When the security policy does not explicitly authorize a role to access a sensitive field, the function should not expose that field.

The implementation should prefer denying access to protected information rather than returning it without authorization.

---

## SR-07: No Sensitive Data in Error Messages

Errors or exceptions generated by the function should not unnecessarily reveal sensitive field values.

For example, an authorization failure should not include:

```text
apiKey = SECRET_VALUE
```

in the error message.

---

## SR-08: Functional Behavior Must Be Preserved

The security changes must not break the original recursive search functionality.

The following baseline behaviors must continue to work:

* `test_search_found`
* `test_search_not_found`
* `test_is_a_list`

---

# 8. Security Test Requirements

At least three security tests shall be implemented in `test_json_search.py`.

The tests should verify the policy defined in `policy.py`.

Suggested security tests:

### Test 1: Viewer Cannot Access API Key

```python
result = json_search("apiKey", data, role="viewer")
self.assertEqual(result, [])
```

### Test 2: Authorized Role Can Access API Key

Test that a role authorized by `policy.py` can retrieve the `apiKey` field.

### Test 3: Restricted Nested Field Cannot Be Retrieved

Place a sensitive field inside a nested dictionary or list and verify that an unauthorized role still receives:

```python
[]
```

The tests should verify that the security check cannot be bypassed through recursive nesting.

---

# 9. Security Acceptance Criteria

The implementation is considered acceptable when all of the following conditions are satisfied:

* `json_search()` supports the `role` parameter.
* Recursive searches correctly aggregate results from dictionaries and lists.
* Access control is enforced for every matching field.
* Unauthorized roles cannot retrieve restricted fields.
* At least three security tests are implemented.
* The baseline functional tests continue to pass.
* The full test suite passes successfully with:

```bash
python3 -m unittest -v test_json_search.py
```

* The implementation does not weaken or remove security tests merely to make the test suite pass.

---

# 10. Summary

The main security risk for `json_search()` is unauthorized disclosure of sensitive monitoring information through insufficient role-based access control.

The primary STRIDE threats for this function are:

* Information Disclosure
* Elevation of Privilege
* Tampering
* Spoofing
* Denial of Service
* Repudiation

The most important security requirement is that a role must only receive fields that it is authorized to access according to `policy.py`, regardless of whether the field is located at the top level or deeply nested inside dictionaries and lists.
