# Threat Model for `json_search()`

## 1. Overview

This document defines a simple threat model for the `json_search()` function used in a monitoring API.

The function recursively searches JSON-like data containing dictionaries and lists and returns values associated with a requested key.

The security model focuses on preventing unauthorized users from retrieving sensitive monitoring information.

The threat model uses the **STRIDE** framework.

---

# 2. System Description

The simplified system is:

```text
User / API Client
       |
       | role + search request
       v
+----------------------+
|    json_search()      |
|                      |
|  Recursive Search    |
|          +           |
|  Access Control      |
+----------+-----------+
           |
           | authorized results
           v
+----------------------+
| Monitoring JSON Data |
|                      |
| Normal Data          |
| Sensitive Data       |
+----------------------+
```

The function receives:

```python
json_search(key, input_object, role=None)
```

where:

* `key` is the field the caller wants to search for.
* `input_object` is the JSON-like monitoring data.
* `role` represents the caller's access-control role.

The main security objective is to ensure that the function does not return fields that the caller's role is not authorized to access.

---

# 3. Actors

## 3.1 Admin

The `admin` role is a privileged user of the monitoring system.

The admin may have access to sensitive monitoring fields according to the access-control policy defined in `policy.py`.

Potential security concern:

* A compromised admin account could expose sensitive information.
* The implementation must still follow the defined access-control policy.

---

## 3.2 Operator

The `operator` role is used for normal monitoring and operational activities.

The operator may have access to operational monitoring information but may not be authorized to retrieve all authentication-related information.

Potential security concern:

* An operator may attempt to request fields restricted to higher-privileged roles.

---

## 3.3 Viewer

The `viewer` role is a lower-privileged monitoring user.

The viewer should only receive fields explicitly permitted by the access-control policy.

Example attack:

```python
json_search("apiKey", data, role="viewer")
```

If `apiKey` is restricted, the expected result should be:

```python
[]
```

---

## 3.4 Malicious or Unauthorized User

An attacker may attempt to access sensitive information by supplying specially chosen search keys or by exploiting recursive data structures.

Examples include:

```text
apiKey
snmpAuth
password
token
```

The attacker may also attempt to find sensitive fields when they are deeply nested inside dictionaries or lists.

---

# 4. Assets

The JSON monitoring data may contain the following assets.

| Asset                      | Example                      | Security Importance |
| -------------------------- | ---------------------------- | ------------------- |
| Device identifiers         | Device ID, hostname, address | Medium              |
| Monitoring information     | CPU, memory, status          | Low/Medium          |
| API keys                   | `apiKey`                     | High                |
| SNMP authentication data   | SNMP authentication strings  | High                |
| Authentication information | Tokens or credentials        | High                |
| Authorization information  | Role/policy information      | High                |

The most sensitive assets are authentication-related values such as API keys and SNMP authentication information.

---

# 5. Trust Boundaries

The primary trust boundary exists between the caller and the monitoring data.

```text
              TRUST BOUNDARY
                    |
                    v
+-------------------+----------------------+
| External / Caller | Application          |
|                   |                      |
| admin             |  json_search()       |
| operator          |       |              |
| viewer            |       v              |
|                   | Access Control       |
+-------------------+-------+--------------+
                            |
                            v
                    Monitoring Data
```

The caller provides a search request and role.

The application must verify authorization before returning matching sensitive data.

The monitoring data itself is considered protected information.

---

# 6. Entry Points

The main entry point is the function:

```python
json_search(key, input_object, role=None)
```

Potentially attacker-controlled inputs include:

1. `key`
2. `input_object`
3. `role`

The security implementation must ensure that manipulating these inputs cannot bypass authorization.

---

# 7. STRIDE Threat Analysis

## 7.1 Spoofing

### Threat

A caller may attempt to claim a more privileged role.

For example:

```python
json_search("apiKey", data, role="admin")
```

when the actual caller is a lower-privileged user.

### Security Impact

If the application blindly trusts a user-supplied role, the attacker may obtain information intended for privileged users.

### Mitigation

The application/API layer should authenticate the caller and determine the caller's real role.

The role supplied to `json_search()` should correspond to the authenticated user's authorization context.

---

# 8. Tampering

### Threat

An attacker may manipulate the structure of the JSON input or place sensitive fields inside nested dictionaries or lists.

Example:

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

An implementation that checks authorization only at the top level could accidentally expose the nested `apiKey`.

### Security Impact

Sensitive information could bypass access-control checks because of its location in the JSON structure.

### Mitigation

Authorization checks must be applied to matching keys at every recursion level.

The function must perform the same security check for:

* top-level dictionaries
* nested dictionaries
* dictionaries inside lists
* deeply nested structures

---

# 9. Repudiation

### Threat

A user may request sensitive information without sufficient logging of the security-relevant operation.

### Security Impact

It may become difficult for the application administrator to determine:

* who requested the information;
* which field was requested;
* which role was used;
* whether access was authorized.

### Mitigation

The application layer should log security-relevant access attempts.

Recommended information includes:

```text
timestamp
user identity
role
requested key
authorization result
```

Sensitive values themselves should not be unnecessarily written to logs.

---

# 10. Information Disclosure

### Threat

A lower-privileged user may request a sensitive field.

Example:

```python
json_search("apiKey", data, role="viewer")
```

If the function does not enforce the access-control policy, it could return:

```python
[
    {"apiKey": "SECRET_VALUE"}
]
```

### Security Impact

An attacker could obtain:

* API keys
* SNMP authentication information
* other credentials
* other restricted monitoring information

This is the primary security threat for this function.

### Mitigation

The function must check the requested key against the role-based policy before returning results.

If the role is not authorized:

```python
[]
```

must be returned instead of the sensitive value.

The check must also apply to nested data.

---

# 11. Denial of Service

### Threat

An attacker may provide extremely large or deeply nested JSON-like input.

Example:

```text
very deeply nested dictionaries
        +
large lists
        +
many repeated objects
```

This could cause excessive recursive processing.

### Security Impact

Potential consequences include:

* excessive CPU usage;
* excessive memory consumption;
* slow responses;
* degradation of the monitoring service.

### Mitigation

The surrounding application should place reasonable limits on:

* input size;
* maximum nesting depth;
* request frequency.

The recursive implementation should also avoid unnecessary repeated processing.

For this lab, Denial of Service is considered a secondary threat compared with access-control issues.

---

# 12. Elevation of Privilege

### Threat

A lower-privileged user may attempt to access information available only to a higher-privileged role.

Example:

```text
viewer
   |
   +---- request "apiKey"
             |
             v
       restricted field
```

If `viewer` receives the field, the user has bypassed the intended authorization policy.

### Security Impact

This is an authorization bypass that can expose privileged information.

### Mitigation

The function must enforce the policy defined in `policy.py`.

For every requested field:

```text
Is this role authorized for this field?
             |
       +-----+-----+
       |           |
      YES          NO
       |           |
   return data    return []
```

Authorization must not depend on whether the field is located at the top level or inside nested data.

---

# 13. Threat Summary

| STRIDE Category        | Threat                                         | Main Asset           | Mitigation                            |
| ---------------------- | ---------------------------------------------- | -------------------- | ------------------------------------- |
| Spoofing               | Claiming a privileged role                     | Authorization        | Authenticate caller and validate role |
| Tampering              | Manipulating nested data to bypass checks      | Sensitive fields     | Apply authorization recursively       |
| Repudiation            | Insufficient security logging                  | Audit information    | Log security-relevant requests        |
| Information Disclosure | Unauthorized access to `apiKey` or credentials | API keys, SNMP data  | Enforce RBAC before returning results |
| Denial of Service      | Extremely large/deep input                     | Service availability | Input/depth/rate limits               |
| Elevation of Privilege | Viewer/operator accesses restricted fields     | Privileged data      | Enforce role-based policy             |

---

# 14. Security Priorities

The threats are considered in the following security areas:

### Priority 1: Information Disclosure

Prevent unauthorized users from retrieving sensitive fields such as:

```text
apiKey
SNMP authentication information
credentials
```

### Priority 2: Elevation of Privilege

Prevent lower-privileged roles from obtaining fields restricted to higher-privileged roles.

### Priority 3: Recursive Authorization

Ensure that security checks cannot be bypassed by placing sensitive fields inside nested dictionaries or lists.

### Priority 4: Input Abuse

Consider large or deeply nested inputs that could cause excessive resource consumption.

---

# 15. Security Test Mapping

The threat model should be reflected in the unit and security tests.

| Threat                         | Security Test                                      |
| ------------------------------ | -------------------------------------------------- |
| Information Disclosure         | Viewer cannot retrieve `apiKey`                    |
| Elevation of Privilege         | Unauthorized role cannot retrieve restricted field |
| Recursive Authorization Bypass | Restricted nested field cannot be retrieved        |
| Authorized Access              | Authorized role can retrieve permitted field       |
| Functional Regression          | Existing recursive search tests continue to pass   |

At least three security tests should be implemented in `test_json_search.py`.

---

# 16. Security Acceptance Criteria

The implementation satisfies this threat model when:

1. `json_search()` supports role-based access control.
2. Unauthorized roles cannot retrieve restricted fields.
3. Sensitive fields remain protected when deeply nested.
4. Dictionary and list traversal cannot bypass authorization.
5. At least three security tests verify the access-control behavior.
6. Existing functional tests continue to pass.
7. The complete test suite passes:

```bash
python3 -m unittest -v test_json_search.py
```

8. Security tests are not removed or weakened simply to make the test suite pass.

---

# 17. Conclusion

The main security concern for `json_search()` is unauthorized disclosure of protected monitoring information.

The STRIDE analysis identifies Information Disclosure and Elevation of Privilege as particularly relevant threats because `json_search()` can recursively expose values from monitoring data.

Therefore, role-based access control must be enforced consistently for every matching field, including fields located inside nested dictionaries and lists.

The implementation should follow the access-control policy defined in `policy.py` while preserving the original recursive search functionality.
