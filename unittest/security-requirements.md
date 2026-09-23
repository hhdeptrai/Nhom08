# Security Requirements and Threat Model for json_search()

## Context

`json_search()` searches nested JSON data returned by a network monitoring API.
The data can contain public operational information and sensitive infrastructure
information. The function is used by different roles: `admin`, `operator`, and
`viewer`.

## Actors and Roles

- `admin`: can search all fields, including secrets and infrastructure details.
- `operator`: can search operational fields needed for monitoring and incident
  handling, but cannot read secrets.
- `viewer`: can search low-sensitivity summary fields only.

## Sensitive Assets

- `apiKey`: SNMP/API credential-like secret.
- `managementIpAddress`: device management IP address.
- `macAddress`, `serialNumber`, `hostname`, and other device identifiers.
- Error and inventory details that may reveal internal infrastructure.

## Trust Boundary

The JSON object comes from an infrastructure monitoring API and may contain
sensitive internal data. The caller of `json_search()` may have a lower-privilege
role than the data source. If `json_search()` returns matched values without
checking the caller role, the function crosses the trust boundary and exposes
data to unauthorized users.

## STRIDE Threats

| STRIDE Category | Threat | Example |
| --- | --- | --- |
| Information Disclosure | A low-privilege user reads a protected field. | `viewer` searches for `apiKey` and receives the secret value. |
| Elevation of Privilege | A caller bypasses role restrictions by choosing sensitive keys directly. | `operator` searches for `apiKey` even though only `admin` should access it. |

## Security Requirements

SR-1. `apiKey` must only be returned when `role="admin"`.

SR-2. `managementIpAddress` must only be returned when the role is `admin` or
`operator`.

SR-3. `issueSummary` may be returned to `admin`, `operator`, and `viewer`.

SR-4. When the requested key is protected by `POLICY` and the caller role is not
listed for that key, `json_search()` must return an empty list.

SR-5. If no role is supplied, `json_search()` treats the caller as `viewer` by
default, so only fields allowed for `viewer` can be returned.

SR-6. The recursive search must aggregate results from all nested dictionaries
and lists without dropping matches found in recursive calls.
