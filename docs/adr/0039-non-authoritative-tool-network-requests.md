# ADR-0039: Non-authoritative tool network requests

## Status

Accepted for [#307](https://github.com/gregwebs/agent-vm/issues/307), slice 3
of [#302](https://github.com/gregwebs/agent-vm/issues/302). Follows
[ADR-0036](0036-default-deny-launch-egress.md) and
[ADR-0037](0037-hostname-egress-allowances.md); amends
[ADR-0018](0018-machine-checked-boundary-contracts.md).

## Context

A repository may describe the services its tool expects, but cannot grant
network authority. Deliberately restricted sessions must still start.

## Decision

`network_requests` is tool metadata in either config tier. Reuse the hostname
allowance parser; refuse IP/CIDR, default bare requests to port 443, and store
canonical exact names and single ports in a sorted, deduplicated set. Cap
**declared entries** at 64, before parsing. Reordering and duplicates therefore
do not cause conflicts. Existing catalog selection applies: user definitions
win wholesale, and invalid shadowed project declarations still fail.

```text
config → canonical requests ──► bounded report ◄── CLI authority → policy
                                  │
                                stderr
```

Report only the launched tool's own requests, never the `tools` provisioning
closure. Coverage is lookup-free syntactic coverage by public or same-name
grants, not connectivity:

| Authority | Covered |
|---|---|
| Internet/Public | Any request |
| Same-name hostname | Port in that allowance's effective ports |
| Numeric, LAN, host | Not matched to names |

Bare hostname allowances use the launch-wide intercepted ports; explicit ports
union for a shared name. Numeric/LAN/host combinations may make an “unmet” name
reachable, but deciding that would require a lookup. Covered names may fail
resolution, private-answer eligibility or TLS client requirements. See the
canonical operational reference in [USAGE](../../USAGE.md#tool-network-requests)
and [TLS client requirements](../../USAGE.md#tls-client-requirements).

Report after egress notices and before applying policy. No requests prints
nothing; all covered prints one fixed header. Otherwise print an informational
`==>` header stating requests never grant access and launch continues, up to 8
sorted `unmet:` entries, an overflow count, and a fixed grant hint. At most 11
lines. The longest renderable entry — a 253-byte canonical name at port 65535 —
is 278 bytes, and a test asserts every line of a maximum-length report is ≤ 300
bytes. Doctor uses the same 8-entry budget.

Only validated canonical ASCII hostname/port displays reach notices. Raw
rejected entries never appear in errors; only entry positions and fixed reasons
do. Tier labels and framing are fixed; no tool names or paths appear in the
report. Covered names are not individually rendered beside approval wording.
No copy-pasteable grant is composed from repository strings.

## Trusted vs proved

Two Verus kernels prove count ≤ 64 and shown < 8. They prove these comparisons,
not that the limits are appropriate. Parsing composes the existing grammar
kernels unchanged; address/name classification, the 443 default and error
mapping remain trusted adapters. Coverage is a read-only query with table and
emitted-policy differential tests, not a proved boundary decision.

“Requests never authorize” rests on a reviewed data-flow invariant plus tested
runtime-input noninterference, not a type-level proof. The request path calls
no resolver, socket, credential or provisioning subsystem. Runtime dumps
cannot establish absence of host I/O; review and the textual tripwire address
that separately.

## Rejected alternatives

- Requests as authority or implicit provider allowances: a repo would widen access.
- Folding `tools`: provisioning is not a request-report input and wildcard shells would report every tool.
- Resolving names to match numeric grants: requests must not trigger lookups.
- Matching SDK policy in production: keep authority typed; policy rules are the independent test oracle.
- `warning:` prefix: restricted launches are normal, not credential failures.
- Rendering covered entries or composing grant commands: repository metadata must not read as approval text.
- Declaration-order storage: reordering should not create a conflict or steer notices.
- Treating grammar as a secret filter: a short LDH-shaped token is a valid name.

## Consequences

Requests add no authority, TLS interception, credential capture or provisioning.
Missing requests never block launch. Coverage remains syntactic and lookup-free.
Request values are publicly rendered metadata and **must not contain secrets**;
`sk-test-sensitivevalue` is grammatical and is printed, not redacted. This is
framing protection, not credential detection.

Amendment 2026-10-12 (#328): Claude/Codex/OpenCode/Pi defaults declare scoped
baseline requests, independently of credential proxy hosts; Copilot is pending
#340. [Endpoint evidence and maintenance](../default-tool-network-requests.md)
define the version/auth conditions and exclusions. Behavior is unchanged.
