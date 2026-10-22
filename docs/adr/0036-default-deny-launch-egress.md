# ADR-0036: Default-deny launch egress

## Status

Accepted for [#302](https://github.com/gregwebs/agent-vm/issues/302), split **A1**.
Roadmap labels used below: **A1** = CLI address/group authority; **A2** =
persistent user-config authority; **C** = hostname allowances; **E** = release
integration and native platform evidence. Story numbers refer to that issue's
acceptance checklist.

The guard half of A2 is delivered by [ADR-0038](0038-config-dir-exposure-guard.md)
(#323). Amended by [ADR-0040](0040-persisted-user-network-authority.md): the user tier accepts verified `[network]`;
the project/built-in tiers still refuse. A1 describes CLI authority.

Supersedes ADR-0009's implicit Public grant. **Breaking change in 0.2.0**:
existing tool launches have no egress or DNS query authorization until a grant is
passed. `--allow-internet-egress` restores public internet and DNS for provider
CLIs; numeric allowances are an address-only alternative. **Hostnames were not
yet supported in A1; C arrives with
[ADR-0037](0037-hostname-egress-allowances.md)**, which adds TLS-only hostname
allowances on intercepted ports and amends this ADR where noted. See
[Ports & egress](../../USAGE.md#ports--egress) for the CLI grammar and DNS table;
[CONTEXT.md](../../CONTEXT.md#egress-authority) defines the terms.

## Decision

Build every tool-launch policy explicitly: default egress Deny, ingress Allow,
allow-only numeric rules followed by independent group rules. Internet grants
Public plus gateway DNS; LAN grants Private; host grants the sandbox gateway.
LAN/host never imply Public. Publishing ports never grants egress.
`NetworkPolicy::from_profiles` is deliberately not used: it authorizes DNS with
LAN, contrary to this boundary. `none()` also denies ingress, which would break
published ports. `setup`'s verification guest is outside this
policy builder and still uses the SDK Public+DNS default.

> Amended by #389: the removed temporary image-acquisition guest no longer
exists. `image refresh` performs native acquisition and boots no guest; only
setup's optional verification guest remains outside this policy.

```text
CLI grants → validated EgressAuthority → base policy → credential overlay → boot
                 │                          │
            before state              policy preserved
```

Apply the base policy even with no grants. SDK network defaults become dense
wire subdocuments, not new permissions. Independent full-object comparisons
pin effective non-policy defaults, including empty secrets/intercept arrays.
Credentials authorize substitution, not connections: their overlay must retain
the exact base policy, not just its rule count.

A1 refused both config tiers. Amended by [ADR-0040](0040-persisted-user-network-authority.md): the user tier accepts
verified `[network]`; the project/built-in tiers still refuse with
file/setting/tier diagnostics. Project config can never grant network authority.
Validation precedes mount preparation, credential capture and state creation;
the existing runtime version identity probe still occurs first.

## DNS costs and accepted deviations

- Host permission includes host-resolver query authorization. This permits data
  in queries to that resolver even without Public access; connection permission
  and resolver/rebind/platform checks still apply.
- LAN-only and numeric-only grants do not authorize DNS. Plain port-53 DNS to an
  allowed resolver IP remains NXDOMAIN in A1: accepted story-28 deviation under
  the no-vendored-change scope, tracked in
  [microsandbox #75](https://github.com/gregwebs/microsandbox/issues/75).
  DoH to an allowed IP or the internet grant is the recovery.
- Denial is prompt NXDOMAIN only when the DNS forwarder is available. Failure to
  read host DNS configuration can prevent initialization; queries then time out.
  A1 does not configure startup nameservers or claim native evidence for that path.
- Internet query authorization retains private-answer rebind protection. LAN or
  a covering local numeric rule **without a port** admits the answer. Source
  behavior accepts protocol-filtered, port-less rules (`tcp://`/`udp://`); a
  port-scoped rule does not qualify. The revision comment's wording says both
  port/protocol-filtered rules are ignored; this ADR records the narrower source
  behavior rather than claiming that broader restriction. [ADR-0037](0037-hostname-egress-allowances.md)
  carries the same eligibility rule forward for hostname allowances (its D4): a
  `Domain` rule never admits a private answer by itself.
- Host permission includes host-resolver query authorization, so an appended
  `deny_dns()` is unreachable behind the port-less `Group(Host)` rule and is not
  emitted. [ADR-0037](0037-hostname-egress-allowances.md) keeps this status quo.

## Grammar and proof boundary

Numeric allowances accept IP/CIDR, optional TCP/UDP scheme and optional canonical
port 1–65535. CIDR-plus-port and IPv6-plus-port require brackets. Bare IPv6 is
always an address. Canonicalization masks CIDR host bits and normalizes eligible
IPv4-mapped IPv6. Permissions are address-wide, never hostname-isolated. CIDRs match any address:
a covering CIDR such as IPv4 `100.64.0.0/10` or `0.0.0.0/0`, or IPv6 ULA
`fd00::/8`, `fc00::/7` or `::/0`, reaches host loopback services through the
sandbox gateway; a range covering link-local metadata
(e.g. `169.254.0.0/16` or `0.0.0.0/0`) reaches those endpoints too, subject to
its transport/port filters.

Four Verus kernels prove exhaustive scheme/offset correspondence, exact target
layout and error precedence, exact decimal port parsing, and independent group
decisions. Rust/std and `ipnetwork` address parsing/canonicalization, message
classification and SDK rule assembly remain trusted adapters, detailed in
[ADR-0018](0018-machine-checked-boundary-contracts.md). Neither these proofs nor
boot-free harness contracts prove native runtime enforcement.

## Admission and evidence

Runtime-identity/capability admission is deferred to E, including credential
injection and C's strict-hostname dependency. A1 may ship independently; existing
identity verification checks only a version string, not runtime capabilities or
binary identity. Story-34 combined enforcement, Linux+KVM and privately unsettable
platform-floor evidence are also E-owned deferrals, not A1 shipping gates. The
native macOS smoke/full harness is unexecuted; no guest-packet or native
enforcement evidence has been collected for this change.

All tool-launch guest programs, MCP servers and hooks share the policy. Project runtime-hook
failure aborts launch; image seed hooks retain their existing `; true` handling.
Host proxies carry only already-authorized connections, except that the ambient
host HTTP proxy resolves a CONNECT name itself; [ADR-0037](0037-hostname-egress-allowances.md)
refuses hostname launches while such a proxy would be selected. TLS interception
remains per port: missing TLS ClientHello/SNI fails closed even for numeric
destinations.

## Rejected alternatives

- Keep Public with an opt-out: ambient internet authority defeats the default.
- Use `from_profiles`: LAN would also open DNS.
- Add `deny_dns()` for host: contradicts the accepted host-resolver allowance and
  introduces order-dependent deny rules into an otherwise OR-like policy.
- Add `allow_dns()` for numeric allowances: opens query authority unrelated to
  the granted numeric connection scope; the accepted port-53 limitation is explicit.
- Add hostname or persistent config authority in A1: A2 (persistent config
  authority) is still deferred and needs its own implementation and protection.
  Hostname authority is delivered by [ADR-0037](0037-hostname-egress-allowances.md),
  not approximated here.
