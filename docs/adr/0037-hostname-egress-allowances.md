# ADR-0037: Hostname egress allowances — TLS on intercepted ports only

## Status

Accepted. Implementation decision for [agent-vm
#306](https://github.com/gregwebs/agent-vm/issues/306), slice 2 of [agent-vm
#302](https://github.com/gregwebs/agent-vm/issues/302); slice 1 (A1) is
[ADR-0036](0036-default-deny-launch-egress.md). Amends
[ADR-0036](0036-default-deny-launch-egress.md) and
[ADR-0018](0018-machine-checked-boundary-contracts.md). Follow-ups owned by
[#307](https://github.com/gregwebs/agent-vm/issues/307) and
[#308](https://github.com/gregwebs/agent-vm/issues/308).

The #307 follow-ups are delivered by
[ADR-0039](0039-non-authoritative-tool-network-requests.md). Operational TLS
client requirements live in [USAGE](../../USAGE.md#tls-client-requirements).

## Context

A1 ([ADR-0036](0036-default-deny-launch-egress.md)) made tool-launch egress
default-deny with numeric IP/CIDR and group grants only; hostname allowances were
rejected outright. The provider CLIs this launcher exists for talk to a small,
stable set of names, so "reach `api.example.com`" is the grant a user actually
wants, and A1 cannot express it without widening to a covering CIDR that also
authorizes unrelated services and, often, the private fixture LAN.

The runtime already carries the machinery for a name-scoped grant. A `Domain`
allow rule never authorizes opaque bytes: on a TLS-intercepted port the guest's
ClientHello SNI must equal the rule name **and** a DNS-cache binding must tie the
guest-dialed IP to that name; the runtime then terminates TLS with a per-sandbox
CA and re-originates to the real server, verifying its certificate for the SNI.
This ADR accepts hostname allowances onto that machinery without a vendored
runtime change — under conditions agent-vm itself must establish and test.

## Decision

A hostname allowance covers **TLS on intercepted ports only**. It emits a
`Domain(name)` allow rule with `protocols = [Tcp]` and the launch's intercepted
ports. `tcp://HOST:PORT` adds `PORT` to the intercepted ports. A bare `HOST`
means the intercepted ports (443 by default) — never all ports. Plain HTTP to a
hostname is not supported. Emitting no deny rules and ordering every numeric and
group rule **before** the `Domain` rules makes first-match evaluation behave like
an OR: a hostname rule can neither veto nor shadow numeric permission.

### Conditions C1–C8

The "no runtime change" premise holds only when all of these hold. Each is a
test in the implementation's verification plan, and a violation is a refused
input or a defect, not a documented gap.

| # | Condition | Why |
|---|---|---|
| C1 | `tls.enabled = true` whenever a hostname allowance exists | Without TLS, port 443 reaches the plain `TcpProxy`. Under strict mode an SNI-bearing hostname flow there is denied by `strict_hostname_allow_is_opaque`, so the rule is dead. Interception is what routes the flow to the SNI- and cache-checked path. |
| C2 | Every `Domain` rule port ∈ `tls.intercepted_ports`, and `ports` is **non-empty** | Empty `ports` means all ports, which would put `Domain` rules on non-intercepted ports where `TcpProxy` + `CacheOnly` authorizes client-first opaque bytes on a DNS-cache hit alone. |
| C3 | `Domain` rule `protocols = [Tcp]` | UDP relay and DNS upstream decisions use `CacheOnly`; a protocol-less rule would authorize UDP on a cache hit. |
| C4 | `Domain` rules come after every numeric/group rule; no deny rules | First match wins, so the policy acts as an OR; hostname strictness cannot veto numeric permission. |
| C5 | Hostname ports are never 53 or 853 | Interception precedes the DNS dispatch branches, so intercepting them would hijack guest DNS-over-TCP/DoT. Refusing them preserves DNS dispatch; it does not close a hole. |
| C6 | Hostname ≠ `host.microsandbox.internal` | The forwarder synthesizes the alias answer without caching it, so the rule would be dead; a cached answer would be a host-loopback grant in disguise. Use `--allow-host`. |
| C7 | `udp://HOST` refused | UDP has no hostname evidence. UDP can be allowed only by explicit IP/CIDR permission. |
| C8 | No hostname allowance when the ambient host HTTP proxy connector would be used | The proxy CONNECTs to the SNI name and resolves it itself, so the checked IP ≠ the dialed IP (§ *Runtime limitations*). Refused before launch. |

### Grammar

`--allow-egress` accepts `HOST`, `tcp://HOST`, `tcp://HOST:PORT` and
scheme-less `HOST:PORT` (equal to `tcp://HOST:PORT`). `HOST` is ASCII and
case-insensitive, canonicalized to lowercase, with at most one terminal dot,
which is stripped. It must be one or more LDH labels (the shared kernel) and its
**final label must not be numeric** — all digits, or `0x` plus lowercase hex —
which rejects inet_aton forms such as `1234`, `1.2.3`, `127.1` and `0x7f.1`.
Wildcards, leading dots, userinfo, path, query, fragment, brackets, non-ASCII
(an A-label is required) and the host alias are refused, each with fixed text.

An exact single-label name (`build`) authorizes exactly that DNS name;
search-domain expansion is not implied, so a guest stub that appends a search
suffix queries a different name and gets NXDOMAIN. Canonical display is `HOST`
or `tcp://HOST:PORT`.

### Ports and cross-host widening

`hostname_ports` is `{443} ∪ {PORT | any tcp://HOST:PORT}`, **global to the
launch**. A bare `HOST` (or `tcp://HOST`) gets all of them; `tcp://HOST:PORT`
gets `PORT`, and several entries for one host union. Credential-only ports never
widen hostname rules — credentials authorize substitution, not connections
(ADR-0036). The consequence is **cross-host widening**: adding
`tcp://git.corp.example:8443` widens every bare hostname to 8443 and makes 8443
TLS-only for **every** destination. The per-hostname launch notice prints each
rule's effective ports; `tcp://host:80` is accepted, and its notice and
documentation state that port 80 then becomes TLS-only for every destination.

### DNS

`allow_dns()` is **not** emitted when only hostnames are allowed — a `Domain`
rule authorizes its own lookups. It is emitted with `--allow-internet-egress`.
With `--allow-host`, host access includes the host resolver (the A1 status quo,
re-documented in ADR-0036); an appended `deny_dns()` would be unreachable behind
the port-less `Group(Host)` rule and is not emitted.

A hostname resolving to a **private** address still needs answer eligibility
beyond the `Domain` rule: a port-less local CIDR or group allowance
(`--allow-lan`, or `udp://CIDR` with no port), because private-answer
eligibility ignores **port-scoped** rules and `Domain` rules never qualify. A
port-less protocol-filtered rule (`tcp://`/`udp://CIDR`) **does** qualify when
the protocol matches, matching ADR-0036's narrower source behavior (D4 below).

## Runtime limitations and residual side effects

These are honest consequences of the current runtime, not hostname escapes. No
runtime change is made in this slice.

**D1 — plain-text framing on numeric/group flows once any hostname rule
exists.** `enforce_http_authority = network_policy.has_domain_rules()`. For a
numeric/group-authorized flow on a non-intercepted port the deferred peek does
not run, the upstream socket is dialed before classification, and the first
flight is classified. If it is not TLS, the plain-HTTP policy handler is
installed. The guest→server stream then behaves as follows:

- **Valid HTTP/1 heads:** a missing `Host` or multiple `Host` headers are
  **blocked**. The `Host` *value* is evaluated against the guest destination,
  where the numeric/group rule matches first (C4), so the value is never vetoed.
- **Printable non-HTTP bytes that contain a header boundary `\r\n\r\n`** are
  parsed as an HTTP/1 head; an invalid request line, or a version other than
  `HTTP/1.x`, is **blocked**.
  - Printable bytes *without* a boundary that look like an HTTP request prefix
    are buffered up to `MAX_HTTP_HEADER_BYTES`, then blocked.
  - So plain-text protocols (SMTP DATA, IMAP literals, Redis inline, IRC, …)
    **can be blocked**, including mid-stream, whenever a chunk is parsed as a
    head.
- **Conclusively binary first flights** go to `scan_opaque`, which latches
  `opaque` so later bytes pass unchanged; the exception is a prefix that "might
  be HTTP", which is blocked.
- **Server-first protocols** are not stalled: the socket is already open, so the
  banner relays while the handler waits for client bytes. The client's later
  printable bytes are subject to the rules above.

D1 narrows what numeric grants carry and never widens what hostname rules
authorize. It is documented compatibility behaviour for this slice; a runtime
fix ("apply authority enforcement only when the flow's first match is a hostname
rule") is a separately scoped, optional microsandbox issue.

**D2 — interception is per-port and global.** Credential launches already pay
this on 443; hostnames impose it on zero-provision launches and on every port
any hostname entry adds. See [TLS client requirements](../../USAGE.md#tls-client-requirements)
for client-side requirements.

**D3 — cache TTL.** Bindings expire; this is an accepted runtime limitation.
See [TLS client requirements](../../USAGE.md#tls-client-requirements) for client advice.

**D4 — private answers.** A `Domain` rule never admits a private or reserved
answer by itself. It needs `--allow-lan` or a **port-less** local numeric
allowance: a bare or `tcp://` CIDR admits the answer and authorizes the address
wide, while a port-less `udp://CIDR` admits it **without** authorizing TCP,
giving name-isolated TCP authority.

**Ambient host HTTP proxy (C8).** The runtime installs
`HostHttpProxyConnector::from_env()` unless an explicit `outbound_proxy` is
configured; agent-vm sets none. The TLS path passes the SNI as the CONNECT
`server_name`, so the *proxy* resolves the hostname, while policy and rebind
checks ran against the guest's cached answer. The dialed address can therefore
differ from the checked one, including a private address the private-answer rule
would have refused. Name evidence is unaffected (SNI equality, the binding to
the guest-dialed IP, and upstream certificate verification through the tunnel).
Hostname launches therefore refuse a selected host HTTP proxy before launch,
with fixed text; `NO_PROXY=*` is the only exemption (per-name `NO_PROXY` entries
do not lift the refusal — mirroring their suffix semantics would be a second
drift surface, and the refusal fails closed). This runtime limitation already
exists, unchanged, for credential and `--publish` launches in A1; it is a #308 /
microsandbox follow-up.

## Trusted vs proved

Three Verus kernels back this boundary (see
[ADR-0018](0018-machine-checked-boundary-contracts.md) for the verified-surface
rows): the shared LDH byte kernel (`dns_name::ldh_host_bytes`, moved out of
`credential_yaml` so network permission does not depend on credential parsing),
`egress_hostname::egress_hostname_bytes` (single labels accepted, numeric-final
labels rejected, with the last-dot uniqueness lemma discharging the existential)
and `hostname_scope` (UDP > bracketed > DNS-port precedence, exact port
preservation).

Trusted adapters: canonicalization, the alias comparison and
`DomainName::from_str`; the `InterceptedPorts` union and `domain_rules`
assembly; `observe_host_proxy`, a hand mirror of the vendored selection rule;
and the vendored private-answer eligibility predicate
(`evaluate_explicit_egress_ip`), which is crate-private with no public seam. The
independent unit oracle compares our serialized rule shape against the runtime's
documented input contract. The runtime's own forwarder caller and its
`rebind_filter_*` tests are the other independent implementation evidence.

Neither the proofs nor the boot-free harness contracts prove native runtime
enforcement. The intended native evidence for the private-answer rule is the RB2
rows, but they are not available on the macOS reference host: the guest forwarder
returns no response for a private-answer name
([gregwebs/microsandbox#76](https://github.com/gregwebs/microsandbox/issues/76)),
including rows whose expected answer is the forwarder's synthesized NXDOMAIN. RB1
and the HN rows are NOT RUN there for the same reason. The per-run status is
recorded in the #306 pull request; the consequence stated here is that the
name×port matrix and the RB2 eligibility rows have **no native evidence** in that
environment and rest on the boot-free runtime differential and the structural
rule-shape invariant.

## Rejected alternatives

- **Plain-HTTP hostname rules.** There is no name evidence for opaque bytes; the
  strict path denies them, and `strict_hostname_allow_is_opaque` keeps that
  closed. Refused rather than approximated.
- **`Domain` rules on all ports.** Reopens the A1 hole: `CacheOnly` on a
  non-intercepted port authorizes client-first opaque bytes on a cache hit (C2).
- **Protocol-less `Domain` rules.** Would authorize UDP on a cache hit (C3).
- **`deny_dns()` with `--allow-host`.** Unreachable behind the port-less
  `Group(Host)` rule and introduces an order-dependent deny rule (C4).
- **Accepting ports 53/853.** Interception would hijack guest DNS dispatch (C5).
- **Accepting the host alias.** A dead rule that would be a host-loopback grant
  in disguise if ever cached (C6).
- **Widening bare names to credential ports.** Credentials authorize
  substitution, not connections (ADR-0036).
- **Suffix/wildcard rules.** The runtime's suffix rules carry a single-label
  restriction and a different evidence story; exact names are the enforceable
  unit here.
- **A ≥2-label rule.** Single-label exact names are enforceable; requiring two
  labels would reject the legitimate internal names the runtime supports.
- **Honouring per-name `NO_PROXY`.** A second mirror of vendored suffix
  semantics; the conservative refusal fails closed.
- **Routing hostname flows through the ambient proxy anyway.** The proxy would
  resolve the name, so the checked address would not be the dialed one (C8).

## Consequences

A zero-provision hostname launch enables TLS interception, which installs the
sandbox CA in the guest trust store and turns the launch's intercepted ports
TLS-only globally (D2). Users who need only address-only reach should keep
numeric grants, which stay plain TCP. The window in which name-isolated
authority needs an extra port-less local allowance for private answers (D4) is a
documented cost, not a silent widening. `--allow-egress api.example.com` becomes
the narrow alternative to `--allow-internet-egress` for provider CLIs.
