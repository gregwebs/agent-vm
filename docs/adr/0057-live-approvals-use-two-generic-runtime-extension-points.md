# ADR-0057: Live approvals use two generic runtime extension points

## Status

Accepted. This is the runtime boundary for [Live network approvals on
macOS](https://github.com/gregwebs/agent-vm/issues/501). Both extension points
have landed in the fork: [record egress
refusals](https://github.com/gregwebs/agent-vm/issues/502) as refusal log out, and
[replace a running sandbox's network
policy](https://github.com/gregwebs/agent-vm/issues/503) as policy replace in.
agent-vm calls neither; the `vendor/microsandbox` pin (fork main `dee2001c`,
0.7.13) carries both, and #501 slice 1 adds the first reader of the refusal log.

## Decision

The runtime (`msb`, in the `gregwebs/microsandbox` fork) gains only two extension
points. Neither knows about allowances.

1. **Refusal log, out.** `msb` writes a JSONL record for each egress denial and secret
   violation. Each record holds facts only: the destination, the guest-supplied name
   evidence and its source, the layer (tenant or platform), the decision site and the
   policy revision. The launcher follows the file through the SDK's existing log
   stream. `msb` rate-limits only to protect its disk.
2. **Policy replace, in.** A control op replaces the running sandbox's whole tenant
   policy and replies with a monotonic revision. Every policy reader loads it at
   decision time, and the platform floor is unreachable through it.

agent-vm owns everything else:
- session and project allowances, and composing the full policy it sends;
- refusal kinds, IDs, coalescing, and the durable project refusal log;
- interception-aware validation (ADR-0037);
- the fallback to next-launch grants when `msb` lacks the capability.

## Considered options

- **Delegated decisions.** `msb` would ask the launcher about each unmatched flow.
  Rejected: it puts an IPC round trip on every such connection and DNS query, needs a
  new reverse channel, and forces `msb` to pick a default when the launcher hangs or
  dies.
- **A watched policy file.** Rejected: it has no acknowledgement, so the CLI could not
  confirm a revoke.
- **A control-socket event stream.** Rejected: control is request/response today. A
  log file reuses tested cursor and rotation machinery, and outlives a crashed
  launcher.

## Consequences

- Both extension points are generic enough to offer upstream. Nothing in agent-vm
  depends on upstream accepting them.
- A replace affects new flows only. Open connections keep the revision they were
  admitted under, which is why the revoke guarantee covers new connections only.
- `msb`'s refusal file lives as long as the sandbox, so the launcher copies records
  into agent-vm's host-only project refusal log.
