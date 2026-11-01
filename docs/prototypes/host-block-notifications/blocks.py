#!/usr/bin/env python3
"""PROTOTYPE: what a click opens. Shows one session's blocks; approves nothing."""
import json
import sys

PROTO = "/tmp/PROTOTYPE-agent-vm-blocks"
KIND = {"network": "network", "locked": "policy lock", "credential": "credential/GitHub"}

session = sys.argv[1]
rows = {}
try:
    with open(f"{PROTO}/{session}.jsonl") as f:
        for line in f:
            e = json.loads(line)
            dest = e["dest"] + (f':{e["port"]}' if e.get("port") and e["port"] != 443 else "")
            r = rows.setdefault((e["kind"], dest), {"n": 0, "first": e["time"], "source": e["source"], "project": e["project"]})
            r["n"] += 1
            r["last"] = e["time"]
except FileNotFoundError:
    sys.exit(f"no blocks recorded for {session} (session ended or prototype state wiped)")

project = next(iter(rows.values()))["project"]
print(f"\n  agent-vm blocks: project {project}, session {session}\n")
print(f"  {'KIND':<18} {'DESTINATION':<32} {'COUNT':>5}  {'FIRST':>8}  {'LAST':>8}  SOURCE")
for (kind, dest), r in rows.items():
    print(f"  {KIND[kind]:<18} {dest[:32]:<32} {r['n']:>5}  {r['first']:>8}  {r['last']:>8}  {r['source']}")
print("\n  Hostnames come from the guest and are shown, not trusted.")
print("  Nothing here was allowed. To allow a network block (not built yet):")
for (kind, dest), _ in rows.items():
    if kind == "network":
        print(f"    agent-vm allow {dest} --session {session.rsplit('-', 1)[-1]}    # or --project")
print("  Policy locks and credential/GitHub refusals can't be allowed from agent-vm.\n")
