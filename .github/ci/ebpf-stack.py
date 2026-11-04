#!/usr/bin/env python3
"""Report per-function BPF stack frames and the deepest call chain.

The kernel verifier bounds the *cumulative* stack of a BPF-to-BPF call chain,
not each function's frame. Reading that from a disassembly keeps the 6.6
porting loop short: the object is small and the check is exact.
"""

import re
import sys

DIS, REL = sys.argv[1], sys.argv[2]

depth = {}
calls = {}
func_at = {}
cur = None

for line in open(DIS):
    m = re.match(r'^([0-9a-f]+) <(.+)>:', line)
    if m:
        addr, name = int(m.group(1), 16), m.group(2)
        func_at[addr] = name
        depth.setdefault(name, 0)
        calls.setdefault(name, [])
        cur = name
        continue
    if cur is None:
        continue
    mi = re.match(r'^\s*([0-9a-f]+):\s*(\S+)\s*(.*)$', line)
    if not mi:
        continue
    at, mnem, ops = int(mi.group(1), 16), mi.group(2), mi.group(3)
    for off in re.findall(r'r10 - 0x([0-9a-f]+)', ops):
        depth[cur] = max(depth[cur], int(off, 16))
    if mnem == 'call':
        t = re.match(r'^(-?0x[0-9a-f]+)', ops.strip())
        if t:
            calls[cur].append((at, int(t.group(1), 16) if t.group(1) != '-0x0' else 0))

rel = {}
for line in open(REL):
    m = re.match(r'^([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+(.+)$', line)
    if m:
        rel[int(m.group(1), 16)] = m.group(2).strip().split()[-1]

inside = sorted(func_at)


def resolve(at, imm):
    if imm:
        target = at + 8 + imm * 8
        for a in inside:
            if a == target:
                return func_at[a]
        return None
    name = rel.get(at)
    if not name:
        return None
    return name.split('+')[0]


graph = {}
for fn, sites in calls.items():
    targets = []
    for at, imm in sites:
        callee = resolve(at, imm)
        if callee in depth:
            targets.append(callee)
    graph[fn] = targets

ENTRIES = (
    'lan_ingress_l2', 'lan_ingress_l3', 'wan_egress_l2', 'wan_egress_l3',
    'honk_tcp_passive', 'dae0_ingress', 'dae0peer_ingress',
    'tproxy_wan_cg_sock_create', 'tproxy_wan_cg_sendmsg4',
)

best = {'total': 0, 'chain': []}


def walk(fn, chain, on_path):
    chain = chain + [fn]
    total = sum(depth[f] for f in chain)
    if total > best['total']:
        best['total'], best['chain'] = total, list(chain)
    if len(chain) > 10:
        return
    for callee in graph.get(fn, []):
        if callee in on_path:
            continue
        walk(callee, chain, on_path | {fn})


for entry in ENTRIES:
    if entry in depth:
        walk(entry, [], set())
for fn in depth:
    walk(fn, [], set())

print('stack_frame  function')
for name, d in sorted(depth.items(), key=lambda kv: -kv[1])[:12]:
    print(f'{d:>11}  {name}')

print()
print(f'deepest chain = {best["total"]} bytes over {len(best["chain"])} frames (limit 512)')
for f in best['chain']:
    print(f'  {depth[f]:>4}  {f}')

print()
print('call edges from those frames:')
for f in best['chain']:
    edges = sorted(set(graph.get(f, [])))
    if edges:
        print(f'  {f} -> {", ".join(edges)}')