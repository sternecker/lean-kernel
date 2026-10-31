#!/usr/bin/env python3
"""List which x86_64 syscalls the built kernel actually has, from out/vmlinux (no boot needed).

Reads sys_call_table out of vmlinux and resolves each slot against System.map. A slot is
compiled out when it points at sys_ni_syscall, or at a COND_SYSCALL stub: those stubs' __cfi_
prefix symbols are weak (W) in System.map, real handlers' are T.

Blind spot: a handler that is compiled in but returns -ENOSYS by config (iopl/ioperm with
X86_IOPL_IOPERM=n) looks present here. make test checks runtime behaviour.

Usage: syscalls.py VMLINUX SYSTEM_MAP SYSCALL_64_TBL OUT_TXT
"""
import struct
import sys

vmlinux, system_map, tbl, out_txt = sys.argv[1:5]

addr_name, sym_type = {}, {}
for line in open(system_map):
    a, t, n = line.split()[:3]
    addr_name.setdefault(int(a, 16), n)
    sym_type[n] = t

names = {}
for line in open(tbl):
    f = line.split()
    if len(f) >= 3 and not line.startswith('#') and f[1] in ('common', '64'):
        names[int(f[0])] = f[2]

table = next(a for a, n in addr_name.items() if n == 'sys_call_table')
data = open(vmlinux, 'rb').read()
shoff, = struct.unpack_from('<Q', data, 0x28)
shentsize, shnum = struct.unpack_from('<HH', data, 0x3A)
base = None
for i in range(shnum):
    addr, off, size = struct.unpack_from('<QQQ', data, shoff + i * shentsize + 0x10)
    if addr <= table < addr + size:
        base = off + (table - addr)
        break
if base is None:
    sys.exit('sys_call_table not found in any vmlinux section')

present, absent = [], []
for nr in sorted(names):
    ptr, = struct.unpack_from('<Q', data, base + 8 * nr)
    target = addr_name.get(ptr, hex(ptr))
    stub = 'ni_syscall' in target or sym_type.get('__cfi_' + target) == 'W'
    (absent if stub else present).append((nr, names[nr]))

with open(out_txt, 'w') as f:
    for nr, n in present:
        f.write(f'present {nr} {n}\n')
    for nr, n in absent:
        f.write(f'absent {nr} {n}\n')

print(f'{len(present)} present, {len(absent)} compiled out (of {len(names)} x86_64 syscalls)')
print('compiled out: ' + ' '.join(n for _, n in absent))
print(f'full list: {out_txt}')
