#!/usr/bin/env python3
"""Host-side bridge for a VMware guest: AF_VSOCK (VMCI) -> api-proxy.py's Unix socket.

Firecracker hands the guest's vsock connection to a host Unix socket, which is where api-proxy.py
listens. VMware doesn't: the host sees an AF_VSOCK connection from the guest's CID. This accepts those
and relays each, byte for byte, to the proxy's Unix socket. It holds no credentials and parses nothing;
the proxy still does all policy. Only guests named with --allow-cid are served, since the CID is the one
thing that says which VM is calling (VMware assigns it, and a guest cannot choose its own; it is the
vmci0.id line in the .vmx once the VM has run).

Host needs the vsock and vmw_vsock_vmci_transport modules (VMware Workstation/Player load them with
vmci). Guest: AF_VSOCK to CID 2 port 8080 (kernel built with VMCI=1, configs/vmci.fragment).

Usage: vmci-bridge.py --allow-cid <vmci0.id> --upstream /path/vsock.sock_8080 [--port 8080]
It needs no root, only permission to connect to the proxy's socket. --allow-cid takes the .vmx value as
written, negative included (VMware writes the 32-bit CID signed; the kernel reports it unsigned).

Limits of the CID as an identity (it is all VMCI offers; Firecracker's per-VM socket has no equivalent):
  - It names a VM only while that VM runs. Power the VM off and another VM on this host whose .vmx sets the
    same vmci0.id is served in its place, with your token. So run the bridge (and the proxy) only for the
    life of the VM: start them before it, stop them when it powers off. Anyone who can edit a .vmx on this
    host can claim a CID.
  - Port 8080 is unprivileged: another local user can bind it first and receive the guest's requests (they
    carry no credential, but they are the guest's prompts). The bridge then fails to start with "address
    in use"; treat that as an alarm, not a nuisance. A port under 1024 needs CAP_NET_BIND_SERVICE to bind
    (--port, and the same port in the guest), which closes this.
"""
import argparse
import socket
import struct
import sys
import threading
import time

BUF = 64 * 1024
# How long the proxy's side may go silent before the bridge gives up on a connection. Must exceed
# api-proxy.py's own upstream timeout (600 s): a non-streaming request, or a stream paused in a long
# think, sends nothing back for minutes, and cutting it here would drop a reply the API still bills.
# The guest side has no bridge timeout: the proxy already closes a guest that idles (its --idle-timeout),
# and that close reaches the guest through this relay.
UPSTREAM_IDLE = 660
# How long a write to the guest may block. A guest that stops reading would otherwise hold its slot and
# two threads for good: the proxy gives up on it, but nothing here would notice. The proxy's own write
# timeout is its idle timeout (30 s).
GUEST_SEND_TIMEOUT = 30
# Log lines per minute. Every refused or failed connection logs one, and any VM on the host can make
# those at will, allow-listed or not; whatever keeps stderr must not grow at the guests' pace.
LOG_PER_MIN = 60


class LogLimit:
    def __init__(self, per_min):
        self.per_min, self.lock = per_min, threading.Lock()
        self.start, self.n, self.dropped = time.monotonic(), 0, 0

    def ok(self):
        """True if a line may be written now; also returns how many were dropped since the last one."""
        with self.lock:
            now = time.monotonic()
            if now - self.start >= 60:
                self.start, self.n = now, 0
            if self.per_min and self.n >= self.per_min:
                self.dropped += 1
                return False, 0
            self.n += 1
            dropped, self.dropped = self.dropped, 0
            return True, dropped


LOG_LIMIT = LogLimit(LOG_PER_MIN)


def log(msg, always=False):
    ok, dropped = LOG_LIMIT.ok()
    if not (ok or always):
        return
    if dropped:
        msg += f" ({dropped} earlier lines dropped: over {LOG_LIMIT.per_min}/min)"
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} vmci-bridge: {msg}", file=sys.stderr, flush=True)


def cid_u32(n):
    """A CID as the kernel reports it, from the signed or unsigned form (the .vmx writes vmci0.id signed)."""
    return n & 0xFFFFFFFF


def pump(src, dst, how=socket.SHUT_WR):
    """Copy src -> dst until EOF or error, then shut dst down (`how`: half-close by default, so the
    other direction can finish)."""
    try:
        while True:
            data = src.recv(BUF)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(how)
        except OSError:
            pass


def relay(guest, upstream_path, idle, send_timeout=GUEST_SEND_TIMEOUT):
    """Connect to the proxy and relay both ways. Returns when both directions are done.

    Guest -> proxy ends in a half-close, so the proxy can still finish its reply. Proxy -> guest ends by
    shutting the guest socket both ways: once the proxy has closed, nothing more can be relayed, and
    that also wakes the other thread if it is blocked reading a guest that went quiet."""
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        up.settimeout(5)
        up.connect(upstream_path)
        up.settimeout(idle)
        # Reads from the guest never time out (the proxy times an idle guest out, and its close ends this
        # relay); writes to it do. SO_SNDTIMEO, since settimeout() would apply to both.
        guest.settimeout(None)
        guest.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                         struct.pack("ll", int(send_timeout), int(send_timeout % 1 * 1_000_000)))
        t = threading.Thread(target=pump, args=(up, guest, socket.SHUT_RDWR), daemon=True)
        t.start()
        pump(guest, up)
        t.join()
    finally:
        up.close()
        guest.close()


class Bridge:
    def __init__(self, allow, upstream, max_conns=16, idle=UPSTREAM_IDLE, send_timeout=GUEST_SEND_TIMEOUT):
        self.allow = {cid_u32(c) for c in allow}
        self.upstream, self.idle, self.send_timeout = upstream, idle, send_timeout
        # A pool per allowed CID: one guest holding all of its slots can't shut the others out.
        self.slots = {c: threading.BoundedSemaphore(max_conns) for c in self.allow}
        self.max_conns = max_conns

    def handle(self, conn, cid):
        """Decide on one accepted connection from guest `cid`; returns True if it is being relayed."""
        slots = self.slots.get(cid)
        if slots is None:
            log(f"REFUSED cid={cid} not in allow list")
            conn.close()
            return False
        if not slots.acquire(blocking=False):
            log(f"LIMIT cid={cid} closed: {self.max_conns} already open")
            conn.close()
            return False

        def run():
            try:
                relay(conn, self.upstream, self.idle, self.send_timeout)
            except OSError as e:
                log(f"cid={cid} upstream error: {e}")
            finally:
                slots.release()

        threading.Thread(target=run, daemon=True).start()
        return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--allow-cid", type=int, action="append", required=True,
                    help="guest CID to serve: vmci0.id from the .vmx, as written (repeatable; required, so no VM is served by default)")
    ap.add_argument("--upstream", required=True, help="api-proxy.py's Unix socket (<vsock uds_path>_<port>)")
    ap.add_argument("--port", type=int, default=8080, help="vsock port the guest connects to (default 8080)")
    ap.add_argument("--max-connections", type=int, default=16, help="per allowed CID (default 16)")
    ap.add_argument("--upstream-idle-timeout", type=float, default=UPSTREAM_IDLE,
                    help=f"seconds the proxy side may stay silent (default {UPSTREAM_IDLE}; keep it above api-proxy's 600)")
    a = ap.parse_args()
    if not hasattr(socket, "AF_VSOCK"):
        sys.exit("vmci-bridge: this Python has no AF_VSOCK")
    if any(not -2**31 <= c < 2**32 for c in a.allow_cid):
        sys.exit("vmci-bridge: a CID is a 32-bit number")
    if any(cid_u32(c) < 3 or cid_u32(c) == 0xFFFFFFFF for c in a.allow_cid):
        sys.exit("vmci-bridge: CIDs 0-2 and -1 are reserved (hypervisor, local, host, any); guests start at 3")
    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    try:
        srv.bind((socket.VMADDR_CID_ANY, a.port))
    except OSError as e:
        sys.exit(f"vmci-bridge: can't bind vsock port {a.port}: {e}. If it is in use, something else on this "
                 "host is receiving the guest's requests: find out what before starting the VM")
    srv.listen(128)
    b = Bridge(a.allow_cid, a.upstream, a.max_connections, a.upstream_idle_timeout)
    log(f"vsock port {a.port} -> {a.upstream} (allow cid {sorted(b.allow)}, max {a.max_connections} each)", always=True)
    while True:
        try:
            conn, (cid, _port) = srv.accept()
        except OSError as e:
            # EMFILE, ECONNABORTED, ENOBUFS...: one failed accept must not end the bridge and cut the guest off.
            log(f"accept failed: {e}")
            time.sleep(0.1)
            continue
        b.handle(conn, cid_u32(cid))


if __name__ == "__main__":
    main()
