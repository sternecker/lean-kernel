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

Usage: vmci-bridge.py --allow-cid 3 --upstream /path/vsock.sock_8080 [--port 8080]
It needs no root, only permission to connect to the proxy's socket.
"""
import argparse
import socket
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


def log(msg):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} vmci-bridge: {msg}", file=sys.stderr, flush=True)


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


def relay(guest, upstream_path, idle):
    """Connect to the proxy and relay both ways. Returns when both directions are done.

    Guest -> proxy ends in a half-close, so the proxy can still finish its reply. Proxy -> guest ends by
    shutting the guest socket both ways: once the proxy has closed, nothing more can be relayed, and
    that also wakes the other thread if it is blocked reading a guest that went quiet."""
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        up.settimeout(5)
        up.connect(upstream_path)
        up.settimeout(idle)
        guest.settimeout(None)
        t = threading.Thread(target=pump, args=(up, guest, socket.SHUT_RDWR), daemon=True)
        t.start()
        pump(guest, up)
        t.join()
    finally:
        up.close()
        guest.close()


class Bridge:
    def __init__(self, allow, upstream, max_conns=16, idle=UPSTREAM_IDLE):
        self.allow, self.upstream, self.idle = set(allow), upstream, idle
        self.slots = threading.BoundedSemaphore(max_conns)
        self.max_conns = max_conns

    def handle(self, conn, cid):
        """Decide on one accepted connection from guest `cid`; returns True if it is being relayed."""
        if cid not in self.allow:
            log(f"REFUSED cid={cid} not in allow list")
            conn.close()
            return False
        if not self.slots.acquire(blocking=False):
            log(f"LIMIT cid={cid} closed: {self.max_conns} already open")
            conn.close()
            return False

        def run():
            try:
                relay(conn, self.upstream, self.idle)
            except OSError as e:
                log(f"cid={cid} upstream error: {e}")
            finally:
                self.slots.release()

        threading.Thread(target=run, daemon=True).start()
        return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--allow-cid", type=int, action="append", required=True,
                    help="guest CID to serve (repeatable; required, so no VM is served by default)")
    ap.add_argument("--upstream", required=True, help="api-proxy.py's Unix socket (<vsock uds_path>_<port>)")
    ap.add_argument("--port", type=int, default=8080, help="vsock port the guest connects to (default 8080)")
    ap.add_argument("--max-connections", type=int, default=16)
    ap.add_argument("--upstream-idle-timeout", type=float, default=UPSTREAM_IDLE,
                    help=f"seconds the proxy side may stay silent (default {UPSTREAM_IDLE}; keep it above api-proxy's 600)")
    a = ap.parse_args()
    if not hasattr(socket, "AF_VSOCK"):
        sys.exit("vmci-bridge: this Python has no AF_VSOCK")
    if any(c < 3 for c in a.allow_cid):
        sys.exit("vmci-bridge: CIDs 0-2 are reserved (hypervisor, local, host); guests start at 3")
    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    srv.bind((socket.VMADDR_CID_ANY, a.port))
    srv.listen(128)
    b = Bridge(a.allow_cid, a.upstream, a.max_connections, a.upstream_idle_timeout)
    log(f"vsock port {a.port} -> {a.upstream} (allow cid {sorted(b.allow)}, max {a.max_connections})")
    while True:
        conn, (cid, _port) = srv.accept()
        b.handle(conn, cid)


if __name__ == "__main__":
    main()
