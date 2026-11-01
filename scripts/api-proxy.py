#!/usr/bin/env python3
"""Host-side API proxy for the agent VM (NOTES: "Credentials without a separate gateway").

Listens on a Unix socket: Firecracker turns a guest connection to vsock CID 2 port P into a
connection to <uds_path>_P on the host. Takes plain HTTP from the guest, strips whatever credential
the guest sent, adds the real one, and forwards to https://api.anthropic.com over verified TLS.
Only allowlisted method+path pairs are forwarded, and only bodies without server-side tools or MCP
servers (see body_policy); everything else gets a 403 and a DENY log line.
Responses are relayed as they arrive (Claude streams server-sent events).

The credential is read from a file at startup and exists only in this process:
  --token-file FILE    Claude subscription OAuth token (from `claude setup-token`), sent as Bearer.
Headers and bodies are never logged; one line per request: verdict, method, path, status, bytes, time.

Usage: api-proxy.py --listen /path/vsock.sock_8080 --token-file ~/.config/lean-kernel/oauth-token
"""
import argparse
import http.client
import http.server
import json
import os
import socket
import socketserver
import ssl
import sys
import time

UPSTREAM = "api.anthropic.com"
ALLOW = {
    ("POST", "/v1/messages"),
    ("POST", "/v1/messages/count_tokens"),
}
OAUTH_BETA = "oauth-2025-04-20"
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
       "transfer-encoding", "upgrade", "host", "content-length"}
DROP_IN = HOP | {"authorization", "x-api-key", "accept-encoding", "cookie"}
MAX_BODY = 32 << 20
# Request fields that make Anthropic's servers reach out on the agent's behalf: server tools (web
# fetch/search, code execution, ...) and remote MCP servers. Any of them turns the API into a route
# to arbitrary hosts, e.g. a URL with data in its query string. Client tools, which the agent runs
# itself, have no "type" (or "custom"), so only those pass.
DENY_FIELDS = ("mcp_servers", "container")


def body_policy(body):
    """Return None if the request body may be forwarded, else the reason it may not."""
    try:
        req = json.loads(body)
    except ValueError:
        return "body is not JSON"
    if not isinstance(req, dict):
        return "body is not a JSON object"
    for k in DENY_FIELDS:
        if k in req:
            return f"field {k!r} not allowed"
    tools = req.get("tools") or []
    if not isinstance(tools, list):
        return "tools is not a list"
    for t in tools:
        typ = t.get("type") if isinstance(t, dict) else "?"
        if typ not in (None, "custom"):
            return f"server tool {typ!r} not allowed"
    return None

TOKEN = ""
TLS = ssl.create_default_context()
LOG = sys.stderr


def log(line):
    LOG.write(time.strftime("%H:%M:%S ") + line + "\n")
    LOG.flush()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "lean-agent-proxy"
    sys_version = ""

    def address_string(self):  # AF_UNIX peers have no address
        return "vsock"

    def log_message(self, fmt, *args):  # replaced by log() lines below
        pass

    def deny(self, code, msg):
        body = ('{"type":"error","error":{"type":"proxy_denied","message":"%s"}}' % msg).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def handle_any(self):
        t0 = time.monotonic()
        path_only = self.path.split("?", 1)[0]
        if not self.path.startswith("/") or (self.command, path_only) not in ALLOW:
            log(f"DENY  {self.command} {path_only}")
            return self.deny(403, "not on the proxy allowlist")
        length = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding") or length is None:
            log(f"DENY  {self.command} {path_only} (no Content-Length)")
            return self.deny(411, "Content-Length required")
        n = int(length)
        if n < 0 or n > MAX_BODY:
            log(f"DENY  {self.command} {path_only} (body {n} bytes)")
            return self.deny(413, "request body too large")
        body = self.rfile.read(n)
        why = body_policy(body)
        if why:
            log(f"DENY  {self.command} {path_only} ({why})")
            return self.deny(403, why)

        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP_IN}
        headers["Authorization"] = "Bearer " + TOKEN
        beta = [b.strip() for b in headers.pop("anthropic-beta", "").split(",") if b.strip()]
        if OAUTH_BETA not in beta:
            beta.append(OAUTH_BETA)
        headers["anthropic-beta"] = ",".join(beta)
        headers["Accept-Encoding"] = "identity"
        headers["Content-Length"] = str(len(body))

        up = http.client.HTTPSConnection(UPSTREAM, 443, context=TLS, timeout=600)
        sent = 0
        status = "-"
        try:
            up.request(self.command, self.path, body=body, headers=headers)
            resp = up.getresponse()
            status = resp.status
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in HOP:
                    self.send_header(k, v)
            clen = resp.getheader("Content-Length")
            chunked = clen is None
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            else:
                self.send_header("Content-Length", clen)
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                data = resp.read1(65536)
                if not data:
                    break
                sent += len(data)
                if chunked:
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                else:
                    self.wfile.write(data)
                self.wfile.flush()
            if chunked:
                self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError):
            status = f"{status} (guest hung up)"
        except Exception as e:  # upstream failure: tell the guest, never leak details of the request
            log(f"ERROR {self.command} {path_only}: {type(e).__name__}: {e}")
            if status == "-":
                return self.deny(502, "upstream request failed")
        finally:
            up.close()
            self.close_connection = True
        log(f"ALLOW {self.command} {path_only} -> {status} {sent}B {time.monotonic() - t0:.1f}s")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = handle_any


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    global TOKEN, LOG
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--listen", required=True, help="Unix socket path (<vsock uds_path>_<port>)")
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--log", help="append request log here as well as stderr")
    a = ap.parse_args()

    st = os.stat(a.token_file)
    if st.st_mode & 0o077:
        sys.exit(f"api-proxy: {a.token_file} is readable by group/others; chmod 600 it")
    with open(a.token_file) as f:
        TOKEN = f.read().strip()
    if not TOKEN or any(c.isspace() for c in TOKEN):
        sys.exit(f"api-proxy: {a.token_file} must contain exactly one token")
    if a.log:
        LOG = Tee(sys.stderr, open(a.log, "a"))

    try:
        os.unlink(a.listen)
    except FileNotFoundError:
        pass
    old = os.umask(0o077)
    srv = Server(a.listen, Handler)
    os.umask(old)
    log(f"api-proxy: {a.listen} -> https://{UPSTREAM} (allow: "
        + ", ".join(f"{m} {p}" for m, p in sorted(ALLOW)) + ")")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        try:
            os.unlink(a.listen)
        except FileNotFoundError:
            pass


class Tee:
    def __init__(self, *fs):
        self.fs = fs

    def write(self, s):
        for f in self.fs:
            f.write(s)

    def flush(self):
        for f in self.fs:
            f.flush()


if __name__ == "__main__":
    main()
