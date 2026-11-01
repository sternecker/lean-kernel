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
  --token-fd N         the same token, read from an inherited fd (the jail wrapper pipes it in, so
                       the proxy's own user never needs access to the file).
Headers and bodies are never logged; one line per request: verdict, method, path, status, bytes, time,
and for messages the tokens used and the running totals.

Budget, per proxy process (one VM session); 0 means unlimited. Over budget: 403 proxy_budget_exhausted.
Over the rate: 429 with Retry-After, which Claude Code backs off on. Totals are counted from the usage
the API reports, so the request in flight when a budget runs out can overshoot it once.
  --max-requests N       requests forwarded (default 500)
  --max-input-tokens N   input tokens, cache reads and writes included (default 50,000,000)
  --max-output-tokens N  output tokens (default 1,000,000)
  --rpm N                requests per rolling minute (default 60)
  --models LIST          comma-separated allowed models, trailing * is a prefix (default: any)

Usage: api-proxy.py --listen /path/vsock.sock_8080 --token-file ~/.config/lean-kernel/oauth-token
"""
import argparse
import http.client
import http.server
import json
import signal
import threading
from collections import deque
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
    """Return (reason, request): reason is None if the body may be forwarded."""
    try:
        req = json.loads(body)
    except ValueError:
        return "body is not JSON", None
    if not isinstance(req, dict):
        return "body is not a JSON object", None
    for k in DENY_FIELDS:
        if k in req:
            return f"field {k!r} not allowed", req
    tools = req.get("tools") or []
    if not isinstance(tools, list):
        return "tools is not a list", req
    for t in tools:
        typ = t.get("type") if isinstance(t, dict) else "?"
        if typ not in (None, "custom"):
            return f"server tool {typ!r} not allowed", req
    return None, req


class Budget:
    """Per-session limits. admit() before forwarding, charge() with the usage the API reported."""

    def __init__(self, max_requests, max_input, max_output, rpm, models):
        self.max_requests, self.max_input, self.max_output, self.rpm = max_requests, max_input, max_output, rpm
        self.models = [m for m in models.split(",") if m] if models else []
        self.lock = threading.Lock()
        self.requests = self.inp = self.out = self.denied = 0
        self.recent = deque()

    def model_ok(self, model):
        if not self.models:
            return True
        return any(model == m or (m.endswith("*") and model.startswith(m[:-1])) for m in self.models)

    def admit(self, model):
        """Return None to forward, else (status, error type, message)."""
        with self.lock:
            if not isinstance(model, str) or not self.model_ok(model):
                why = (403, "proxy_denied", f"model {model!r} not allowed")
            elif self.max_requests and self.requests >= self.max_requests:
                why = (403, "proxy_budget_exhausted", f"request budget used up ({self.max_requests})")
            elif self.max_input and self.inp >= self.max_input:
                why = (403, "proxy_budget_exhausted", f"input token budget used up ({self.max_input})")
            elif self.max_output and self.out >= self.max_output:
                why = (403, "proxy_budget_exhausted", f"output token budget used up ({self.max_output})")
            else:
                now = time.monotonic()
                while self.recent and now - self.recent[0] > 60:
                    self.recent.popleft()
                if self.rpm and len(self.recent) >= self.rpm:
                    why = (429, "rate_limit_error", f"proxy rate limit {self.rpm}/min")
                else:
                    self.requests += 1
                    self.recent.append(now)
                    return None
            self.denied += 1
            return why

    def charge(self, inp, out):
        with self.lock:
            self.inp += inp
            self.out += out
            return self.inp, self.out

    def summary(self):
        with self.lock:
            return (f"session total: {self.requests} requests forwarded, {self.denied} refused, "
                    f"{self.inp} input tokens, {self.out} output tokens")


class Usage:
    """Token usage from a /v1/messages response: SSE stream (message_start, message_delta) or JSON."""

    def __init__(self, content_type):
        self.sse = "text/event-stream" in (content_type or "")
        self.buf = b""
        self.inp = self.out = 0

    def _take(self, u):
        if not isinstance(u, dict):
            return
        i = sum(u.get(k) or 0 for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"))
        self.inp = max(self.inp, i)
        self.out = max(self.out, u.get("output_tokens") or 0)

    def feed(self, data):
        self.buf += data
        if not self.sse:
            self.buf = self.buf[: 8 << 20]
            return
        *lines, self.buf = self.buf.split(b"\n")
        for line in lines:
            if not line.startswith(b"data:"):
                continue
            try:
                ev = json.loads(line[5:])
            except ValueError:
                continue
            if ev.get("type") == "message_start":
                self._take((ev.get("message") or {}).get("usage"))
            elif ev.get("type") == "message_delta":
                self._take(ev.get("usage"))

    def finish(self):
        if not self.sse:
            try:
                self._take(json.loads(self.buf).get("usage"))
            except (ValueError, AttributeError):
                pass
        return self.inp, self.out

TOKEN = ""
# --upstream-addr: connect to these addresses instead of resolving UPSTREAM, still verifying TLS for
# UPSTREAM. The jail wrapper resolves the name once and lets this proxy's uid reach only those
# addresses on 443 (nftables), so the proxy needs no DNS and can't reach anything else.
ADDRS = []


class UpstreamConnection(http.client.HTTPSConnection):
    def connect(self):
        if not ADDRS:
            return super().connect()
        err = None
        for ip in ADDRS:
            try:
                raw = socket.create_connection((ip, self.port), self.timeout)
                self.sock = TLS.wrap_socket(raw, server_hostname=UPSTREAM)
                return
            except OSError as e:
                err = e
        raise err
BUDGET = Budget(0, 0, 0, 0, "")
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

    def deny(self, code, msg, etype="proxy_denied"):
        body = json.dumps({"type": "error", "error": {"type": etype, "message": msg}}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if code == 429:
            self.send_header("Retry-After", "10")
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
        why, req = body_policy(body)
        if why:
            log(f"DENY  {self.command} {path_only} ({why})")
            return self.deny(403, why)
        refused = BUDGET.admit(req.get("model"))
        if refused:
            code, etype, msg = refused
            log(f"{'LIMIT' if code == 429 else 'DENY '} {self.command} {path_only} ({msg})")
            return self.deny(code, msg, etype)
        usage = None

        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP_IN}
        headers["Authorization"] = "Bearer " + TOKEN
        beta = [b.strip() for b in headers.pop("anthropic-beta", "").split(",") if b.strip()]
        if OAUTH_BETA not in beta:
            beta.append(OAUTH_BETA)
        headers["anthropic-beta"] = ",".join(beta)
        headers["Accept-Encoding"] = "identity"
        headers["Content-Length"] = str(len(body))

        up = UpstreamConnection(UPSTREAM, 443, context=TLS, timeout=600)
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
            if path_only == "/v1/messages" and resp.status == 200:
                usage = Usage(resp.getheader("Content-Type"))
            while True:
                data = resp.read1(65536)
                if not data:
                    break
                sent += len(data)
                if usage:
                    usage.feed(data)
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
            tokens = ""
            if usage:  # charge even if the guest hung up mid-stream: the tokens were spent
                i, o = usage.finish()
                ti, to = BUDGET.charge(i, o)
                tokens = f" in {i} out {o} (session {ti}/{to})"
        log(f"ALLOW {self.command} {path_only} -> {status} {sent}B {time.monotonic() - t0:.1f}s{tokens}")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = handle_any


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    global TOKEN, LOG, BUDGET, ADDRS
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--listen", required=True, help="Unix socket path (<vsock uds_path>_<port>)")
    tok = ap.add_mutually_exclusive_group(required=True)
    tok.add_argument("--token-file")
    tok.add_argument("--token-fd", type=int)
    ap.add_argument("--log", help="append request log here as well as stderr")
    ap.add_argument("--max-requests", type=int, default=500)
    ap.add_argument("--max-input-tokens", type=int, default=50_000_000)
    ap.add_argument("--max-output-tokens", type=int, default=1_000_000)
    ap.add_argument("--rpm", type=int, default=60)
    ap.add_argument("--models", default="")
    ap.add_argument("--upstream-addr", action="append", default=[],
                    help=f"IP address for {UPSTREAM} (repeatable); default: resolve the name")
    a = ap.parse_args()
    BUDGET = Budget(a.max_requests, a.max_input_tokens, a.max_output_tokens, a.rpm, a.models)
    ADDRS = a.upstream_addr

    if a.token_file:
        st = os.stat(a.token_file)
        if st.st_mode & 0o077:
            sys.exit(f"api-proxy: {a.token_file} is readable by group/others; chmod 600 it")
        with open(a.token_file) as f:
            TOKEN = f.read().strip()
    else:
        with os.fdopen(a.token_fd, closefd=True) as f:
            TOKEN = f.read(4096).strip()
    if not TOKEN or any(c.isspace() for c in TOKEN):
        sys.exit("api-proxy: the token must be exactly one token")
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
    if ADDRS:
        log(f"upstream: {UPSTREAM} pinned to {', '.join(ADDRS)} (no DNS)")
    log(f"budget: requests {a.max_requests or 'unlimited'}, input tokens {a.max_input_tokens or 'unlimited'}, "
        f"output tokens {a.max_output_tokens or 'unlimited'}, {a.rpm or 'unlimited'}/min, models {a.models or 'any'}")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # run-agent.sh stops the proxy with TERM
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        log(BUDGET.summary())
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
