#!/usr/bin/env python3
"""Host-side API proxy for the agent VM (NOTES: "Credentials without a separate gateway").

Listens on a Unix socket: Firecracker turns a guest connection to vsock CID 2 port P into a
connection to <uds_path>_P on the host. Takes plain HTTP from the guest, keeps only allowlisted
headers (no credential the guest sent survives), adds the real one, and forwards to
https://api.anthropic.com over verified TLS. Only allowlisted method+path pairs are forwarded, only with
the pinned anthropic-version and with the dangerous anthropic-beta families refused (upstream_headers), and
only bodies that can't make Anthropic's servers fetch anything (body_policy: allowlisted top-level fields,
client tools only, inline content sources only); everything else gets a 403 and a DENY log line.
Responses are relayed as they arrive (Claude streams server-sent events).

The credential is read from a file at startup and exists only in this process:
  --token-file FILE    Claude subscription OAuth token (from `claude setup-token`), sent as Bearer.
  --token-fd N         the same token, read from an inherited fd (the jail wrapper pipes it in, so
                       the proxy's own user never needs access to the file).
Headers and bodies are never logged; one line per request: verdict, method, path, status, bytes, time,
and for messages the tokens used and the running totals. Guest-chosen text in a refusal (a field name, a
source type, a model) is cut to 64 characters, and every log line to MAX_LOG_LINE, so the guest can't
grow the host log by bytes the way the line cap and rate limit stop it growing by lines.

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
ALLOWED_QUERIES = frozenset({"", "beta=true"})
OAUTH_BETA = "oauth-2025-04-20"
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
       "transfer-encoding", "upgrade", "host", "content-length"}
MAX_BODY = 32 << 20
# Request headers are an allowlist too. anthropic-version and anthropic-beta decide what the body's fields
# mean, so a body check that ignored them would be checking the wrong request: they are checked here, and
# everything not named (x-stainless-*, x-claude-code-session-id, anthropic-dangerous-direct-browser-access,
# cookies, credentials, ...) is dropped. Names are matched case-insensitively and every repeat is seen.
FORWARD_HEADERS = frozenset({"content-type", "accept", "user-agent", "x-app"})
ANTHROPIC_VERSION = "2023-06-01"
# anthropic-beta values are a DENYLIST, not an allowlist. The body policy (ALLOW_FIELDS, client tools
# only, inline sources only) is the real wall: a beta header does nothing on its own -- it only changes
# what some request field means, and body_policy already gates every field that could carry a fetch. The
# web-search beta is inert without a web_search tool (refused by _tool_why); mcp-servers without the
# mcp_servers field (refused by ALLOW_FIELDS); a server-state beta without its thread/diagnostics field
# (also out of ALLOW_FIELDS). So any beta is forwarded EXCEPT the families below, which are worth refusing
# at the header too. Matched by name STEM (prefix), case-insensitively (the value is lowercased before the
# check, so Web-Search-... is refused too), so a date bump of one of these stays refused. A refused
# beta gets a 403 naming it (which the guest's Claude Code shows as a login/auth error, then stops).
DENY_BETA_PREFIXES = (
    # Server reaches out or runs things -- would turn the API into a route to arbitrary hosts. The matching
    # body (a server tool, the mcp_servers/container field, a url/file source) is refused by body_policy too.
    "web-search-", "web-fetch-", "code-execution-", "computer-use-",
    "mcp-servers-", "mcp-client-", "mcp-tunnels-", "files-api-", "skills-", "environments-", "ccr-byoc-",
    "advisor-tool-",
    # Names stored server-side state by id, which nothing ties to this session (a message id from another
    # session on the account would be read back). The matching fields (thread, diagnostics) are out of
    # ALLOW_FIELDS too.
    "message-threads-", "cache-diagnosis-",
    # Costs more per token than the budget counts. fast-mode's speed field is out of ALLOW_FIELDS too;
    # context-1m is mostly beta-driven, so a date bump could slip past and bill at the 1M rate -- a cost
    # risk, not an egress one.
    "context-1m-", "fast-mode-", "cache-keepalive-",
)
# Anything that makes Anthropic's servers reach out on the agent's behalf turns the API into a route
# to arbitrary hosts (a URL with data in its query string): server tools (web fetch/search, code
# execution, ...), remote MCP servers, containers, and content blocks whose source is a URL or an
# uploaded file. Everything here is an allowlist, so a field or source type added to the API later is
# refused until someone reads what it does and adds it. A refusal names the field in the DENY line.
#
# Top-level request fields that are forwarded. Anything else (mcp_servers, container, ...) is a 403.
# The second group is what the pinned Claude Code (VERSION: CLAUDE_CODE_VERSION) adds to its request
# body, read from its request builder: safeguards = [{type, classifier_context}] for Anthropic's
# safety classifiers; cache_control. Neither names something for the server to fetch. Not speed: "fast"
# is priced per token above what the budget counts (fast-mode beta). Not thread or diagnostics: both carry
# a previous_message_id, a reference to stored server-side state (see the betas below). The pinned version
# sends none of the three by default. On a Claude Code bump, recheck them (HOWTO, "Bump").
ALLOW_FIELDS = frozenset({
    "model", "messages", "system", "max_tokens", "metadata", "stop_sequences", "stream",
    "temperature", "top_k", "top_p", "tools", "tool_choice", "thinking", "service_tier",
    "context_management", "output_format", "output_config",
    "safeguards", "cache_control",
})
# Content block "source" types that carry their data inline. Not "url" (the server fetches it) and not
# "file" (a Files API upload, which this proxy never allows the agent to make or reference).
ALLOW_SOURCES = frozenset({"base64", "text", "content"})
MAX_DEPTH = 64
MAX_LOG_LINE = 1024


def _short(v, n=64):
    """repr of a guest-chosen value, cut to n characters: it ends up in a log line and in the 403 body,
    and a 32 MB field name must not become a 32 MB line of either."""
    s = repr(v)
    return s if len(s) <= n else s[:n] + "..."


def _tool_why(t):
    """Client tools, which the agent runs itself, have no "type" (or "custom"); server tools all do."""
    typ = t.get("type") if isinstance(t, dict) else "?"
    if typ not in (None, "custom"):
        return f"server tool {_short(typ)} not allowed"
    return None


# Where a JSON Schema legitimately appears: a client tool definition's "input_schema", and the "schema" of
# an output format. A schema may describe a property called "source" with a "type", and the server never
# fetches anything from one, so those two subtrees are not walked. The same key anywhere else (say inside
# a content block) is walked like everything else. _walk tracks where it is with `kind`:
#   "tools"         the top-level tools list (its items are "tool")
#   "tool"          a tool definition: skip its input_schema
#   "output_config" skip nothing, but its "format" is a "format"
#   "format"        an output format: skip its schema
_TOP_KINDS = {"tools": "tools", "output_format": "format", "output_config": "output_config"}
_SCHEMA_KEY = {"tool": "input_schema", "format": "schema"}


def _child_kind(kind, v, k):
    if kind == "top":
        return _TOP_KINDS.get(k)
    if kind == "output_config" and k == "format":
        return "format"
    # A tool added mid-conversation: tool_definition carries a full definition.
    if kind is None and v.get("type") == "tool_definition" and k == "definition":
        return "tool"
    return None


def _walk(v, depth=0, kind="top"):
    """Return a reason if anything nested in v points the server at something to fetch. kind says
    which schema-bearing place v is (see above); the caller passes the request itself as "top"."""
    if depth > MAX_DEPTH:
        return "body nested too deeply"
    if isinstance(v, list):
        for x in v:
            why = _walk(x, depth + 1, "tool" if kind == "tools" else None)
            if why:
                return why
    elif isinstance(v, dict):
        src = v.get("source")
        if isinstance(src, dict) and src.get("type") not in ALLOW_SOURCES:
            return f"content source type {_short(src.get('type'))} not allowed"
        # A tool added inside the conversation (mid-conversation tool changes: a tool_addition block in a
        # message, or in a compaction block's tool_changes) is held to the same rule as the top-level tools
        # list. The tool is a definition or a reference by name; any other shape is refused, so a server
        # tool can't be put there bare or under a wrapper this check doesn't know.
        if v.get("type") in ("tool_addition", "tool_removal"):
            t = v.get("tool")
            kind = t.get("type") if isinstance(t, dict) else None
            if kind not in ("tool_definition", "tool_reference"):
                return f"{v['type']} of {_short(kind)} not allowed"
        if v.get("type") == "tool_definition":
            why = _tool_why(v.get("definition"))
            if why:
                return why
        # A tool call's arguments are the agent's own JSON, not content blocks: a parameter that
        # happens to be called "source" there means nothing to the server. Schemas likewise, in the
        # two places _walk's comment names.
        skip = "input" if v.get("type") in ("tool_use", "server_tool_use") else _SCHEMA_KEY.get(kind)
        for k, x in v.items():
            if k == skip:
                continue
            why = _walk(x, depth + 1, _child_kind(kind, v, k))
            if why:
                return why
    return None


class DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs):
    # Python keeps the last copy of a repeated key; another parser may keep the first. A body that
    # means one thing here and another upstream would get past every check below, so refuse it.
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise DuplicateKey(k)
        obj[k] = v
    return obj


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def body_policy(body):
    """Return (reason, request): reason is None if the body may be forwarded. The caller forwards
    canonical(request), never the bytes it received, so upstream parses exactly what was checked."""
    try:
        req = json.loads(body, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except DuplicateKey as e:
        return f"duplicate key {_short(str(e))}", None
    except (ValueError, RecursionError):
        return "body is not JSON", None
    if not isinstance(req, dict):
        return "body is not a JSON object", None
    for k in req:
        if k not in ALLOW_FIELDS:
            return f"field {_short(k)} not allowed", req
    tools = req.get("tools") or []
    if not isinstance(tools, list):
        return "tools is not a list", req
    for t in tools:
        why = _tool_why(t)
        if why:
            return why, req
    # Sources and tool definitions anywhere in the request, not just in messages and system: a field that
    # grows a place for a content block later is covered without anyone noticing it first. Only schemas
    # (in a tool definition or an output format) and tool-call arguments are skipped.
    why = _walk(req)
    if why:
        return why, req
    return None, req


def upstream_headers(items):
    """items: the guest's (name, value) header pairs, repeats included. Return (reason, headers): reason is
    None if the request may go upstream with headers, which never carry anything the guest sent unchecked."""
    out, betas, versions = {}, [], set()
    for k, v in items:
        name = k.lower()
        if name == "anthropic-beta":
            betas += [b.strip() for b in v.split(",") if b.strip()]
        elif name == "anthropic-version":
            versions.add(v.strip())
        elif name in FORWARD_HEADERS and name not in out:
            out[name] = v
    if versions - {ANTHROPIC_VERSION}:
        return f"anthropic-version {sorted(versions - {ANTHROPIC_VERSION})[0][:64]!r} not allowed", None
    for b in betas:
        if b.lower().startswith(DENY_BETA_PREFIXES):
            return f"beta {b[:64]!r} not allowed", None
    out["anthropic-version"] = ANTHROPIC_VERSION
    out["anthropic-beta"] = ",".join(dict.fromkeys(betas + [OAUTH_BETA]))
    out["authorization"] = "Bearer " + TOKEN
    out["accept-encoding"] = "identity"
    return None, out


def canonical(req):
    """The checked request, re-encoded: plain ASCII JSON, one copy of every key."""
    return json.dumps(req, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()


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
                why = (403, "proxy_denied", f"model {_short(model)} not allowed")
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
            raw = None
            try:
                raw = socket.create_connection((ip, self.port), self.timeout)
                self.sock = TLS.wrap_socket(raw, server_hostname=UPSTREAM)
                return
            except BaseException as e:
                # A failed handshake leaves raw open (wrap_socket doesn't close it on error).
                if raw is not None:
                    raw.close()
                if not isinstance(e, OSError):
                    raise
                err = e
        raise err
BUDGET = Budget(0, 0, 0, 0, "")
TLS = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
TLS.check_hostname = True
TLS.verify_mode = ssl.CERT_REQUIRED
TLS.load_default_certs()
TLS.minimum_version = ssl.TLSVersion.TLSv1_2
TLS.options |= ssl.OP_NO_TLSv1
TLS.options |= ssl.OP_NO_TLSv1_1
LOG = sys.stderr


class LogLimit:
    """The guest decides how often the proxy logs (every refused request is a line), so the log is
    rate-limited (a burst of `burst`, then `rate` lines a second) and capped per session. Lines
    dropped are counted and reported; the startup lines and the session summary always get through."""

    def __init__(self, rate=2.0, burst=50, cap=5000):
        self.rate, self.burst, self.cap = rate, burst, cap
        self.tokens, self.last = float(burst), time.monotonic()
        self.written = self.dropped = 0
        self.lock = threading.Lock()

    def admit(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.written >= self.cap or self.tokens < 1:
                self.dropped += 1
                return None
            self.tokens -= 1
            self.written += 1
            dropped, self.dropped = self.dropped, 0
            return dropped


LOG_LIMIT = LogLimit()


def printable(s):
    """Escape control characters: the guest chooses parts of every log line (method, path, error
    text), and the log is shown on the owner's terminal, so no escape sequence may pass through."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in s)


def log(line, always=False):
    # The backstop for anything a format site forgot to cut (a request path, an exception's text).
    if len(line) > MAX_LOG_LINE:
        line = line[:MAX_LOG_LINE] + " ..."
    line = printable(line)
    stamp = time.strftime("%H:%M:%S ")
    if not always:
        dropped = LOG_LIMIT.admit()
        if dropped is None:
            return
        if dropped:
            LOG.write(f"{stamp}({dropped} log lines dropped by the rate limit)\n")
    LOG.write(stamp + line + "\n")
    LOG.flush()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Idle limit on the guest side of a connection (socket timeout, set by StreamRequestHandler):
    # a connection that sends nothing, or stops mid-request, is closed instead of holding a thread.
    timeout = 30
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
        path_only, _, query = self.path.partition("?")
        if not self.path.startswith("/") or (self.command, path_only) not in ALLOW:
            log(f"DENY  {self.command} {path_only}")
            return self.deny(403, "not on the proxy allowlist")
        # The query string is checked too: the SDK only ever adds ?beta=true. What goes upstream is rebuilt
        # from the checked parts, never self.path.
        if query not in ALLOWED_QUERIES:
            log(f"DENY  {self.command} {path_only} (query string not allowed)")
            return self.deny(403, "query string not allowed")
        upstream_path = path_only + ("?" + query if query else "")
        length = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding") or length is None:
            log(f"DENY  {self.command} {path_only} (no Content-Length)")
            return self.deny(411, "Content-Length required")
        # Digits only: int() would also take signs, spaces and underscores, and raise on anything else.
        if not (length.isascii() and length.isdigit() and len(length) <= 9):
            log(f"DENY  {self.command} {path_only} (bad Content-Length)")
            return self.deny(400, "bad Content-Length")
        n = int(length)
        if n > MAX_BODY:
            log(f"DENY  {self.command} {path_only} (body {n} bytes)")
            return self.deny(413, "request body too large")
        body = self.rfile.read(n)
        why, headers = upstream_headers(self.headers.items())
        if why:
            log(f"DENY  {self.command} {path_only} ({why})")
            return self.deny(403, why)
        why, req = body_policy(body)
        if why:
            log(f"DENY  {self.command} {path_only} ({why})")
            return self.deny(403, why)
        body = canonical(req)  # forward what was checked, not what was sent
        refused = BUDGET.admit(req.get("model"))
        if refused:
            code, etype, msg = refused
            log(f"{'LIMIT' if code == 429 else 'DENY '} {self.command} {path_only} ({msg})")
            return self.deny(code, msg, etype)
        usage = None

        headers["content-length"] = str(len(body))

        up = UpstreamConnection(UPSTREAM, 443, context=TLS, timeout=600)
        sent = 0
        status = "-"
        try:
            up.request(self.command, upstream_path, body=body, headers=headers)
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
    """One thread per connection, at most max_connections at a time: a connection over the limit is
    closed at once, so the guest can't make the proxy hold an unbounded number of threads."""
    daemon_threads = True
    max_connections = 16
    # Listen backlog (socketserver's default is 5). Firecracker's vsock device connects to this socket with
    # a blocking connect() on its VMM thread (docs/firecracker-review-v1.17.0.md, B), and a guest can send
    # up to 256 connection requests per queue pass; a deeper backlog keeps that thread from parking in
    # connect() while the accept loop below catches up. The loop itself never blocks: a connection is
    # either handed to a thread or closed at once.
    request_queue_size = 128

    def server_activate(self):
        super().server_activate()
        self.slots = threading.BoundedSemaphore(self.max_connections)
        self.refused = 0

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.refused += 1
            log(f"LIMIT connection closed: {self.max_connections} already open")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def handle_error(self, request, client_address):
        # The default prints a traceback to stderr, outside the log's rate limit and cap, so a guest
        # that can trigger one at will could grow the host log without bound. One limited line instead.
        e = sys.exc_info()[1]
        log(f"ERROR handler: {type(e).__name__}: {e}")

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


# --- seccomp: begin (kept identical in scripts/api-proxy.py and scripts/console-filter.py; ---
# --- tests/seccomp-test.py checks that) ---
# A host process that parses guest-controlled bytes gets a seccomp filter once it has set itself up. It
# is a denylist that answers EPERM, not an allowlist that kills: CPython with threads and TLS uses
# syscalls nobody wants to enumerate, and a miss must not take the console or the proxy down mid-run.
# What it removes is the kernel surface a compromised process would reach for next: exec, debugging other
# processes, namespaces and mounts, bpf, io_uring, userfaultfd, perf, keyrings, modules, kexec, terminal
# input injection (TIOCSTI). x86_64
# only, like the rest of the repo (Firecracker's release binaries are x86_64); anything else refuses to
# start rather than run unfiltered. Standard library only (ctypes): the scripts run under python3 -I.
SECCOMP_DENY_COMMON = {
    "execve": 59, "execveat": 322, "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
    "process_madvise": 440, "pidfd_getfd": 438, "personality": 135,
    "unshare": 272, "setns": 308, "mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161,
    "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433, "move_mount": 429, "open_tree": 428,
    "open_tree_attr": 467, "mount_setattr": 442,
    "bpf": 321, "perf_event_open": 298, "userfaultfd": 323,
    "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    "keyctl": 250, "add_key": 248, "request_key": 249,
    "init_module": 175, "finit_module": 313, "delete_module": 176, "kexec_load": 246, "kexec_file_load": 320,
    "open_by_handle_at": 304, "name_to_handle_at": 303, "swapon": 167, "swapoff": 168, "reboot": 169,
    "acct": 163, "quotactl": 179,
}
_NR_CLONE, _NR_CLONE3, _NR_SOCKET, _NR_IOCTL = 56, 435, 41, 16
# ioctls that act on another process's input: TIOCSTI pushes bytes into a terminal's input queue (the
# console filter's stdout is the user's terminal, so that would type commands into their shell), and
# TIOCLINUX can do the same on a virtual console. Refused even where dev.tty.legacy_tiocsti=0.
_IOCTL_DENY = (0x5412, 0x541C)   # TIOCSTI, TIOCLINUX
# CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET
_CLONE_NS = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000


def install_seccomp(extra_deny=(), socket_families=None, threads=True):
    """Load the filter into this process (all its threads). extra_deny: more syscall numbers to refuse.
    socket_families: the address families socket() may create (an empty tuple refuses socket() outright;
    None leaves it alone). threads=False refuses clone() too; otherwise clone() may make threads but no
    namespaces. clone3() answers ENOSYS, so glibc falls back to clone(), whose flags a filter can read.
    Raises OSError if the filter could not be loaded: callers stop rather than run without it."""
    import ctypes
    import struct

    if os.uname().machine != "x86_64":
        raise OSError(f"seccomp filter: x86_64 only, not {os.uname().machine}")
    LD, JEQ, JGE, JSET, RET = 0x20, 0x15, 0x35, 0x45, 0x06   # BPF_LD|W|ABS, BPF_JMP|{JEQ,JGE,JSET}|K, BPF_RET|K
    KILL, ALLOW = 0x80000000, 0x7FFF0000                      # SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_ALLOW
    EPERM, ENOSYS = 0x00050000 | 1, 0x00050000 | 38           # SECCOMP_RET_ERRNO | errno
    prog = [
        (LD, 0, 0, 4), (JEQ, 1, 0, 0xC000003E), (RET, 0, 0, KILL),   # arch must be AUDIT_ARCH_X86_64
        (LD, 0, 0, 0), (JGE, 0, 1, 0x40000000), (RET, 0, 0, KILL),   # no x32 numbers past the denylist
    ]
    for nr in sorted(set(SECCOMP_DENY_COMMON.values()) | set(extra_deny)):
        prog += [(JEQ, 0, 1, nr), (RET, 0, 0, EPERM)]
    prog += [(JEQ, 0, 1, _NR_CLONE3), (RET, 0, 0, ENOSYS)]
    # ioctl: args[1] low word (offset 24) is the request
    prog += [(JEQ, 0, len(_IOCTL_DENY) + 3, _NR_IOCTL), (LD, 0, 0, 24)]
    prog += [(JEQ, len(_IOCTL_DENY) - i, 0, c) for i, c in enumerate(_IOCTL_DENY)]
    prog += [(RET, 0, 0, ALLOW), (RET, 0, 0, EPERM)]
    if threads:   # args[0] low word (offset 16): the flags
        prog += [(JEQ, 0, 4, _NR_CLONE), (LD, 0, 0, 16), (JSET, 0, 1, _CLONE_NS), (RET, 0, 0, EPERM), (RET, 0, 0, ALLOW)]
    else:
        prog += [(JEQ, 0, 1, _NR_CLONE), (RET, 0, 0, EPERM)]
    if socket_families is not None:
        fams = list(socket_families)
        prog += [(JEQ, 0, len(fams) + 3, _NR_SOCKET), (LD, 0, 0, 16)]
        prog += [(JEQ, len(fams) - i, 0, f) for i, f in enumerate(fams)]
        prog += [(RET, 0, 0, EPERM), (RET, 0, 0, ALLOW)]
    prog.append((RET, 0, 0, ALLOW))

    buf = ctypes.create_string_buffer(b"".join(struct.pack("<HBBI", *i) for i in prog))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fprog = SockFprog(len(prog), ctypes.addressof(buf))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    # PR_SET_NO_NEW_PRIVS: required to load a filter without CAP_SYS_ADMIN, and nothing here needs privs.
    if libc.prctl(38, ctypes.c_ulong(1), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS)")
    # seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog): every thread, or none.
    rc = libc.syscall(ctypes.c_long(317), ctypes.c_long(1), ctypes.c_long(1), ctypes.byref(fprog))
    if rc != 0:
        raise OSError(ctypes.get_errno(), f"seccomp(SECCOMP_SET_MODE_FILTER) returned {rc}")
# --- seccomp: end ---


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
    ap.add_argument("--max-connections", type=int, default=16, help="concurrent guest connections (default 16)")
    ap.add_argument("--idle-timeout", type=float, default=30, help="seconds a guest connection may sit idle (default 30)")
    ap.add_argument("--max-log-lines", type=int, default=5000, help="log lines per session before the log stops (default 5000)")
    ap.add_argument("--upstream-addr", action="append", default=[],
                    help=f"IP address for {UPSTREAM} (repeatable); default: resolve the name")
    a = ap.parse_args()
    BUDGET = Budget(a.max_requests, a.max_input_tokens, a.max_output_tokens, a.rpm, a.models)
    ADDRS = a.upstream_addr
    Server.max_connections = max(1, a.max_connections)
    Handler.timeout = a.idle_timeout
    LOG_LIMIT.cap = a.max_log_lines

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
        + ", ".join(f"{m} {p}" for m, p in sorted(ALLOW)) + ")", always=True)
    if ADDRS:
        log(f"upstream: {UPSTREAM} pinned to {', '.join(ADDRS)} (no DNS)", always=True)
    log(f"budget: requests {a.max_requests or 'unlimited'}, input tokens {a.max_input_tokens or 'unlimited'}, "
        f"output tokens {a.max_output_tokens or 'unlimited'}, {a.rpm or 'unlimited'}/min, models {a.models or 'any'}", always=True)
    log(f"limits: {Server.max_connections} connections, {a.idle_timeout:g}s idle timeout, "
        f"{a.max_log_lines} log lines", always=True)
    # Token read, log open, socket bound: from here on the proxy only serves. Unix sockets for the guest,
    # TCP to the API; no other socket family.
    try:
        install_seccomp(socket_families=(socket.AF_UNIX, socket.AF_INET, socket.AF_INET6))
    except OSError as e:
        sys.exit(f"api-proxy: {e}; not running without the seccomp filter")
    log("seccomp: filter loaded", always=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # run-agent.sh stops the proxy with TERM
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        dropped = LOG_LIMIT.dropped
        log(BUDGET.summary() + f", {getattr(srv, 'refused', 0)} connections over the limit"
            + (f", {dropped} log lines dropped" if dropped else ""), always=True)
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
