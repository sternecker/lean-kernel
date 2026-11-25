#!/usr/bin/env python3
"""Tests for scripts/api-proxy.py's request policy: python3 -I tests/api-proxy-test.py"""
import importlib.util
import json
import os
import sys

sys.dont_write_bytecode = True
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ap", os.path.join(here, "..", "scripts", "api-proxy.py"))
ap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ap)
ap.TOKEN = "real-token"

fails = 0


def check(name, ok, detail=""):
    global fails
    if not ok:
        fails += 1
        print(f"FAIL {name} {detail}")


# What the pinned Claude Code sent to a fake upstream (HOWTO, "Bump"), session id and versions made up.
CC_BETAS = ("claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,"
            "per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,thinking-token-count-2026-05-13,"
            "advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11")
CC = [("Accept", "application/json"), ("Authorization", "Bearer placeholder"), ("Content-Type", "application/json"),
      ("User-Agent", "claude-cli/2.1.316 (external, sdk-cli)"), ("X-Stainless-Retry-Count", "0"),
      ("anthropic-beta", CC_BETAS), ("anthropic-dangerous-direct-browser-access", "true"),
      ("anthropic-version", "2023-06-01"), ("x-app", "cli"), ("x-claude-code-session-id", "s"),
      ("Accept-Encoding", "gzip"), ("Cookie", "c=1"), ("X-Api-Key", "k"), ("Host", "evil")]

why, h = ap.upstream_headers(CC)
check("claude code headers pass", why is None, why)
if h:
    check("only allowlisted names", set(h) == {"accept", "content-type", "user-agent", "x-app", "anthropic-version",
                                               "anthropic-beta", "authorization", "accept-encoding"}, sorted(h))
    check("real credential", h["authorization"] == "Bearer real-token")
    check("identity encoding", h["accept-encoding"] == "identity")
    check("betas kept in order, oauth once", h["anthropic-beta"] == CC_BETAS, h["anthropic-beta"])

# Case variants and repeats are all seen, merged into one lowercase header, and checked.
why, h = ap.upstream_headers([("Anthropic-Beta", "effort-2025-11-24"), ("ANTHROPIC-BETA", "claude-code-20250219"),
                              ("anthropic-beta", "effort-2025-11-24")])
check("case variants merged", why is None and h["anthropic-beta"] == "effort-2025-11-24,claude-code-20250219,oauth-2025-04-20"
      and sum(k.lower() == "anthropic-beta" for k in h) == 1, (why, h))
# Betas are a denylist: anything is forwarded except the dangerous families. These appear when the agent
# does flaggable or unusual things, and an unrecognised beta is forwarded rather than bricking the agent.
for b in ("dangerous-tool-use-2026-09-03", "thinking-display-updates-2026-08-18",
          "something-new-2027-01-01", "inline-tools-2026-09-15"):
    why, _ = ap.upstream_headers([("anthropic-beta", b)])
    check(f"forwarded: {b}", why is None, why)
for hdrs, what in [
    ([("anthropic-beta", "web-search-2025-03-05")], "server tool beta"),
    ([("Anthropic-Beta", "files-api-2025-04-14")], "beta in other case"),
    ([("anthropic-beta", "effort-2025-11-24"), ("ANTHROPIC-BETA", "mcp-servers-2025-12-04")], "dangerous beta in a repeat"),
    ([("anthropic-beta", "effort-2025-11-24, context-1m-2025-08-07")], "cost beta"),
    ([("anthropic-beta", "fast-mode-2026-02-01")], "fast mode"),
    ([("anthropic-beta", "mcp-tunnels-2026-06-22")], "mcp tunnels"),
    ([("anthropic-beta", "advisor-tool-2026-03-01")], "advisor server tool"),
    ([("anthropic-beta", "message-threads-2026-08-12")], "server-state thread"),
    # A date bump of a dangerous family is still refused, because the stem is matched, not the exact value.
    ([("anthropic-beta", "web-search-2099-12-31")], "date-bumped server tool"),
    ([("anthropic-beta", "mcp-servers-2099-01-01")], "date-bumped mcp"),
    ([("anthropic-beta", "mcp-client-2025-04-04")], "mcp connector"),
    ([("anthropic-beta", "skills-2025-10-02")], "skills"),
    # The stem is matched without regard to case, in case the API treats beta names that way.
    ([("anthropic-beta", "Web-Search-2025-03-05")], "server tool beta, mixed case"),
    ([("anthropic-beta", "effort-2025-11-24,MCP-CLIENT-2025-11-20")], "mcp connector, upper case, in a list"),
    ([("anthropic-version", "2099-01-01")], "other version"),
    ([("anthropic-version", "2023-06-01"), ("Anthropic-Version", "2099-01-01")], "version in a repeat"),
]:
    why, _ = ap.upstream_headers(hdrs)
    check(f"refused: {what}", why is not None)
why, h = ap.upstream_headers([])
check("defaults filled in", why is None and h["anthropic-version"] == "2023-06-01" and h["anthropic-beta"] == "oauth-2025-04-20", h)


def body(**kw):
    return json.dumps({"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}], **kw}).encode()


WEB = {"type": "web_search_20250305", "name": "web_search"}
CLIENT = {"name": "Bash", "input_schema": {"type": "object"}}
add = lambda t: {"role": "system", "content": [{"type": "tool_addition", "tool": {"type": "tool_definition", "definition": t}}]}
for b, ok, what in [
    (body(), True, "plain"),
    (body(tools=[CLIENT]), True, "client tool"),
    (body(tools=[WEB]), False, "server tool"),
    (body(speed="fast"), False, "speed field"),
    (body(messages=[{"role": "user", "content": "hi"}, add(CLIENT)]), True, "client tool added mid-conversation"),
    (body(messages=[{"role": "user", "content": "hi"}, add(WEB)]), False, "server tool added mid-conversation"),
    (body(messages=[{"role": "assistant", "content": [{"type": "compaction", "content": "x",
                                                       "tool_changes": [{"type": "tool_addition", "tool": {"type": "tool_definition", "definition": WEB}}]}]}]),
     False, "server tool in compaction tool_changes"),
    (body(messages=[{"role": "user", "content": "hi"}, add("x")]), False, "tool definition not an object"),
    (body(messages=[{"role": "system", "content": [{"type": "tool_addition", "tool": WEB}]}]), False, "bare server tool added"),
    (body(messages=[{"role": "system", "content": [{"type": "tool_addition", "tool": {"type": "wrapper", "x": WEB}}]}]),
     False, "server tool under an unknown wrapper"),
    (body(messages=[{"role": "system", "content": [{"type": "tool_addition", "tool": {"type": "tool_reference", "name": "Bash"}}]}]),
     True, "tool added by reference"),
    (body(messages=[{"role": "system", "content": [{"type": "tool_removal", "tool": {"type": "tool_reference", "name": "Bash"}}]}]),
     True, "tool removed by reference"),
    # The whole request is walked, not only messages and system; schemas are the one place a "source"
    # property is just a property.
    (body(context_management={"edits": [{"type": "x", "source": {"type": "url", "url": "https://x/"}}]}),
     False, "url source outside messages"),
    (body(tools=[{"name": "t", "input_schema": {"type": "object", "properties": {"source": {"type": "string"}}}}]),
     True, "client tool schema with a source property"),
    (body(output_format={"type": "json_schema", "schema": {"properties": {"source": {"type": "url"}}}}),
     True, "output schema with a source property"),
    (body(messages=[{"role": "user", "content": "hi"}, add({"name": "t", "input_schema": {"properties": {"source": {"type": "string"}}}})]),
     True, "added client tool schema with a source property"),
    (body(output_config={"format": {"type": "json_schema", "schema": {"properties": {"source": {"type": "url"}}}}}),
     True, "output_config format schema with a source property"),
    (body(messages=[{"role": "user", "content": [{"type": "text", "text": "x", "schema": {"source": {"type": "url", "url": "https://x/"}}}]}]),
     False, "url source under a schema key in a content block"),
    (body(messages=[{"role": "user", "content": [{"type": "text", "text": "x", "input_schema": {"source": {"type": "url", "url": "https://x/"}}}]}]),
     False, "url source under an input_schema key in a content block"),
    (body(context_management={"schema": {"source": {"type": "url", "url": "https://x/"}}}),
     False, "url source under a schema key outside output_format"),
    (body(output_format={"type": "json_schema", "input_schema": {"source": {"type": "url", "url": "https://x/"}}}),
     False, "input_schema key in output_format is not a schema"),
    (body(tools=[{"name": "t", "schema": {"source": {"type": "url", "url": "https://x/"}}}]),
     False, "schema key in a tool definition is not input_schema"),
    (body(messages=[{"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "x",
                                                       "input": {"source": {"type": "url", "url": "https://x/"}}}]}]),
     True, "url inside tool_use input is the agent's own argument"),
    (b'{"model":"m","max_tokens":1e999,"messages":[]}', False, "non-finite number"),
    (body(thread={"type": "continue", "previous_message_id": "msg_other"}), False, "thread continue"),
    (body(diagnostics={"previous_message_id": "msg_other"}), False, "diagnostics"),
]:
    why, _ = ap.body_policy(b)
    check(f"body {what}", (why is None) == ok, why)

# Guest-chosen text in a refusal is cut: a 1 MB field name or source type is not a 1 MB log line or 403.
big = "A" * (1 << 20)
for b, what in [(body(**{big: 1}), "field name"),
                (body(messages=[{"role": "user", "content": [{"type": "image", "source": {"type": big}}]}]), "source type"),
                (body(tools=[{"type": big}]), "tool type"),
                (("{" + json.dumps(big) + ":1," + json.dumps(big) + ":2}").encode(), "duplicate key")]:
    why, _ = ap.body_policy(b)
    check(f"refusal cut: {what}", why is not None and len(why) < 200, why and len(why))
refused = ap.Budget(0, 0, 0, 0, "").admit([big])   # a non-string model is refused with its repr
check("refusal cut: model", refused and len(refused[2]) < 200, refused and len(refused[2]))

# Budget: requests in flight reserve against the token budgets, so concurrent ones can't all pass the same check.
b = ap.Budget(0, 1000, 500, 0, "")
check("budget: first reservation admitted", b.admit("m", 1000, 100) is None)
check("budget: a second request sees the first's input reservation", b.admit("m", 1, 1) is not None)
b.charge(300, 100, (1000, 100))   # real usage replaces the reservation
check("budget: released reservation frees room", b.admit("m", 1, 500) is None and b.inp == 300)
check("budget: a second request sees the output reservation", b.admit("m", 1, 1) is not None)
b.charge(0, 0, (1, 500))
check("budget: output reservation released", b.admit("m", 1, 1) is None)
# Reservations alone reaching a limit is a retry (429); tokens actually spent reaching it ends the session (403).
b = ap.Budget(0, 0, 50000, 0, "")
check("budget: two parallel requests admitted", b.admit("m", 1, 32000) is None and b.admit("m", 1, 32000) is None)
r = b.admit("m", 1, 32000)
check("budget: reservation-only overflow is a 429", r is not None and r[0] == 429, r)
b.charge(0, 50000, (1, 32000))
r = b.admit("m", 1, 1)
check("budget: spent budget is a 403", r is not None and r[0] == 403, r)
# max_tokens is what the budget reserves: anything but a positive int is refused, not forwarded and counted as 0.
for mt, ok in ((32000, True), (32000.0, False), ("32000", False), (True, False), (0, False), (-1, False)):
    why, _ = ap.body_policy(json.dumps({"model": "m", "max_tokens": mt, "messages": []}).encode())
    check(f"max_tokens {mt!r}", (why is None) == ok, why)
check("max_tokens may be absent (count_tokens)", ap.body_policy(b'{"model":"m","messages":[]}')[0] is None)
check("budget: unlimited ignores reservations", ap.Budget(0, 0, 0, 0, "").admit("m", 10**9, 10**9) is None)
# A stream cut off before message_delta is charged what it asked for, not what it had streamed.
u = ap.Usage("text/event-stream")
u.feed(b'data: {"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":1}}}\n')
check("usage: cut stream is not complete", not u.complete and u.finish() == (5, 1))
u.feed(b'data: {"type":"message_delta","usage":{"output_tokens":9}}\n')
check("usage: final delta completes it", u.complete and u.finish() == (5, 9))
# A stream the API ends with an error event is marked as such, with what it had streamed as its estimate.
u = ap.Usage("text/event-stream")
u.feed(b'data: {"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":1}}}\n')
u.feed(b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}\n')
u.feed(b'event: error\ndata: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}\n')
check("usage: error event marks the stream", u.errored and not u.complete)
check("usage: streamed estimate covers the deltas", 1 < u.streamed_estimate() < 100, u.streamed_estimate())
# Request bytes in flight are capped (a body costs BODY_COST times its size while held).
bb = ap.ByteBudget(100)
check("bytes: fits", bb.acquire(60))
check("bytes: over the cap refused", not bb.acquire(60))
bb.release(60)
check("bytes: released", bb.acquire(100))
check("bytes: cap 0 is unlimited", ap.ByteBudget(0).acquire(10**12))

# Landlock: after install_landlock a process reads the interpreter and /etc, not other files, and (ABI 6+)
# can't reach another process's abstract unix socket. Run in a child; skipped where the kernel has no Landlock.
import socket
import tempfile
secret_dir = tempfile.mkdtemp(dir=os.environ.get("TMPDIR", "/tmp"))
secret = os.path.join(secret_dir, "secret")
open(secret, "w").write("x")
# A resolver file that is a symlink out of /etc (systemd-resolved: /etc/resolv.conf -> /run/systemd/resolve/...):
# its real directory must stay readable, while other directories (secret_dir) stay denied.
resolv_dir = tempfile.mkdtemp(dir=os.environ.get("TMPDIR", "/tmp"))
open(os.path.join(resolv_dir, "stub-resolv.conf"), "w").write("nameserver 127.0.0.53\n")
resolv_link = os.path.join(tempfile.mkdtemp(dir=os.environ.get("TMPDIR", "/tmp")), "resolv.conf")
os.symlink(os.path.join(resolv_dir, "stub-resolv.conf"), resolv_link)
listener = socket.socket(socket.AF_UNIX)
listener.bind("\0lean-test-" + str(os.getpid()))
listener.listen(1)
rfd, wfd = os.pipe()
pid = os.fork()
if pid == 0:
    out = []
    try:
        ap.RESOLVER_FILES = ap.RESOLVER_FILES + (resolv_link,)
        abi = ap.install_landlock(remove_in=(), required=False)
        out.append(f"abi={abi}")
        if abi:
            for name, p in (("secret", secret), ("etc", "/etc/hostname"), ("resolv", resolv_link)):
                try:
                    open(p).close()
                    out.append(f"{name}=read")
                except OSError:
                    out.append(f"{name}=denied")
            try:
                open(os.path.join(secret_dir, "new"), "w")
                out.append("write=allowed")
            except OSError:
                out.append("write=denied")
            c = socket.socket(socket.AF_UNIX)
            try:
                c.connect("\0lean-test-" + str(os.getppid()))
                out.append("abstract=connected")
            except OSError:
                out.append("abstract=denied")
    except BaseException as e:
        out.append(f"error={e!r}")
    os.write(wfd, " ".join(out).encode())
    os._exit(0)
os.waitpid(pid, 0)
res = os.read(rfd, 4096).decode()
if "abi=0" in res or not res:
    print("skip: Landlock not available here")
elif not secret.startswith(tuple({sys.prefix, sys.base_prefix, "/usr", "/etc"})):
    check("landlock: secret file denied", "secret=denied" in res, res)
    check("landlock: /etc readable", "etc=read" in res, res)
    check("landlock: no writes", "write=denied" in res, res)
    check("landlock: resolver file behind a symlink readable", "resolv=read" in res, res)
    check("landlock: abstract sockets scoped (ABI 6+)", "abstract=denied" in res or int(res.split("abi=")[1].split()[0]) < 6, res)
import io
buf, keep = io.StringIO(), ap.LOG
ap.LOG = buf
ap.log("x" * 100000, always=True)
ap.LOG = keep
check("log line cut", len(buf.getvalue()) < ap.MAX_LOG_LINE + 64, len(buf.getvalue()))

# Canary: the proxy's copy of the guest's placeholder credential is the one the image sets.
with open(os.path.join(here, "..", "scripts", "mkrootfs-agent.sh")) as f:
    check("canary matches the image's placeholder", f"CLAUDE_CODE_OAUTH_TOKEN={ap.CANARY} " in f.read(), ap.CANARY)
import base64
C = ap.CANARY.encode()
for b, how, what in [
    (body(), None, "ordinary body"),
    (body(messages=[{"role": "user", "content": "placeholder-real-token"}]), None, "a prefix is not the canary"),
    (body(messages=[{"role": "user", "content": "env: CLAUDE_CODE_OAUTH_TOKEN=" + ap.CANARY}]), "as text", "text"),
    (body(system=ap.CANARY.upper()), "as text", "upper case"),
    (b'{"x":"\\u0070' + C[1:] + b'"}', None, "JSON escape, raw bytes (the re-encoded body catches it)"),
    (ap.canonical(json.loads(b'{"x":"\\u0070' + C[1:] + b'"}')), "as text", "JSON escape, re-encoded"),
] + [
    (b'{"x":"' + enc(pre + C + post) + b'"}', "as base64", f"{name} base64, {len(pre)} bytes before")
    for name, enc in [("standard", base64.b64encode), ("url-safe", base64.urlsafe_b64encode)]
    for pre in (b"", b"a", b"ab", b"abc", b"TOKEN=")
    for post in (b"", b"\n", b"xy")
]:
    got = ap.canary_seen(b)
    check(f"canary: {what}", got == how, f"-> {got}")

# Through the handler: the query string is checked, and what goes upstream is the checked path.
import socket
import tempfile
import threading

sent = []


class FakeUp:
    def __init__(self, *a, **kw):
        pass

    def request(self, method, path, body=None, headers=None):
        sent.append((method, path, headers))
        raise OSError("no upstream in tests")

    def close(self):
        pass


ap.UpstreamConnection = FakeUp
ap.LOG = open(os.devnull, "w")
sock = os.path.join(tempfile.mkdtemp(), "p.sock")
srv = ap.Server(sock, ap.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()


def status(path, hdrs=b"", b=None):
    b = b or body()
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock)
    s.sendall(b"POST " + path.encode() + b" HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n" + hdrs
              + b"Content-Length: " + str(len(b)).encode() + b"\r\n\r\n" + b)
    line = s.makefile("rb").readline().split()
    s.close()
    return int(line[1]) if len(line) > 1 else None


for path, code in [("/v1/messages", 502), ("/v1/messages?beta=true", 502), ("/v1/messages/count_tokens?beta=true", 502),
                   ("/v1/messages?beta=true&x=1", 403), ("/v1/messages?x=secret", 403), ("/v1/messages?", 502)]:
    got = status(path)
    check(f"handler {path}", got == code, f"-> {got}")
check("upstream got only checked paths",
      [p for _, p, _ in sent] == ["/v1/messages", "/v1/messages?beta=true", "/v1/messages/count_tokens?beta=true", "/v1/messages"],
      [p for _, p, _ in sent])
check("handler refuses an off-list beta", status("/v1/messages", b"Anthropic-Beta: files-api-2025-04-14\r\n") == 403)
check("handler header names", sent and set(sent[0][2]) == {"content-type", "anthropic-version", "anthropic-beta",
                                                          "authorization", "accept-encoding", "content-length"},
      sent and sorted(sent[0][2]))

# The canary is a tripwire, not a wall: the request still goes upstream, the hit is counted, and the first
# one is logged even when the log's rate limit has nothing left.
check("no canary hits so far", ap.CANARY_HITS.count == 0, ap.CANARY_HITS.count)
buf, keep, keep_tokens = io.StringIO(), ap.LOG, ap.LOG_LIMIT.tokens
ap.LOG, ap.LOG_LIMIT.tokens = buf, 0
n_sent = len(sent)
leak = body(messages=[{"role": "user", "content": "here is my token: " + ap.CANARY}])
check("canary body still forwarded", status("/v1/messages", b=leak) == 502 and len(sent) == n_sent + 1)
check("canary counted once", ap.CANARY_HITS.count == 1, ap.CANARY_HITS.count)
check("first canary logged past the rate limit", " CANARY POST /v1/messages: " in buf.getvalue(), buf.getvalue())
check("canary log line has no body text", "here is my token" not in buf.getvalue())
escaped = b'{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"\\u0070' + C[1:] + b'"}]}'
status("/v1/messages", b=escaped)
check("escaped canary counted once", ap.CANARY_HITS.count == 2, ap.CANARY_HITS.count)
status("/v1/messages", b=body(speed="fast", system=ap.CANARY))
check("canary in a refused body counted", ap.CANARY_HITS.count == 3, ap.CANARY_HITS.count)
ap.LOG, ap.LOG_LIMIT.tokens = keep, keep_tokens

# Through the handler: what a /v1/messages stream is charged. A fake upstream sends an SSE body; the budget's
# output total afterwards is what the proxy charged for it (max_tokens here is 32000, as Claude Code sends).
class FakeResp:
    status, reason = 200, "OK"

    def __init__(self, chunks):
        self.chunks = list(chunks)

    def getheaders(self):
        return [("Content-Type", "text/event-stream")]

    def getheader(self, k, default=None):
        return {"content-type": "text/event-stream"}.get(k.lower(), default)

    def read1(self, n):
        return self.chunks.pop(0) if self.chunks else b""


START = b'data: {"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":1}}}\n'
DELTA = b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}\n'
streams = {
    "error": [START, DELTA, b'event: error\ndata: {"type":"error","error":{"type":"overloaded_error"}}\n'],
    "cut": [START, DELTA],
    "done": [START, DELTA, b'data: {"type":"message_delta","usage":{"output_tokens":7}}\n'],
}


def charged(kind):
    class StreamUp(FakeUp):
        def request(self, *a, **kw):
            pass

        def getresponse(self):
            return FakeResp(streams[kind])

    ap.UpstreamConnection = StreamUp
    ap.BUDGET = ap.Budget(0, 0, 0, 0, "")
    b = body(max_tokens=32000, stream=True)
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock)
    s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
              b"Content-Length: " + str(len(b)).encode() + b"\r\n\r\n" + b)
    while s.recv(65536):
        pass
    s.close()
    for _ in range(50):   # the handler charges in its finally, after the guest has the last byte
        if ap.BUDGET.out or ap.BUDGET.res_out == 0:
            break
        time.sleep(0.02)
    return ap.BUDGET.out


import time


# The guest hangs up while the API is still working: the reply it never read is billed, so it is charged
# (it was charged nothing: usage was only set up after the headers had been written to the guest).
def charged_after_hangup():
    release = threading.Event()

    class SlowUp(FakeUp):
        def request(self, *a, **kw):
            pass

        def getresponse(self):
            release.wait(5)
            return FakeResp([START, DELTA, b'data: {"type":"message_delta","usage":{"output_tokens":7}}\n'] * 2000)

    ap.UpstreamConnection = SlowUp
    ap.BUDGET = ap.Budget(0, 0, 0, 0, "")
    b = body(max_tokens=32000, stream=True)
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock)
    s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
              b"Content-Length: " + str(len(b)).encode() + b"\r\n\r\n" + b)
    time.sleep(0.2)
    s.close()
    release.set()
    for _ in range(100):
        if ap.BUDGET.out:
            break
        time.sleep(0.02)
    return ap.BUDGET.inp, ap.BUDGET.out


i_, o_ = charged_after_hangup()
check("handler: a guest that hangs up before the reply is still charged", o_ > 0 and i_ > 0, (i_, o_))

# A body that is all JSON structure costs far more memory than its bytes: refused when it can never fit.
# B3: a line break in a header value (a folded header) is refused, forwarded header or not.
why, _ = ap.upstream_headers([("User-Agent", "a\r\n\tb")])
check("headers: folded value refused", why is not None, why)
why, _ = ap.upstream_headers([("X-Unlisted", "a\nb")])
check("headers: line break in an unlisted header refused", why is not None, why)
# A policy denial counts as refused in the session summary.
ap.BUDGET = ap.Budget(0, 0, 0, 0, "")
ap.BUDGET.note_refused()
check("budget: policy denial counted", "1 refused" in ap.BUDGET.summary(), ap.BUDGET.summary())

ap.UpstreamConnection = FakeUp
ap.BUDGET = ap.Budget(0, 0, 0, 0, "")
keep_inflight, ap.INFLIGHT = ap.INFLIGHT, ap.ByteBudget(1 << 20)


def post(b):
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock)
    s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
              b"Content-Length: " + str(len(b)).encode() + b"\r\n\r\n" + b)
    line = s.makefile("rb").readline().split()
    s.close()
    return int(line[1]) if len(line) > 1 else None


check("handler: dense JSON body refused (413)", post(body(messages=[[] for _ in range(20000)])) == 413)
check("handler: ordinary body still forwarded", post(body()) == 502)
# The handler thread releases after it has written the reply, which the client can read first: wait for it.
for _ in range(100):
    if ap.INFLIGHT.used == 0:
        break
    time.sleep(0.02)
check("handler: in-flight bytes released", ap.INFLIGHT.used == 0, ap.INFLIGHT.used)
ap.INFLIGHT = keep_inflight

# The proxy's seccomp filter refuses socketpair(): it would hand out AF_UNIX sockets socket() is denied.
import subprocess
snippet = (
    "import importlib.util, socket, sys\n"
    "s = importlib.util.spec_from_file_location('ap', sys.argv[1]); ap = importlib.util.module_from_spec(s); s.loader.exec_module(ap)\n"
    "ap.install_seccomp(extra_deny=(53,), socket_families=(socket.AF_INET, socket.AF_INET6))\n"
    "try:\n    socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)\n    sys.exit(1)\nexcept OSError:\n    sys.exit(0)\n")
rc = subprocess.run([sys.executable, "-I", "-c", snippet, os.path.join(here, "..", "scripts", "api-proxy.py")]).returncode
check("seccomp: socketpair refused", rc == 0, rc)
check("main denies socketpair", "extra_deny=(53,)" in open(os.path.join(here, "..", "scripts", "api-proxy.py")).read())

c = charged("error")
check("handler: stream ended by an API error is charged what it streamed", 0 < c < 100, c)
check("handler: stream cut off without an error is charged max_tokens", charged("cut") == 32000)
check("handler: complete stream is charged the reported usage", charged("done") == 7)
srv.shutdown()

print("FAIL" if fails else "ok", f"({fails} failures)")
sys.exit(1 if fails else 0)
