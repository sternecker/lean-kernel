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
    (body(messages=[{"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "x",
                                                       "input": {"source": {"type": "url", "url": "https://x/"}}}]}]),
     True, "url inside tool_use input is the agent's own argument"),
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
import io
buf, keep = io.StringIO(), ap.LOG
ap.LOG = buf
ap.log("x" * 100000, always=True)
ap.LOG = keep
check("log line cut", len(buf.getvalue()) < ap.MAX_LOG_LINE + 64, len(buf.getvalue()))

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


def status(path, hdrs=b""):
    b = body()
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
srv.shutdown()

print("FAIL" if fails else "ok", f"({fails} failures)")
sys.exit(1 if fails else 0)
