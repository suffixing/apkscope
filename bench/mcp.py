"""An agent-style MCP session: the same xref and decompile calls through rust_ASC's MCP server
and apkscope's (stateless, and with the warm cached session). Prints per-call latency.

usage: python bench/mcp.py <rust_ASC.exe> <apkscope.exe> <app.apk>
"""
import json
import statistics
import subprocess
import sys
import time

STRINGS = ["https://", "api_key", "Authorization", "/v1/", "token", "secret", "sign", "device_id"]
CLASSES = [
    "com.ss.android.ugc.aweme.app.api.RequestLog",
    "com.ttnet.org.chromium.net.impl.JavaCronetEngine",
    "org.chromium.wschannel.WsClient",
    "X.0DoH",
    "X.0rHZ",
]


class Server:
    def __init__(self, cmd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        self.id = 0
        self.call_raw("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "bench", "version": "1"}})
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.p.stdin.flush()

    def call_raw(self, method, params):
        self.id += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params}) + "\n")
        self.p.stdin.flush()
        while True:
            msg = json.loads(self.p.stdout.readline())
            if msg.get("id") == self.id:
                return msg

    def tool(self, name, args):
        t = time.perf_counter()
        r = self.call_raw("tools/call", {"name": name, "arguments": args})
        ms = (time.perf_counter() - t) * 1000
        res = r.get("result", {})
        text = "".join(c.get("text", "") for c in res.get("content", []))
        return ms, (not res.get("isError")) and "error" not in r, len(text)

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=30)


ROUNDS = 3


def run(label, server, calls):
    rounds, fails = [], 0
    for _ in range(ROUNDS):
        times = []
        for name, args in calls:
            ms, ok, _ = server.tool(name, args)
            times.append(ms)
            fails += not ok
        rounds.append(times)
    server.close()
    cells = " | ".join(f"{sum(t)/1000:,.2f} s (median {statistics.median(t):,.0f} ms)" for t in rounds)
    total = sum(map(sum, rounds)) / 1000
    print(f"| {label} | {cells} | {total:,.2f} s | {fails} |")


def main():
    asc, ours, apk = sys.argv[1:4]
    asc_calls = [("findrefs", {"apk_path": apk, "query": {"kind": "string", "value": s}}) for s in STRINGS]
    asc_calls += [("getclass", {"apk_path": apk, "class_name": c}) for c in CLASSES]
    ours_calls = lambda cache: [("find_refs", {"apk_path": apk, "kind": "string", "query": s, "cache": cache}) for s in STRINGS] + [
        ("decompile", {"apk_path": apk, "classes": [c], "cache": cache}) for c in CLASSES
    ]
    n = len(asc_calls)
    print(f"{n} calls ({len(STRINGS)} string xrefs, then {len(CLASSES)} class decompiles) x {ROUNDS} rounds in one MCP session\n")
    print("| Server | " + " | ".join(f"Round {r + 1}" for r in range(ROUNDS)) + " | Total | Failed |")
    print("|---|" + "---:|" * (ROUNDS + 2))
    run("rust_ASC mcp", Server([asc, "mcp"]), asc_calls)
    run("apkscope mcp (stateless)", Server([ours, "mcp"]), ours_calls(False))
    run("apkscope mcp (cache: true)", Server([ours, "mcp"]), ours_calls(True))


if __name__ == "__main__":
    main()
