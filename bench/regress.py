"""Decompile sample APKs and compare quality counters with bench/baseline.json.

usage: python bench/regress.py <apkscope.exe> <app.apk>... [--update]

Fails (exit 1) when any method fails or crashes, the decompiler panics, or gotos/warnings
grow past the recorded baseline. --update records the current numbers as the new baseline.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(HERE, "baseline.json")


def measure(exe, apk):
    r = subprocess.run([exe, "decompile", apk, "--no-deobf"], capture_output=True)
    out = r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    return {
        "exit": r.returncode,
        "panics": err.count("panicked"),
        "smali_fallbacks": out.count("Showing Dalvik bytecode"),
        "warned_methods": out.count("/* WARNING:"),
        "gotos": out.count("goto L"),
        "unmatched_locks": out.count("monitorEnter("),
        "lines": out.count("\n"),
    }


def main():
    args = [a for a in sys.argv[1:] if a != "--update"]
    update = "--update" in sys.argv
    if len(args) < 2:
        print(__doc__)
        return 2
    exe, apks = args[0], args[1:]
    base = json.load(open(BASELINE)) if os.path.exists(BASELINE) else {}
    ok = True
    for apk in apks:
        name = os.path.basename(apk)
        m = measure(exe, apk)
        b = base.get(name, {})
        print(f"{name}: " + ", ".join(f"{k}={v}" + (f" (was {b[k]})" if k in b and b[k] != v else "") for k, v in m.items()))
        if m["exit"] != 0 or m["panics"] or m["smali_fallbacks"] > b.get("smali_fallbacks", 0):
            print("  FAIL: crash, panic or new decompile failure")
            ok = False
        for k in ("gotos", "warned_methods", "unmatched_locks"):
            if k in b and m[k] > b[k]:
                print(f"  FAIL: {k} got worse ({b[k]} -> {m[k]})")
                ok = False
        if update:
            base[name] = m
    if update:
        json.dump(base, open(BASELINE, "w"), indent=2, sort_keys=True)
        print(f"baseline written to {BASELINE}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
