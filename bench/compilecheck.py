"""Export an APK with apkscope, then compile the Java with javac against android.jar.

usage: python bench/compilecheck.py <apkscope.exe> <app.apk> <android.jar> <work-dir>

Reports, separately:
  - syntax: files that javac can't parse (gotos are counted apart, they are a known gap)
  - types:  errors in the files that do parse, grouped by kind
"""
import collections
import os
import re
import shutil
import subprocess
import sys


def javac(files, jar, out_dir, listfile):
    with open(listfile, "w", encoding="utf-8") as f:
        f.write("\n".join(files) + "\n")
    shutil.rmtree(out_dir, ignore_errors=True)
    r = subprocess.run(
        ["javac", "-J-Xmx4g", "-nowarn", "-proc:none", "-Xmaxerrs", "1000000", "-encoding", "UTF-8", "-cp", jar, "-d", out_dir, "@" + listfile],
        capture_output=True,
    )
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def errors(text):
    """(file, message, source line) per error"""
    out = []
    lines = text.splitlines()
    for i, l in enumerate(lines):
        m = re.match(r"^(.+?\.java):\d+: error: (.*)$", l)
        if m:
            src = lines[i + 1].strip() if i + 1 < len(lines) else ""
            out.append((os.path.normpath(m.group(1)), m.group(2), src))
    return out


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        return 2
    exe, apk, jar, work = sys.argv[1:]
    proj = os.path.join(work, "project")
    shutil.rmtree(proj, ignore_errors=True)
    subprocess.run([exe, "export", apk, proj], check=True, capture_output=True)
    src = os.path.join(proj, "app", "src", "main", "java")
    files = []
    for root, _, names in os.walk(src):
        files += [os.path.normpath(os.path.join(root, n)) for n in names if n.endswith(".java")]
    goto_files = {f for f in files if re.search(r"goto L|<caught exception>", open(f, encoding="utf-8").read())}
    clean = [f for f in files if f not in goto_files]
    out = os.path.join(work, "classes")
    lst = os.path.join(work, "files.txt")

    syn = errors(javac(clean, jar, out, lst))
    bad = {e[0] for e in syn}
    typed = [f for f in clean if f not in bad]
    raw = javac(typed, jar, out, lst)
    with open(os.path.join(work, "javac-raw.txt"), "w", encoding="utf-8") as f:
        f.write(raw)
    sem = errors(raw)
    sem_files = {e[0] for e in sem}

    print(f"{len(files)} files: {len(goto_files)} contain gotos, {len(bad)} other files have syntax errors")
    print(f"{len(typed)} files parse; {len(sem)} type errors in {len(sem_files)} of them")
    print(f"=> {len(typed) - len(sem_files)} of {len(files)} files ({100 * (len(typed) - len(sem_files)) / max(len(files), 1):.1f}%) compile with no errors in the file itself")
    kinds = collections.Counter(re.sub(r"'[^']*'", "'_'", re.sub(r"\d+", "N", m)).split(":")[0][:70] for _, m, _ in sem)
    print("\ntype errors by kind:")
    for k, n in kinds.most_common(25):
        print(f"  {n:6} {k}")
    if "-v" in os.environ.get("CC_VERBOSE", ""):
        for f, m, s in sem[:200]:
            print(f, "|", m, "|", s)
    with open(os.path.join(work, "type-errors.txt"), "w", encoding="utf-8") as f:
        for e in sem:
            f.write(" | ".join(e) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
