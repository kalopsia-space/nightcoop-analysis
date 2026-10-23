import re, sys
src = open(sys.argv[1], encoding="utf-8", errors="replace").read()
F = {}
for f in re.split(r"^//==== ", src, flags=re.M)[1:]:
    h, _, b = f.partition("\n"); F[h.split()[0]] = (h, b)
pat = re.compile(sys.argv[3]) if len(sys.argv) > 3 else None
ctx = int(sys.argv[4]) if len(sys.argv) > 4 else 3
for a in sys.argv[2].split(","):
    h, b = F[a]
    lines = b.split("\n")
    print(f"##### {h}  ({len(lines)} lines)")
    if pat is None:
        print(b[:4000]); continue
    keep = set()
    for i, l in enumerate(lines):
        if pat.search(l):
            keep.update(range(max(0, i-ctx), i+ctx+1))
    last = -2
    for i in sorted(keep):
        if i != last+1: print("   ...")
        print("  ", lines[i][:200]); last = i
