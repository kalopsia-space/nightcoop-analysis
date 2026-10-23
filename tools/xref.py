import sys, re, pefile, collections
dll, dis, targets = sys.argv[1], sys.argv[2], sys.argv[3].split(",")
ctx = int(sys.argv[4]) if len(sys.argv) > 4 else 14
pe = pefile.PE(dll)
base = pe.OPTIONAL_HEADER.ImageBase
iat = {}
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        if i.name: iat[i.address] = i.name.decode()
data = pe.get_memory_mapped_image()

def s_at(va):
    off = va - base
    if off < 0 or off >= len(data): return None
    b = data[off:off+200]
    a = b.split(b"\0")[0]
    if len(a) >= 4 and all(32 <= c < 127 for c in a): return repr(a.decode())
    w = b"".join(b[k:k+2] for k in range(0, 200, 2))
    try:
        u = b.decode("utf-16le", "ignore").split("\0")[0]
        if len(u) >= 4 and all(32 <= ord(c) < 127 for c in u): return "L" + repr(u)
    except Exception: pass
    return None

lines = open(dis).read().split("\n")
want = set(targets)
hits = collections.defaultdict(list)
for idx, l in enumerate(lines):
    m = re.search(r"call\s+QWORD PTR \[rip\+0x[0-9a-f]+\]\s+#\s+0x([0-9a-f]+)", l)
    if not m: continue
    name = iat.get(int(m.group(1), 16))
    if name in want: hits[name].append(idx)

for name in targets:
    print(f"===== {name}: {len(hits[name])} call sites")
    for idx in hits[name][: int(sys.argv[5]) if len(sys.argv) > 5 else 6]:
        print("  --")
        for l in lines[max(0, idx-ctx): idx+1]:
            t = l.strip()
            m = re.search(r"#\s+0x([0-9a-f]+)", t)
            extra = ""
            if m:
                a = int(m.group(1), 16)
                if a in iat: extra = "  <" + iat[a] + ">"
                else:
                    s = s_at(a)
                    if s: extra = "  STR " + s[:120]
            if "lea" in t or "call" in t or extra:
                print("   ", t[:110] + extra)
