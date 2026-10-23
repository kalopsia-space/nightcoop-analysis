import re, sys, collections
src = open(sys.argv[1], encoding="utf-8", errors="replace").read()
funcs = re.split(r"^//==== ", src, flags=re.M)[1:]
F = {}
for f in funcs:
    head, _, body = f.partition("\n")
    F[head] = body
print("functions:", len(F))

def callers(pat):
    r = re.compile(pat)
    return [h for h, b in F.items() if r.search(b)]

# 1. sensitive API usage
apis = ["VirtualProtect", "VirtualAlloc", "CreateThread", "CreateFileW", "CreateFile2", "WriteFile", "MoveFileExW",
        "DeleteFileW", "CopyFile2", "LoadLibrary", "GetProcAddress", "Ordinal_20\\b", "Ordinal_9\\b",
        "WSASendTo", "Ordinal_4\\b", "Ordinal_52\\b", "GetClipboardData", "SetClipboardData", "GetAsyncKeyState",
        "ReadProcessMemory", "SuspendThread", "GetThreadContext", "RegQueryValueExW", "SHGetKnownFolderPath",
        "CreateToolhelp32Snapshot", "TerminateProcess", "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler",
        "MessageBox", "GetEnvironmentStrings", "SetEnvironmentVariable", "OpenThread"]
print("\n== API usage (functions containing call)")
for a in apis:
    c = callers(r"\b" + a + r"\w*\s*\(")
    print(f"{a:28} {len(c):4}  " + ", ".join(h.split()[0] for h in c[:8]))

# 2. PEB walk / API hashing / shellcode-ish patterns
print("\n== suspicious patterns")
pats = {
    "PEB/TEB access (GS:0x60/0x30)": r"in_GS_OFFSET\s*\+\s*0x(60|30)|GS_OFFSET.{0,20}0x60",
    "ROR13 hash const": r"0x6a4abc5b|0xec0e4e8e|0x7c0dfcaa|0x726774c|0x0726774c",
    "FNV/djb2 + export dir walk": r"\+\s*0x88\)\s*\+.*\+\s*0x18\)|IMAGE_EXPORT",
    "PAGE_EXECUTE flags in VirtualProtect": r"VirtualProtect\([^;]*,\s*0x(10|20|40|80)\s*,",
    "call through data pointer cast to code from buffer": r"\(\*\(code \*\)\s*(local_|param_)\w+\s*\)\(",
    "syscall instruction": r"\bsyscall\(",
    "CreateProcess/ShellExecute/WinExec": r"CreateProcess|ShellExecute|WinExec|system\(",
    "IsDebuggerPresent outside CRT": r"IsDebuggerPresent",
}
for k, p in pats.items():
    c = callers(p)
    print(f"{k:48} {len(c):4}  " + ", ".join(h.split()[0] for h in c[:10]))

# 3. XOR-decode loops over byte buffers (string obfuscation)
xr = re.compile(r"\^\s*0x[0-9a-f]{2}\b.*;\s*$", re.M)
xc = [(h, len(xr.findall(b))) for h, b in F.items() if "do {" in b or "for (" in b]
xc = sorted([x for x in xc if x[1] >= 3], key=lambda x: -x[1])[:15]
print("\n== functions with many byte-xor ops in loops (crypto or obfuscation):")
for h, n in xc: print("  ", n, h)
