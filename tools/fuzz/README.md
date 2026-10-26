# Fuzz harnesses

Transcription-based libFuzzer harnesses for NightCoop's attacker-reachable
parsers. Each harness is a faithful C transcription of a decompiled function
(not the shipped bytes — see the caveat in each file), fuzzed under ASan/UBSan
with buffers sized so any out-of-bounds access faults immediately.

See [`../../docs/F_rce_fuzzing_0.1.1-beta.2.md`](../../docs/F_rce_fuzzing_0.1.1-beta.2.md)
for the audit writeup and results.

## `fuzz_wirezip.c` — the `wire_zip` / NCZQ decompressor (`FUN_180066cc0`)

```sh
clang -g -O1 -fsanitize=fuzzer,address,undefined -o fuzz_wirezip fuzz_wirezip.c
mkdir -p corpus
./fuzz_wirezip -max_total_time=90 -max_len=70000 corpus/
```

Input layout: `[outsize:u16 LE][base:u16 LE][compressed bytes…]`.

Result (0.1.1-beta.2): 452,858 executions, coverage saturated, **0 crashes /
leaks / sanitizer errors**. Hand-crafted seeds for the literal run, `0xf/0xff`
length extension, overlapping (RLE) match, and prior-window back-reference all
run clean.

## Not yet harnessed

The NCSQ reassembler (`FUN_18005d860`), the decompressed-stream framer
(`FUN_180066b20`), the header/size parser (`FUN_180066360`), and the save-splice
path remain to be fuzzed — see the residual-risk section of the audit writeup.
