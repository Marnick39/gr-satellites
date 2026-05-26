# Advisory 3 — Double-free in libfec viterbi packed decoder at flowgraph teardown

CVSS 3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = **5.5 Medium**
CWE: CWE-415 (double free)
Affected: gr-satellites `>= 1.0.0, <= 5.9.0` (bug introduced in commit `14aa501`, 2017-06-17, first released in v1.0.0)
Audit reference: F60

## What happens

`lib/viterbi.c:63` declares decoder state as a file-scope static:

```c
static struct v27 v27_local;
```

`create_viterbi_packed()` returns a pointer to this single shared struct and `malloc()`s a fresh `decisions` array into `v27_local.decisions`. `delete_viterbi_packed()` frees the array but does not NULL the pointer. The next destructor call frees the same heap region a second time, and modern glibc traps it unconditionally:

```
double free or corruption (!prev)
Aborted (core dumped)
```

The bug fires at flowgraph teardown when two or more `u482c_decode` blocks are destroyed in sequence. `gr_satellites <SAT>` instantiates one decoder per satellite, so the bug doesn't fire in the common single-satellite CLI usage. It does fire when an operator composes a custom GRC flowgraph with two or more `u482c_decode` blocks (diversity-receiver experiments, multi-band downlink decoding) or runs multiple `gr_satellites` instances in one process.

## Affected satellites

Custom-flowgraph reach only. The nine satyaml configs that use `framing: U482C` (AISAT, ATHENOXAT-1, AU02, AU03, CZ02, D-SAT, GALASSIA, GOMX-1, HUMSAT-D) are the realistic deployment surface; the bug doesn't fire on any of them in the default single-instance configuration.

The 42 satellites using `AX100 ASM+Golay` and the 2 FORESAIL satellites instantiate `u482c_decode` with `viterbi=OFF`, so `d_vp` is never allocated and the double-free path is unreachable.

## Proof of concept

`pocs/F60-viterbi-double-free/poc_F60_double_free.c` is a minimal libfec-level reproducer: it calls `create_viterbi_packed()` twice and then `delete_viterbi_packed()` twice against the in-tree `lib/viterbi.c`. The second `delete` aborts with glibc's `double free or corruption (!prev)` signature deterministically — no GNU Radio runtime needed. `run.sh` builds and runs it against `src/lib/viterbi.c`; the crash reproduces with `MALLOC_CHECK_=0` and `GLIBC_TUNABLES=glibc.malloc.check=0` set, so it's not a sanitizer artifact.

## Upstream provenance

Karn's upstream libfec (`fec-3.0.1/viterbi27_port.c`) is reentrant — it allocates `struct v27` per instance with `malloc()` and frees it in `delete_viterbi`. The static global was introduced in gr-satellites commit `14aa501` (2017-06-17) and has been in every release since. Upstream Karn is not affected.

Daniel's own 2017–2019 refactor of `lib/radecoder` to use a `ra_context` struct per instance is the right pattern to mirror here.

## RCE escalation

The 16,368-byte allocation lands in glibc's large-bin, not the tcache, so tcache-poisoning techniques don't apply. No chainable write primitive identified elsewhere in gr-satellites by this audit; F4 is the only RCE path filed.

## Fix

`patches/0003-F60-viterbi-per-instance-state.patch`. Allocate `struct v27` per call with `malloc()`, NULL `decisions` after `free()`, free the struct in the destructor. Mirrors the radecoder refactor.

## Notes

Reported by Marnick Vandecauter security@marnick.net as part of an independent security audit of gr-satellites v5.9.0 (May 2026). Research supported by Mamato Labs.
