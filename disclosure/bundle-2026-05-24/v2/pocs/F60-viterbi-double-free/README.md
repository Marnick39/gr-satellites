# F60 PoC — Karn viterbi double-free

Two-line C program plus a build/run wrapper. No GNU Radio needed.

```
./run.sh /path/to/gr-satellites-v5.9.0/src
```

The script compiles `poc_F60_double_free.c` against the in-tree
`lib/viterbi.c`, runs it, and reports the crash signature.

On unpatched v5.9.0 (commit `f663ee4`) the second `delete_viterbi_packed`
trips glibc's malloc check and the process aborts. After patch
`patches/0003-F60-viterbi-per-instance-state.patch` the two `create`
calls return distinct pointers and both `delete`s succeed.

## Why two decoders

`create_viterbi_packed` returns `&v27_local`, a file-scope static. The
first decoder construction works; a second `create` overwrites
`v27_local.decisions` (and leaks the first allocation). At teardown,
both delete paths call `free()` on the same pointer — glibc traps it.

In a real flowgraph the bug fires when any custom GRC graph has two or
more `u482c_decode` instances (multi-band diversity, dual-satellite
test rig). The single-satellite CLI default `gr_satellites <SAT>` does
not trigger it because only one decoder is instantiated.

