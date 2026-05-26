/*
 * F60 focused PoC — libfec Karn viterbi double-free at flowgraph teardown.
 *
 * Build against the gr-satellites in-tree viterbi.c. No GNU Radio required.
 *
 *   gcc -O0 -g -fno-omit-frame-pointer \
 *       -I<gr-satellites-src>/lib \
 *       -o poc_F60 poc_F60_double_free.c <gr-satellites-src>/lib/viterbi.c
 *   ./poc_F60
 *
 * Expected output on unpatched v5.9.0 (commit f663ee4):
 *
 *   F60 PoC — create two viterbi decoders, delete both
 *     decoder A: 0x55e...
 *     decoder B: 0x55e...        <-- SAME POINTER (file-scope static)
 *     deleting A...   ok
 *     deleting B...
 *   double free or corruption (!prev)
 *   Aborted (core dumped)
 *
 * After applying patches/0003-F60-viterbi-per-instance-state.patch:
 *
 *   decoder A: 0x55e..1010
 *   decoder B: 0x55e..2020        <-- distinct heap allocations
 *   deleting A...   ok
 *   deleting B...   ok
 *   F60 PoC complete — no crash.
 *
 * The two-decoder case is the realistic operator-side reproducer: any
 * custom flowgraph with two u482c_decode blocks (multi-band diversity,
 * dual-satellite test rig) tears down both at exit and hits the bug.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "viterbi.h"

int main(void) {
    printf("F60 PoC \xe2\x80\x94 create two viterbi decoders, delete both\n");

    void *a = create_viterbi_packed(128);
    void *b = create_viterbi_packed(128);
    printf("  decoder A: %p\n", a);
    printf("  decoder B: %p\n", b);
    if (a == b) {
        printf("  >> shared static struct \xe2\x80\x94 unpatched v5.9.0 confirmed\n");
    }

    printf("  deleting A...");
    fflush(stdout);
    delete_viterbi_packed(a);
    printf("   ok\n");

    printf("  deleting B...");
    fflush(stdout);
    delete_viterbi_packed(b);   /* glibc trap fires here on unpatched build */
    printf("   ok\n");

    printf("F60 PoC complete \xe2\x80\x94 no crash.\n");
    return 0;
}
