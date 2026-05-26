# F112 hygiene PoC — build with and without hardening flags

```
./poc_F112_checksec.sh /path/to/gr-satellites/src
```

Builds the in-tree CMake project twice (unpatched, then patched) and
runs `checksec` / `hardening-check` / `readelf` heuristics against
`libgnuradio-satellites.so` to show which hardening properties are
present before and after the patch.

## Why this is hygiene, not a CVE

Distros that build via `dpkg-buildflags` (Debian/Ubuntu apt builds) or
`rpm %optflags` (Fedora, RHEL, SUSE) already inject these flags by
default. Only operators who do a plain source build via
`cmake .. && make` (the documented path in
`docs/source/installation.rst`) miss them.

Not a vulnerability. Aligns the shipped CMakeLists with the OpenSSF
"Token-Permissions"-adjacent expectation that security-relevant C/C++
code has hardening enabled by default.
