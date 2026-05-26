# F105 hygiene PoC — verify CI action pin

```
./verify_action_sha.sh
```

Hits the GitHub API for `daniestevez/gr-satellites-ci-action`'s `v2.1.0`
tag and asserts the SHA matches the one pinned in
`patches/0097-F105-pin-action-by-sha.patch`. Run this whenever the patch
gets refreshed against a newer release to update the pin.

This is intentionally a low-ceremony verifier rather than an exploit
PoC — the bug class (mutable tag in `uses:` clause) is well-known and
the patch is a one-line pin change. No CVE filed; OpenSSF Scorecard
hygiene only.
