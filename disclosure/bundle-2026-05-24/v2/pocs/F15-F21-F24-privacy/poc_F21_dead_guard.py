#!/usr/bin/env python3
"""F21 — lat/lon zero guard is dead code.

Reimplements the submit.py request-construction and guard logic from
python/submit.py:81-106 (pre-F21 fix). Demonstrates that the
"operator left coordinates at default" guard is permanently False
because the dict stores stringified 'longitude': '0.0E' (etc.), not
the original numeric values, so the comparison '0.0E' == 0.0 is
always False.

Run:
    python3 poc_F21_dead_guard.py
"""


# Verbatim from submit.py pre-fix (only relevant bits)
def build_request_unpatched(longitude, latitude):
    return {
        'longitude': str(abs(longitude)) + ('E' if longitude >= 0 else 'W'),
        'latitude': str(abs(latitude)) + ('N' if latitude >= 0 else 'S'),
    }


def guard_unpatched(request):
    """Verbatim from submit.py:104-106 pre-fix."""
    if (request['longitude'] == 0.0
            and request['latitude'] == 0.0):
        return 'GUARD_FIRED'
    return 'guard_did_not_fire'


def guard_patched(request, _latitude, _longitude):
    """Post-F21 fix: compare the numeric values, not the strings."""
    if _longitude == 0.0 and _latitude == 0.0:
        return 'GUARD_FIRED'
    return 'guard_did_not_fire'


def main():
    print('=== F21 — lat/lon-zero guard demonstrably dead ===')
    print()

    for lat, lon in [(0.0, 0.0), (52.5, 13.4)]:
        r = build_request_unpatched(lon, lat)
        verdict = guard_unpatched(r)
        print(f'  operator coords ({lat}, {lon})  ->  request fields:')
        print(f'    longitude = {r["longitude"]!r}')
        print(f'    latitude  = {r["latitude"]!r}')
        print(f'    unpatched guard: {verdict}')
        print(f'    patched guard:   {guard_patched(r, lat, lon)}')
        print()

    print('Conclusion: the unpatched guard is permanently False because the',
          "dict stores '0.0E' / '0.0N', and '0.0E' == 0.0 evaluates to False.")
    print('Operators leaving their lat/lon at the default to suppress',
          'station-location disclosure still get their coordinates uploaded',
          'to the public SatNOGS DB.')


if __name__ == '__main__':
    main()
