import os

def parse_tlm_env_verbatim(value):
    """VERBATIM from gr_satellites_flowgraph.py:215-217"""
    return bool(int(value))

print('=' * 72)
print(' [F24] GR_SATELLITES_SUBMIT_TLM env var parsing — verbatim test')
print('=' * 72)
test_values = ['1', '0', 'yes', 'no', 'true', 'false',
               'on', 'off', 'No', 'False', 'OFF',
               '-1', '2', '999', '', 'disabled']
results = {}
for v in test_values:
    try:
        r = parse_tlm_env_verbatim(v)
        results[v] = ('OK', r)
        marker = '  ok' if v in ('0', '1') else '  !!'
        print(f'  {v!r:<14} -> tlm_submit = {r}   {marker}')
    except Exception as e:
        results[v] = ('CRASH', e)
        print(f'  {v!r:<14} -> CRASH: {type(e).__name__}')

print()
print('  Natural opt-out values that CRASH the flowgraph init:')
crash_count = 0
for v in ['no', 'false', 'off', 'disabled', 'No', 'False', 'OFF']:
    if results[v][0] == 'CRASH':
        print(f'    {v!r}')
        crash_count += 1
print()
print('  Intuitive opt-out values that SILENTLY ENABLE submission:')
silent_enable = 0
for v in ['-1', '2', '999']:
    if results[v] == ('OK', True):
        print(f'    {v!r} -> tlm_submit = True   (user intended off!)')
        silent_enable += 1
print()
if crash_count >= 4 and silent_enable >= 2:
    print('  *** F24 CONFIRMED ***')
