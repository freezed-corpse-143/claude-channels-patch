#!/usr/bin/env python3
"""Analyze the Claude Code binary for patch anchor patterns."""
import sys

BIN = r"C:\Users\y86133\.bun\install\global\node_modules\@anthropic-ai\claude-code-win32-x64\claude.exe"

with open(BIN, "rb") as f:
    data = f.read()

print(f"Binary size: {len(data):,} bytes")

def count_all(pattern_bytes):
    """Count occurrences of a byte pattern."""
    return data.count(pattern_bytes)

def find_all_with_context(pattern_bytes, context=40):
    """Find all occurrences and show surrounding bytes."""
    results = []
    start = 0
    while True:
        idx = data.find(pattern_bytes, start)
        if idx == -1:
            break
        before = data[max(0, idx - context):idx]
        after = data[idx + len(pattern_bytes):idx + len(pattern_bytes) + context]
        results.append((idx, before, after))
        start = idx + 1
    return results

# ========================================
# 1. Feature flag: tengu_harbor
# ========================================
print("\n" + "=" * 60)
print("1. FEATURE FLAG: tengu_harbor")
print("=" * 60)

# Old pattern
pat = b'tengu_harbor",!'
print(f"\nPattern 'tengu_harbor\",!': {count_all(pat)} occurrences")
for idx, before, after in find_all_with_context(pat, 30):
    print(f"  @{idx}: ...{before[-20:]}<<HERE>>{after[:20]}...")

# Z8 pattern
pat = b'Z8("tengu_harbor"'
print(f"\nPattern 'Z8(\"tengu_harbor\"': {count_all(pat)} occurrences")
for idx, before, after in find_all_with_context(pat, 30):
    print(f"  @{idx}: ...{before}<<HERE>>{after[:20]}...")

# All tengu_harbor references
for subpat in [b'tengu_harbor",!1)}', b'tengu_harbor",!0)}', b'tengu_harbor",!1)', b'tengu_harbor",!0)']:
    c = count_all(subpat)
    if c:
        print(f"  '{subpat.decode()}': {c}")

# ========================================
# 2. Permissions flag
# ========================================
print("\n" + "=" * 60)
print("2. PERMISSIONS FLAG: tengu_harbor_permissions")
print("=" * 60)

pat = b'tengu_harbor_permissions",!'
print(f"\nPattern 'tengu_harbor_permissions\",!': {count_all(pat)} occurrences")
for idx, before, after in find_all_with_context(pat, 30):
    print(f"  @{idx}: ...{before[-30:]}<<HERE>>{after[:20]}...")

for subpat in [b'tengu_harbor_permissions",!1)}', b'tengu_harbor_permissions",!0)}',
               b'tengu_harbor_permissions",!1)', b'tengu_harbor_permissions",!0)']:
    c = count_all(subpat)
    if c:
        print(f"  '{subpat.decode()}': {c}")

# ========================================
# 3. Auth bypass patterns
# ========================================
print("\n" + "=" * 60)
print("3. AUTH BYPASS: accessToken + skip")
print("=" * 60)

# Old anchor
pat1 = b'?.accessToken)return{action:"skip",kind:"auth"'
pat2 = b'accessToken)return{action:"skip",kind:"auth"'
print(f"Old auth anchor 1: {count_all(pat1)}")
print(f"Old auth anchor 2: {count_all(pat2)}")

# Look for any auth+skip pattern
for subpat in [b'action:"skip",kind:"auth"', b'kind:"auth"', b'action:"skip"']:
    c = count_all(subpat)
    print(f"  '{subpat.decode()}': {c}")

# ========================================
# 4. Allowlist bypass
# ========================================
print("\n" + "=" * 60)
print("4. ALLOWLIST BYPASS")
print("=" * 60)

# Old patterns
pat1 = b'.marketplace))return{action:"skip",kind:"allowlist"'
pat2 = b')return{action:"skip",kind:"allowlist",reason:`server'
pat3 = b'return{action:"skip",kind:"allowlist"'
print(f"Old plugin allowlist anchor: {count_all(pat1)}")
print(f"Old server allowlist anchor: {count_all(pat2)}")
print(f"Generic allowlist skip: {count_all(pat3)}")

# New patterns
pat4 = b'action:"skip",kind:"allowlist",reason:z==='
print(f"\nNew allowlist pattern: {count_all(pat4)}")
for idx, before, after in find_all_with_context(pat4, 40):
    print(f"  @{idx}: ...{before[-40:]}<<HERE>>{after[:40]}...")

# ========================================
# 5. noAuth pattern
# ========================================
print("\n" + "=" * 60)
print("5. noAuth PATTERN")
print("=" * 60)

pat = b'noAuth:'
print(f"'noAuth:': {count_all(pat)} occurrences")
for idx, before, after in find_all_with_context(b'noAuth:', 20):
    snippet = after[:20]
    print(f"  @{idx}: ...noAuth:{snippet}...")

# ========================================
# 6. Channel decision function
# ========================================
print("\n" + "=" * 60)
print("6. CHANNEL DECISION FUNCTION")
print("=" * 60)

feat_msg = b'channels feature is not currently available'
print(f"'channels feature is not currently available': {count_all(feat_msg)}")

# aiH function
aih = b'function aiH('
print(f"'function aiH(': {count_all(aih)}")

# capability check
cap = b'claude/channel'
print(f"'claude/channel': {count_all(cap)}")

# register return
reg = b'return{action:"register"}'
print(f"'return{{action:\"register\"}}': {count_all(reg)}")

# ========================================
# 7. policyBlocked pattern
# ========================================
print("\n" + "=" * 60)
print("7. policyBlocked PATTERN")
print("=" * 60)

pat = b'policyBlocked:'
print(f"'policyBlocked:': {count_all(pat)} occurrences")
for idx, before, after in find_all_with_context(b'policyBlocked:', 20):
    snippet = after[:30]
    print(f"  @{idx}: ...policyBlocked:{snippet.decode('latin-1')[:50]}...")

# ========================================
# 8. New UI/State patterns
# ========================================
print("\n" + "=" * 60)
print("8. NEW CHANNELS STATE PATTERNS")
print("=" * 60)

# Look for state patterns near channel logic
for subpat in [b'is3P:', b'disabled:', b'unmatched:', b'channelsEnabled']:
    c = count_all(subpat)
    print(f"  '{subpat.decode()}': {c} occurrences")

# ========================================
# Summary
# ========================================
print("\n" + "=" * 60)
print("SUMMARY: Changes needed for patch.py")
print("=" * 60)
print("""
Based on the analysis above, here is what needs to change:

OLD → NEW mapping:
1. Feature flag anchor: 'tengu_harbor",!1)}' → still exists but count may differ
2. Permissions flag: 'tengu_harbor_permissions",!1)}' → still exists
3. Auth bypass: REMOVED - no explicit accessToken check in channel decision
4. Plugin allowlist: new anchor needed: 'action:"skip",kind:"allowlist",reason:z==='
5. Server allowlist: new anchor needed for else clause
6. noAuth: REMOVED - pattern 'noAuth:!' no longer exists
""")
