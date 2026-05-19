#!/usr/bin/env python3
"""IDA analysis script for Claude Code binary --channels investigation."""
import idaapi
import idautils
import idc
import ida_search
import ida_bytes
import ida_funcs
import ida_name
import ida_xref
import sys
import os

OUTPUT = os.path.join(os.path.dirname(__file__), "ida_channels_analysis.txt")

def log(msg):
    print(msg)
    with open(OUTPUT, "a") as f:
        f.write(msg + "\n")

def analyze():
    with open(OUTPUT, "w") as f:
        f.write("=== IDA Claude Code Channel Analysis ===\n\n")

    # 1. Search for key strings
    patterns = [
        ("tengu_harbor", "Feature flag name"),
        ("tengu_harbor_permissions", "Permissions flag name"),
        ("channels feature is not currently available", "Feature disabled message"),
        ("action:\"skip\",kind:\"capability\"", "Capability skip"),
        ("action:\"skip\",kind:\"disabled\"", "Disabled skip"),
        ("action:\"skip\",kind:\"allowlist\"", "Allowlist skip"),
        ("action:\"register\"", "Register action"),
        ("claude/channel", "Channel capability"),
        ("--channels", "CLI flag"),
        ("allowedChannelPlugins", "Allowed plugins setting"),
        ("channelsEnabled", "Channels enabled setting"),
        ("channels feature is not", "Feature message partial"),
    ]

    for pattern, desc in patterns:
        log(f"\n## {desc}: '{pattern}'")
        ea = ida_search.find_binary(0, idc.BADADDR, pattern, 0, idc.SEARCH_DOWN)
        found = []
        while ea != idc.BADADDR:
            found.append(ea)
            # Check for xrefs to this location
            xrefs = []
            for xref in idautils.XrefsTo(ea):
                xrefs.append(f"0x{xref.frm:x}")
            if xrefs:
                log(f"  @0x{ea:x} (xrefs from: {', '.join(xrefs)})")
            else:
                log(f"  @0x{ea:x}")
            ea = ida_search.find_binary(ea + 1, idc.BADADDR, pattern, 0, idc.SEARCH_DOWN)
        log(f"  Total: {len(found)} occurrences")

    # 2. Find functions that reference "tengu_harbor" or "channels"
    log("\n\n## Functions referencing key strings\n")
    for target_name in ["tengu_harbor", "channels feature", "claude/channel"]:
        ea = ida_search.find_binary(0, idc.BADADDR, target_name, 0, idc.SEARCH_DOWN)
        if ea != idc.BADADDR:
            for xref in idautils.XrefsTo(ea):
                func = ida_funcs.get_func(xref.frm)
                if func:
                    func_name = ida_name.get_name(func.start_ea)
                    log(f"  {target_name} -> xref from {func_name} @0x{func.start_ea:x}")

    # 3. List all segments
    log("\n\n## Segments\n")
    for seg in idautils.Segments():
        seg_obj = idaapi.getseg(seg)
        if seg_obj:
            log(f"  {idaapi.get_segm_name(seg_obj)}: 0x{seg_obj.start_ea:x}-0x{seg_obj.end_ea:x} ({seg_obj.size():,} bytes)")

    # 4. Find the "channels" entry point in the Bun runtime
    log("\n\n## Searching for --channels CLI argument handling\n")
    channels_ea = ida_search.find_binary(0, idc.BADADDR, "--channels", 0, idc.SEARCH_DOWN)
    if channels_ea != idc.BADADDR:
        log(f"  '--channels' at 0x{channels_ea:x}")
        for xref in idautils.XrefsTo(channels_ea):
            func = ida_funcs.get_func(xref.frm)
            if func:
                func_name = ida_name.get_name(func.start_ea)
                log(f"  xref from {func_name} @0x{func.start_ea:x}")
                # Try to decompile
                try:
                    import ida_hexrays
                    if ida_hexrays.init_hexrays_plugin():
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            log(f"\n  === Decompiled {func_name} ===\n")
                            log(str(cfunc))
                except Exception as e:
                    log(f"  Decompile failed: {e}")

    # 5. Find JS bundle boundaries (look for "// @bun" markers)
    log("\n\n## Bun SEA bundle markers\n")
    bun_ea = ida_search.find_binary(0, idc.BADADDR, "// @bun", 0, idc.SEARCH_DOWN)
    count = 0
    while bun_ea != idc.BADADDR and count < 20:
        # Read 50 bytes
        data = ida_bytes.get_bytes(bun_ea, 50)
        if data:
            try:
                text = data.decode('latin-1', errors='replace').replace('\n', '\\n').replace('\r', '\\r')
                log(f"  @0x{bun_ea:x}: {text[:80]}")
            except:
                log(f"  @0x{bun_ea:x}: {data[:30].hex()}")
        count += 1
        bun_ea = ida_search.find_binary(bun_ea + 1, idc.BADADDR, "// @bun", 0, idc.SEARCH_DOWN)

    log("\n## Analysis complete\n")

if __name__ == "__main__":
    idaapi.auto_wait()
    analyze()
    idc.qexit(0)
