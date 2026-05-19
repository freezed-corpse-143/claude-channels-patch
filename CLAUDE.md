# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Binary patch for Claude Code that enables the `--channels` feature without requiring claude.ai OAuth authentication. Patches two gates: feature flag (`tengu_harbor`) and channel allowlist. (The explicit OAuth/accessToken check was removed from the channel decision function in newer Claude Code builds.)

## Architecture

Python patch script (`patch.py`) that:

1. **Auto-detects** all installed Claude Code binaries (native `.exe` + npm versions)
2. **Strategy A (decision function bypass)**: Locates the channel decision function `aiH` via the stable feature message string, keeps the MCP capability check, and replaces the rest of the function body with `return{action:"register"}`. This is the preferred strategy.
3. **Strategy B (legacy byte patches)**: Finds stable anchors (string literals and property names) and applies single-byte replacements (always `!` -> space or `1` -> `0`), keeping binary size unchanged. Used as fallback.

The Claude Code binary is a Node.js SEA with **multiple embedded bundles**. The source code bundle (B2) contains the channel decision logic as readable JS. Bytecode bundles are switched to source mode via `@bun @bytecode` → `@bun @source__` (5 markers total). Source-only bundles may have 1 copy of each pattern (not 2 as in older builds).

## Key Design Constraints

- **No minified name dependency**: Variable names like `SL`, `D`, `OaH` change between builds. All anchors use only stable strings (return values, property names, string literals).
- **Equal-length replacement**: All patches are 1-byte changes. No shifting, no size change.
- **Backup-first**: Always patches from the `.bak` copy, never from an already-patched binary.
- **Cross-platform**: Pure Python 3.10+, ASCII-only output, handles Windows/Linux/macOS path differences.

## Testing

```bash
# Setup: create virtual environment with uv
uv venv

# Test against a copy of the original binary
.venv/Scripts/python.exe patch.py --check --binary /path/to/claude
.venv/Scripts/python.exe patch.py --binary /path/to/claude
```

## Adding New Patches

When adding a patch, follow the existing pattern:
1. Pick a **stable anchor** (string literal, property name — never a minified identifier)
2. Use `find_backwards()` / `find_all()` to locate the target byte
3. Verify the byte before replacing
4. Expect **1x match** per anchor in the source bundle (older builds had 2x matches in dual-copy bundles). The `channels feature is not currently available` feature message is the most reliable anchor across builds.
