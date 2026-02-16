# Patches (this fork)

- **xrefs_to / function_xrefs:** `code_only` param; call/flow refs listed first. Lets MCP find call sites without scanning data refs.
- **getFunctionXrefs:** Refs to entire function body (not just entry). BL to first instruction is included.
- **Disassembly:** Bridge returns one newline-joined string instead of list. Full listing in MCP, no truncation.
- **Timeout:** Default 60s; `GHIDRA_MCP_TIMEOUT` env. Stops timeouts on decompile/list_data for large binaries.
- **get_xrefs_to_range(start, end):** Plugin + bridge. Xrefs to any address in [start,end] (step 8). For vtables/data blocks with no direct ref to exact addr.
- **read_memory(address, length) / get_pointer_at(address):** Plugin `/read_memory` + bridge. Read raw bytes (hex) or one 64-bit pointer (LE). For vtable slots and data layout without UI.

Build: copy Ghidra JARs to `lib/`, then `mvn clean package assembly:single`. Install zip from `target/` in Ghidra. Run `python bridge_mcp_ghidra.py` for MCP server.
