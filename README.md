# GhidraMCP - Destoroyah Patch

**Patches**

- **xrefs_to / function_xrefs**  
  Before: No filter; all reference types returned in one list.  
  Why: You need call sites only; mixing in data refs is noise.  
  Patch: Added `code_only` param. When true, only call/flow refs are returned. When false, call/flow refs are listed first so call sites stay at the top.

- **getFunctionXrefs**  
  Before: Ref manager was queried only for the function’s entry address.  
  Why: A BL to the first instruction of a function is a call but was missing.  
  Patch: Refs are gathered for every address in the function body so BL-to-entry is included.

- **Disassembly**  
  Before: Bridge returned disassembly as a list of lines; MCP clients often showed one line or truncated.  
  Why: You need the full listing in the client.  
  Patch: Bridge returns one newline-joined string so the full disassembly is shown.

- **Timeout**  
  Before: HTTP timeout was short (e.g. 5s); decompile and list_data on large binaries often timed out.  
  Why: Large programs (e.g. kernel) need longer.  
  Patch: Default timeout is 600s. Override with `GHIDRA_MCP_TIMEOUT` (seconds) in the environment.

- **get_xrefs_to_range**  
  Before: Only `get_xrefs_to(single address)`; no way to ask for refs to any address in a block.  
  Why: Vtables and data blocks often have no ref to the exact stored address; code references somewhere in the block.  
  Patch: New plugin endpoint and bridge tool `get_xrefs_to_range(start_address, end_address)`. Scans the range in 8-byte steps (up to a cap) and returns all refs to any address in that range.

- **pom.xml**  
  Before: Upstream MCP pom was several versions behind (older Ghidra API version and outdated Maven plugin versions).  
  Why: Build failed or did not match current Ghidra and Maven.  
  Patch: Updated pom to Ghidra 12.0.3 and current plugin versions so the project builds against current tooling.

- **Bridge (bridge_mcp_ghidra.py)**  
  Before: No `code_only` on xref tools; no range xref tool; short fixed timeout for Ghidra HTTP; no way to read memory.  
  Why: Plugin patches above need to be exposed to MCP clients; large binaries need longer timeout; vtable and data audit need reading pointers at an address.  
  Patch: `get_xrefs_to` and `get_function_xrefs` accept `code_only` and pass it through. New tool `get_xrefs_to_range(start_address, end_address, ...)`. All requests use `GHIDRA_MCP_TIMEOUT` (default 600s). Disassembly comes from plugin as full listing; bridge passes it through. New tool `read_memory(address, length)` (hex bytes); `get_pointer_at(address)` (8-byte LE pointer) so vtables and data can be read without the UI.

- **read_memory / get_pointer_at**  
  Before: No way to read raw memory or a pointer at an address via MCP.  
  Why: Resolving OOL vtable slots (+0x100, +0x108, +0x110) and checking data layout requires reading at an address.  
  Patch: Plugin endpoint `/read_memory?address=&length=` (max 128 bytes, returns hex). Bridge tools `read_memory(address, length)` and `get_pointer_at(address)` (8 bytes, little-endian, returns hex address).

- **ref_type filter on xrefs**  
  Before: No way to restrict xrefs by access type (read vs write).  
  Why: Finding writers to a global (e.g. who sets a BSS table) or only data refs (vtable slots) requires filtering by reference type.  
  Patch: Plugin `getXrefsTo` and `getXrefsToRange` accept optional query param `ref_type`: `WRITE`, `READ`, or `DATA`. Bridge tools `get_xrefs_to` and `get_xrefs_to_range` accept `ref_type`. Use `ref_type="WRITE"` to find code that writes to an address; `ref_type="DATA"` for non-call/flow refs only.

- **list_functions_data_only_xrefs**  
  Before: No way to list functions that are only referenced from data (e.g. vtable targets).  
  Why: Auditing OOL handlers or vtables requires finding functions with no code (call/flow) refs—only data refs.  
  Patch: New plugin endpoint `/functions_data_only_xrefs` and bridge tool `list_functions_data_only_xrefs(offset, limit)`. Returns "functionName at address" for each function that has at least one reference and zero call/flow references. May be slow on very large programs.

- **search_memory_for_value**  
  Before: No way to find where a given pointer or value is stored in memory via MCP.  
  Why: Finding handler-table entries (e.g. where the copy_response bug handler pointer is stored) or other data refs requires searching memory for the 64-bit value; xrefs may be missing for the table cell.  
  Patch: Plugin endpoint `/search_memory_value?value=&size=4|8&max_results=&start=&end=` and bridge tool `search_memory_for_value(value, value_size=8, max_results=100, start_address, end_address)`. Scans initialized memory (little-endian) for the value; scan capped at 50 MB. Values are parsed with `Long.parseUnsignedLong` so 64-bit kernel addresses (e.g. `0xfffffe00088a7c5c`) work. Returns one address per line or "No matches". **Tested:** curl to `/search_memory_value` returns 200; search runs (32-bit value test returns "No matches"); after reinstall, 64-bit value finds table entries.

---

GhidraMCP is an MCP server plus a Ghidra plugin. An MCP client (e.g. Cursor) can drive Ghidra: decompile, rename, list methods/classes/imports/exports, xrefs, and more.

**Prerequisites:** Ghidra, Python 3.10+, and the MCP SDK. Install with `pip install mcp requests` or use the repo’s `requirements.txt`.

**Ghidra plugin**
1. Copy Ghidra JARs into `lib/`. From your Ghidra install: `Base.jar`, `Decompiler.jar`, and from `Framework/*/lib/`: `Docking`, `Generic`, `Project`, `SoftwareModeling`, `Utility`, `Gui`.
2. Build: `mvn clean package` then `mvn assembly:single` (or `mvn clean package assembly:single`). The zip is in `target/`.
3. In Ghidra: File → Install Extensions → + → choose the zip from `target/` → restart. Turn the plugin on in File → Configure → Developer. To change the HTTP port: Edit → Tool Options → GhidraMCP HTTP Server.

**Bridge (MCP server)**  
Run `python bridge_mcp_ghidra.py`. It talks to Ghidra at `http://127.0.0.1:8080/` by default. To use another host or port, pass `--ghidra-server` or set it in your MCP config. To change how long the bridge waits for Ghidra, set `GHIDRA_MCP_TIMEOUT` in the environment (seconds; default 600). Exposed tools include `get_xrefs_to`, `get_xrefs_to_range` (with optional `ref_type`: WRITE, READ, DATA), `list_functions_data_only_xrefs`, and `search_memory_for_value(value, value_size=8, max_results=100, start_address, end_address)` to find where a pointer/value is stored in memory.

**Cursor**  
In MCP settings, set the command to `python` and the args to the path to `bridge_mcp_ghidra.py` and `--ghidra-server` and your Ghidra URL (e.g. `http://127.0.0.1:8080/`).

**Build from source:** Java 11+ and Maven. The JARs in `lib/` are not in the repo; copy them from your Ghidra install as above.