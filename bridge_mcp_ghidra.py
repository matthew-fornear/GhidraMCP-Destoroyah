# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import os
import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

# Timeout for Ghidra HTTP requests (seconds). Decompile/list_data on large programs can take 30s+.
GHIDRA_REQUEST_TIMEOUT = int(os.environ.get("GHIDRA_MCP_TIMEOUT", "600"))

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=GHIDRA_REQUEST_TIMEOUT)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=GHIDRA_REQUEST_TIMEOUT)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=GHIDRA_REQUEST_TIMEOUT)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, code_only: bool = False, ref_type: str = None) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        code_only: If True, return only call/flow refs (e.g. BL call sites); call refs are listed first
        ref_type: Optional filter: "WRITE" (only write refs), "READ" (only read refs), "DATA" (only data refs, no call/flow). Omit for all.
        
    Returns:
        List of references to the specified address
    """
    params = {"address": address, "offset": offset, "limit": limit}
    if code_only:
        params["code_only"] = "true"
    if ref_type:
        params["ref_type"] = ref_type
    return safe_get("xrefs_to", params)

@mcp.tool()
def get_xrefs_to_range(start_address: str, end_address: str, offset: int = 0, limit: int = 100, code_only: bool = False, ref_type: str = None) -> list:
    """
    Get all references to any address in [start_address, end_address] (step 8 bytes).
    Use when a data block (e.g. vtable) has no direct xref to the exact address but
    code may reference somewhere in the range.

    Args:
        start_address: Start of range in hex (e.g. "0xfffffe000b6e8f00")
        end_address: End of range in hex (e.g. "0xfffffe000b6e8f40")
        offset: Pagination offset (default: 0)
        limit: Max refs to return (default: 100)
        code_only: If True, only call/flow refs
        ref_type: Optional "WRITE", "READ", or "DATA" to filter by ref type

    Returns:
        List of "From <addr> in <func> [TYPE] (to <addr>)" lines
    """
    params = {"start": start_address, "end": end_address, "offset": offset, "limit": limit}
    if code_only:
        params["code_only"] = "true"
    if ref_type:
        params["ref_type"] = ref_type
    return safe_get("xrefs_to_range", params)

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, code_only: bool = False) -> list:
    """
    Get all references to the specified function by name (includes refs to entire function body).
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        code_only: If True, return only call/flow refs (call sites); call refs are listed first
        
    Returns:
        List of references to the specified function
    """
    params = {"name": name, "offset": offset, "limit": limit}
    if code_only:
        params["code_only"] = "true"
    return safe_get("function_xrefs", params)

@mcp.tool()
def list_functions_data_only_xrefs(offset: int = 0, limit: int = 100) -> list:
    """
    List functions that have at least one reference and zero code (call/flow) references.
    Use to find vtable slot targets or other functions only referenced from data.

    Args:
        offset: Pagination offset (default: 0)
        limit: Max entries to return (default: 100)

    Returns:
        List of "functionName at address" for functions with data-only xrefs
    """
    return safe_get("functions_data_only_xrefs", {"offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def search_memory_for_value(
    value: str,
    value_size: int = 8,
    max_results: int = 100,
    start_address: str = None,
    end_address: str = None,
) -> list:
    """
    Search memory for a 64-bit or 32-bit value (little-endian). Returns addresses where the value appears.
    Use to find where a function pointer or address is stored (e.g. handler table entries).

    Args:
        value: Hex value (e.g. "0xfffffe00088a7c5c" or "88a7c5c")
        value_size: 4 or 8 bytes (default 8)
        max_results: Stop after this many hits (default 100)
        start_address: Optional start of range to search
        end_address: Optional end of range to search

    Returns:
        List of addresses (hex strings) where the value was found, or ["No matches"]
    """
    params = {"value": value, "size": value_size, "max_results": max_results}
    if start_address:
        params["start"] = start_address
    if end_address:
        params["end"] = end_address
    lines = safe_get("search_memory_value", params)
    if not lines or (len(lines) == 1 and lines[0].startswith("Error")):
        return lines or ["Error: no response"]
    if len(lines) == 1 and lines[0] == "No matches":
        return ["No matches"]
    return lines

@mcp.tool()
def read_memory(address: str, length: int = 8) -> str:
    """
    Read raw bytes at address. Returns hex string (little-endian).
    Use for vtables, pointers, or any fixed address (max 128 bytes).
    """
    if length <= 0 or length > 128:
        length = 8
    lines = safe_get("read_memory", {"address": address, "length": length})
    if not lines or lines[0].startswith("Error"):
        return lines[0] if lines else "Error: no response"
    return lines[0]

@mcp.tool()
def get_pointer_at(address: str) -> str:
    """
    Read 8 bytes at address as a 64-bit pointer (little-endian). Returns hex address.
    Use for vtable slots (e.g. vtable_base+0x100) to get handler function address.
    """
    hex_str = read_memory(address, 8)
    if hex_str.startswith("Error"):
        return hex_str
    if len(hex_str) != 16:
        return f"Error: expected 16 hex chars, got {len(hex_str)}"
    try:
        value = int.from_bytes(bytes.fromhex(hex_str), "little")
        return f"0x{value:x}"
    except (ValueError, TypeError):
        return f"Error: invalid hex {hex_str}"

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()
