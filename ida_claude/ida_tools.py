"""IDA-side tool implementations exposed to Claude via the Messages API
tool-use protocol. Each @tool-decorated function:
  * returns (result_text, is_error)
  * must be safe to call on the main IDA thread (the chat widget marshals
    calls through idaapi.execute_sync)
"""
import idaapi
import idautils
import idc
import ida_bytes
import ida_kernwin
import ida_name
import ida_segment

try:
    import ida_ida
except Exception:
    ida_ida = None

try:
    import ida_entry
except Exception:
    ida_entry = None

try:
    import ida_typeinf
except Exception:
    ida_typeinf = None

try:
    import ida_frame
except Exception:
    ida_frame = None

try:
    import ida_struct
except Exception:
    ida_struct = None

try:
    import ida_enum
except Exception:
    ida_enum = None

try:
    import ida_hexrays
    _HEXRAYS_OK = True
except Exception:
    _HEXRAYS_OK = False


# ---------- registry ----------

_TOOL_REGISTRY = []


def tool(name, description, schema):
    def deco(fn):
        _TOOL_REGISTRY.append({
            "name": name,
            "description": description,
            "input_schema": schema,
            "_fn": fn,
        })
        return fn
    return deco


def get_tool_defs():
    """Return the list of tool definitions for the Anthropic API payload."""
    out = []
    for t in _TOOL_REGISTRY:
        out.append({k: v for k, v in t.items() if not k.startswith("_")})
    return out


# Undo journal populated by write-tool wrappers. Each entry is a dict with
# enough info to revert: {"fn": callable, "label": str}. The UI reads
# pop_undo_batch() at the end of an agent turn so a single Undo click reverts
# the whole batch.
_UNDO_STACK = []


def _record_undo(label, revert_fn):
    _UNDO_STACK.append({"label": label, "fn": revert_fn})


def pop_undo_batch():
    """Return and clear the pending undo entries, oldest first."""
    out = list(_UNDO_STACK)
    _UNDO_STACK[:] = []
    return out


def revert_entries(entries):
    """Apply revert_fn for each entry (latest change first). Returns list of
    (label, ok, err) tuples."""
    results = []
    for e in reversed(entries):
        try:
            e["fn"]()
            results.append((e["label"], True, ""))
        except Exception as ex:
            results.append((e["label"], False, str(ex)))
    return results


# Dry-run flag is flipped by the UI before dispatch and consumed by the
# write-tool wrappers. When true, write tools describe what they would do
# instead of mutating the database.
_DRY_RUN = {"on": False}


def set_dry_run(on):
    _DRY_RUN["on"] = bool(on)


def _is_dry_run():
    return _DRY_RUN["on"]


def dispatch(name, params):
    for t in _TOOL_REGISTRY:
        if t["name"] == name:
            try:
                return t["_fn"](**(params or {}))
            except TypeError as e:
                return ("Bad arguments for %s: %s" % (name, e), True)
            except Exception as e:
                return ("Tool %s raised: %s" % (name, e), True)
    return ("Unknown tool: %s" % name, True)


# ---------- helpers ----------

def _resolve(target):
    """Accept a function name, label, or hex/decimal address. Returns ea or BADADDR."""
    if target is None:
        return idaapi.BADADDR
    s = str(target).strip()
    if not s:
        return idaapi.BADADDR
    if s.lower().startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            return idaapi.BADADDR
    ea = idc.get_name_ea_simple(s)
    if ea != idaapi.BADADDR:
        return ea
    try:
        return int(s, 16)
    except ValueError:
        return idaapi.BADADDR


# Shared with ida_context.py -- same implementation, re-export to keep a
# single source of truth.
from ida_claude.ida_context import _func_disasm, _try_decompile  # noqa: F401


def _min_ea():
    if ida_ida is not None and hasattr(ida_ida, "inf_get_min_ea"):
        try:
            return ida_ida.inf_get_min_ea()
        except Exception:
            pass
    return getattr(idaapi.cvar.inf, "min_ea", idaapi.BADADDR)


def _max_ea():
    if ida_ida is not None and hasattr(ida_ida, "inf_get_max_ea"):
        try:
            return ida_ida.inf_get_max_ea()
        except Exception:
            pass
    return getattr(idaapi.cvar.inf, "max_ea", idaapi.BADADDR)


# ---------- read tools ----------

@tool(
    "read_function",
    "Return disassembly and (when available) Hex-Rays decompilation for a function. "
    "Target may be a function name or a hex address.",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "include_decompilation": {"type": "boolean", "default": True},
            "max_disasm_lines": {"type": "integer", "default": 400},
        },
        "required": ["target"],
    },
)
def read_function(target, include_decompilation=True, max_disasm_lines=400):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Address 0x%X is not inside a function" % ea, True)
    name = idc.get_func_name(func.start_ea) or ("sub_%X" % func.start_ea)
    parts = [
        "Function: %s  (0x%X - 0x%X, size=%d)" % (name, func.start_ea, func.end_ea, func.end_ea - func.start_ea),
        "",
        "Disassembly:",
        _func_disasm(func, max_disasm_lines),
    ]
    if include_decompilation:
        pc = _try_decompile(func.start_ea)
        if pc:
            parts += ["", "Decompilation (Hex-Rays):", pc]
    return ("\n".join(parts), False)


@tool(
    "list_functions",
    "List function names in the database, optionally filtered by substring. Use this to explore what functions exist.",
    {
        "type": "object",
        "properties": {
            "filter": {"type": "string", "description": "Case-insensitive substring to match on function name."},
            "limit": {"type": "integer", "default": 200},
        },
    },
)
def list_functions(filter="", limit=200):
    rows = []
    needle = (filter or "").lower()
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if needle and needle not in name.lower():
            continue
        rows.append("0x%08X  %s" % (ea, name))
        if len(rows) >= limit:
            rows.append("... (truncated at %d)" % limit)
            break
    return ("\n".join(rows) or "(no matching functions)", False)


@tool(
    "list_strings",
    "List strings found in the binary, optionally filtered by substring.",
    {
        "type": "object",
        "properties": {
            "filter": {"type": "string"},
            "limit": {"type": "integer", "default": 200},
        },
    },
)
def list_strings(filter="", limit=200):
    rows = []
    needle = (filter or "").lower()
    try:
        strings = idautils.Strings()
    except Exception as e:
        return ("idautils.Strings() failed: %s" % e, True)
    for s in strings:
        text = str(s)
        if needle and needle not in text.lower():
            continue
        rows.append("0x%08X  %s" % (s.ea, text))
        if len(rows) >= limit:
            rows.append("... (truncated at %d)" % limit)
            break
    return ("\n".join(rows) or "(no matching strings)", False)


@tool(
    "list_imports",
    "List imported APIs (module + name + address). Useful to spot crypto, networking, anti-debug, etc.",
    {
        "type": "object",
        "properties": {
            "filter": {"type": "string"},
        },
    },
)
def list_imports(filter=""):
    needle = (filter or "").lower()
    rows = []
    nmods = idaapi.get_import_module_qty()
    for i in range(nmods):
        modname = idaapi.get_import_module_name(i) or "?"

        def cb(ea, name, ord_, _mod=modname):
            if name and (not needle or needle in name.lower()):
                rows.append("[%s] 0x%08X  %s" % (_mod, ea, name))
            return True

        idaapi.enum_import_names(i, cb)
    return ("\n".join(rows) or "(no matching imports)", False)


@tool(
    "list_exports",
    "List exported symbols (name + address + ordinal). Useful to see what the binary publishes.",
    {
        "type": "object",
        "properties": {
            "filter": {"type": "string"},
            "limit": {"type": "integer", "default": 500},
        },
    },
)
def list_exports(filter="", limit=500):
    if ida_entry is None:
        return ("ida_entry not available", True)
    needle = (filter or "").lower()
    rows = []
    qty = ida_entry.get_entry_qty()
    for i in range(qty):
        ord_ = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ord_)
        name = ida_entry.get_entry_name(ord_) or ""
        if needle and needle not in name.lower():
            continue
        rows.append("0x%08X  %s  (ord=%d)" % (ea, name, ord_))
        if len(rows) >= limit:
            rows.append("... (truncated at %d)" % limit)
            break
    return ("\n".join(rows) or "(no matching exports)", False)


@tool(
    "list_segments",
    "List memory segments with range, permissions, and class (.text/.data/...).",
    {"type": "object", "properties": {}},
)
def list_segments():
    rows = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        name = ida_segment.get_segm_name(seg) or "?"
        perm = seg.perm
        p = "".join([
            "R" if perm & ida_segment.SEGPERM_READ else "-",
            "W" if perm & ida_segment.SEGPERM_WRITE else "-",
            "X" if perm & ida_segment.SEGPERM_EXEC else "-",
        ])
        sclass = ida_segment.get_segm_class(seg) or ""
        rows.append("%-16s 0x%08X-0x%08X  %s  class=%s"
                    % (name, seg.start_ea, seg.end_ea, p, sclass))
        seg = ida_segment.get_next_seg(seg.start_ea)
    return ("\n".join(rows) or "(no segments)", False)


@tool(
    "list_entry_points",
    "List the binary's declared entry points (main, DllMain, exports used as entries).",
    {"type": "object", "properties": {}},
)
def list_entry_points():
    if ida_entry is None:
        return ("ida_entry not available", True)
    rows = []
    qty = ida_entry.get_entry_qty()
    for i in range(qty):
        ord_ = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ord_)
        name = ida_entry.get_entry_name(ord_) or ""
        rows.append("0x%08X  %s  (ord=%d)" % (ea, name, ord_))
    return ("\n".join(rows) or "(no entry points)", False)


def _compile_pattern(pattern):
    """Compile a hex pattern like 'DE AD BE EF' (optionally with '?' wildcards)
    into a compiled_binpat_vec_t usable by ida_bytes.bin_search.
    Returns the vector or None if unavailable."""
    if not hasattr(ida_bytes, "compiled_binpat_vec_t"):
        return None
    if not hasattr(ida_bytes, "parse_binpat_str"):
        return None
    patterns = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(patterns, _min_ea(), pattern, 16)
    # IDA 9 returns None on success / a str on error; older returns bool.
    if err is False or (isinstance(err, str) and err):
        return None
    return patterns


@tool(
    "search_bytes",
    "Search for a hex byte pattern (e.g. 'DE AD BE EF' or with wildcards '48 8B ? ?'). "
    "Returns matching addresses.",
    {
        "type": "object",
        "properties": {
            "pattern": {"type": "string"},
            "limit": {"type": "integer", "default": 64},
        },
        "required": ["pattern"],
    },
)
def search_bytes(pattern, limit=64):
    limit = max(1, min(int(limit), 1024))
    start = _min_ea()
    end = _max_ea()
    rows = []
    patterns = _compile_pattern(pattern)
    if patterns is None:
        # Fallback to deprecated ida_search.find_binary for older IDA.
        try:
            import ida_search
            ea = start
            while ea < end and len(rows) < limit:
                ea = ida_search.find_binary(ea, end, pattern, 16,
                                            ida_search.SEARCH_DOWN)
                if ea == idaapi.BADADDR:
                    break
                rows.append("0x%08X" % ea)
                ea += 1
        except Exception as e:
            return ("Pattern search unavailable: %s" % e, True)
    else:
        ea = start
        flags = getattr(ida_bytes, "BIN_SEARCH_FORWARD", 0)
        while ea < end and len(rows) < limit:
            try:
                found = ida_bytes.bin_search(ea, end, patterns, flags)
            except TypeError:
                # Some IDA builds require 6 args (start, end, patterns,
                # flags, src_flags, ...). Best-effort stop.
                break
            if isinstance(found, tuple):
                found_ea = found[0] if found else idaapi.BADADDR
            else:
                found_ea = found
            if found_ea == idaapi.BADADDR:
                break
            rows.append("0x%08X" % found_ea)
            ea = found_ea + 1
    return ("\n".join(rows) or "(no matches)", False)


@tool(
    "search_immediate",
    "Search the database for instructions whose operand equals a given "
    "immediate value (e.g. crypto constants like 0x67452301). Decimal or hex.",
    {
        "type": "object",
        "properties": {
            "value": {"type": "string"},
            "limit": {"type": "integer", "default": 64},
        },
        "required": ["value"],
    },
)
def search_immediate(value, limit=64):
    s = str(value).strip()
    try:
        v = int(s, 16) if s.lower().startswith("0x") else int(s, 0)
    except ValueError:
        return ("Could not parse value as integer: %r" % value, True)
    limit = max(1, min(int(limit), 1024))
    rows = []
    for ea in idautils.Heads(_min_ea(), _max_ea()):
        if not idc.is_code(idc.get_full_flags(ea)):
            continue
        for opn in range(3):
            try:
                t = idc.get_operand_type(ea, opn)
            except Exception:
                break
            if t == idc.o_void:
                break
            if t == idc.o_imm and idc.get_operand_value(ea, opn) == v:
                disasm = idc.generate_disasm_line(ea, 0) or ""
                rows.append("0x%08X  %s" % (ea, disasm))
                break
        if len(rows) >= limit:
            rows.append("... (truncated at %d)" % limit)
            break
    return ("\n".join(rows) or "(no matches)", False)


@tool(
    "get_xrefs_to",
    "List cross-references TO the given target (who calls/reads it).",
    {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
    },
)
def get_xrefs_to(target):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    rows = []
    for x in idautils.XrefsTo(ea):
        caller_func = idaapi.get_func(x.frm)
        caller_name = idc.get_func_name(caller_func.start_ea) if caller_func else ""
        rows.append("0x%08X  in %s  (type=%d)" % (x.frm, caller_name or "?", x.type))
    return ("\n".join(rows) or "(no xrefs)", False)


@tool(
    "get_xrefs_from",
    "List cross-references FROM the given function (what it calls / accesses).",
    {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
    },
)
def get_xrefs_from(target):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    rows = []
    if func:
        for insn_ea in idautils.FuncItems(func.start_ea):
            for x in idautils.XrefsFrom(insn_ea, 0):
                if x.to == idaapi.BADADDR:
                    continue
                tname = idc.get_name(x.to) or ""
                rows.append("0x%08X -> 0x%08X  %s  (type=%d)" % (insn_ea, x.to, tname, x.type))
    else:
        for x in idautils.XrefsFrom(ea):
            rows.append("0x%08X -> 0x%08X  (type=%d)" % (x.frm, x.to, x.type))
    return ("\n".join(rows) or "(no xrefs)", False)


@tool(
    "get_callees",
    "List the functions called by the given function (direct call instructions only). "
    "Use this instead of get_xrefs_from when you only care about calls, not data refs.",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "limit": {"type": "integer", "default": 256},
        },
        "required": ["target"],
    },
)
def get_callees(target, limit=256):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    seen = {}
    for insn_ea in idautils.FuncItems(func.start_ea):
        if not idaapi.is_call_insn(insn_ea):
            continue
        for x in idautils.XrefsFrom(insn_ea, 0):
            if x.to == idaapi.BADADDR:
                continue
            callee = idaapi.get_func(x.to)
            key = callee.start_ea if callee else x.to
            name = (idc.get_func_name(callee.start_ea) if callee
                    else (idc.get_name(x.to) or ""))
            row = seen.setdefault(key, {"name": name or ("sub_%X" % key),
                                        "sites": []})
            row["sites"].append(insn_ea)
            if len(seen) >= limit:
                break
    lines = []
    for key, row in sorted(seen.items()):
        sites = ", ".join("0x%X" % s for s in row["sites"][:6])
        more = "" if len(row["sites"]) <= 6 else " +%d more" % (len(row["sites"]) - 6)
        lines.append("0x%08X  %s  (called from %s%s)" %
                     (key, row["name"], sites, more))
    return ("\n".join(lines) or "(no callees)", False)


@tool(
    "get_callers",
    "List the functions that call the given function (via code xrefs to its start).",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "limit": {"type": "integer", "default": 256},
        },
        "required": ["target"],
    },
)
def get_callers(target, limit=256):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    start = func.start_ea if func else ea
    seen = {}
    for x in idautils.XrefsTo(start):
        caller_func = idaapi.get_func(x.frm)
        if caller_func is None:
            key = x.frm
            name = idc.get_name(x.frm) or ""
        else:
            key = caller_func.start_ea
            name = idc.get_func_name(caller_func.start_ea) or ""
        row = seen.setdefault(key, {"name": name or ("sub_%X" % key),
                                    "sites": []})
        row["sites"].append(x.frm)
        if len(seen) >= limit:
            break
    lines = []
    for key, row in sorted(seen.items()):
        sites = ", ".join("0x%X" % s for s in row["sites"][:6])
        more = "" if len(row["sites"]) <= 6 else " +%d more" % (len(row["sites"]) - 6)
        lines.append("0x%08X  %s  (sites: %s%s)" %
                     (key, row["name"], sites, more))
    return ("\n".join(lines) or "(no callers)", False)


@tool(
    "disassemble_range",
    "Disassemble an address range (useful for non-function code / data blobs).",
    {
        "type": "object",
        "properties": {
            "start": {"type": "string"},
            "end": {"type": "string"},
            "max_lines": {"type": "integer", "default": 400},
        },
        "required": ["start", "end"],
    },
)
def disassemble_range(start, end, max_lines=400):
    s = _resolve(start)
    e = _resolve(end)
    if s == idaapi.BADADDR or e == idaapi.BADADDR:
        return ("Could not resolve range: %r..%r" % (start, end), True)
    if e <= s:
        return ("End must be greater than start", True)
    lines = []
    for ea in idautils.Heads(s, e):
        dis = idc.generate_disasm_line(ea, 0) or ""
        lines.append("  %08X  %s" % (ea, dis))
        if len(lines) >= max_lines:
            lines.append("  ... (truncated at %d lines)" % max_lines)
            break
    return ("\n".join(lines) or "(empty range)", False)


@tool(
    "decompile_range",
    "Decompile every function whose start falls inside the given address range. "
    "Hex-Rays decompiles per-function, so this returns each function's "
    "pseudocode concatenated.",
    {
        "type": "object",
        "properties": {
            "start": {"type": "string"},
            "end": {"type": "string"},
        },
        "required": ["start", "end"],
    },
)
def decompile_range(start, end):
    if not _HEXRAYS_OK:
        return ("Hex-Rays not available", True)
    s = _resolve(start)
    e = _resolve(end)
    if s == idaapi.BADADDR or e == idaapi.BADADDR:
        return ("Could not resolve range: %r..%r" % (start, end), True)
    if e <= s:
        return ("End must be greater than start", True)
    parts = []
    for fea in idautils.Functions(s, e):
        name = idc.get_func_name(fea) or ("sub_%X" % fea)
        pc = _try_decompile(fea) or "(no decompilation)"
        parts.append("=== %s (0x%X) ===\n%s" % (name, fea, pc))
    return ("\n\n".join(parts) or "(no functions in range)", False)


@tool(
    "read_bytes",
    "Read raw bytes at an address, returned as hex. Size is clamped to [1, 4096].",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "size": {"type": "integer", "default": 64},
        },
        "required": ["address"],
    },
)
def read_bytes(address, size=64):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    size = max(1, min(int(size), 4096))
    data = ida_bytes.get_bytes(ea, size) or b""
    hexed = " ".join("%02X" % b for b in data)
    ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ("0x%08X: %s\n           %s" % (ea, hexed, ascii_view), False)


@tool(
    "get_current_address",
    "Return the address of the IDA cursor and the function it sits in.",
    {"type": "object", "properties": {}},
)
def get_current_address():
    ea = idc.get_screen_ea()
    f = idaapi.get_func(ea)
    fname = idc.get_func_name(f.start_ea) if f else ""
    return ("cursor=0x%X function=%s" % (ea, fname or "(none)"), False)


@tool(
    "get_function_info",
    "Return metadata for a function: name, bounds, prototype (if set), and first line of the decompilation.",
    {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
    },
)
def get_function_info(target):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    name = idc.get_func_name(func.start_ea) or ""
    proto = idc.get_type(func.start_ea) or ""
    comment = idc.get_func_cmt(func.start_ea, 0) or ""
    return ("name=%s\nrange=0x%X-0x%X\nprototype=%s\ncomment=%s"
            % (name, func.start_ea, func.end_ea, proto, comment), False)


@tool(
    "get_stack_frame",
    "Return the stack-frame layout for a function: each member's offset, size, "
    "name, and type (as currently recorded in the IDB).",
    {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
    },
)
def get_stack_frame(target):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    frame_id = idc.get_frame_id(func.start_ea)
    if frame_id == idaapi.BADADDR or frame_id is None:
        return ("(no stack frame)", False)
    rows = []
    # Prefer tinfo_t UDT walk if available, fall back to ida_struct.
    if ida_struct is not None and hasattr(ida_struct, "get_struc"):
        st = ida_struct.get_struc(frame_id)
        if st is not None:
            off = ida_struct.get_struc_first_offset(st)
            while off != idaapi.BADADDR:
                mem = ida_struct.get_member(st, off)
                if mem is not None:
                    mname = ida_struct.get_member_name(mem.id) or ""
                    msize = ida_struct.get_member_size(mem)
                    mtype = idc.get_member_type(frame_id, off) or ""
                    rows.append("  +0x%X  size=%d  %s : %s"
                                % (off, msize, mname, mtype))
                off = ida_struct.get_struc_next_offset(st, off)
    if not rows:
        # ida 9: use idc.get_member_name iteration fallback.
        off = 0
        last = idc.get_struc_size(frame_id)
        while off < last:
            mname = idc.get_member_name(frame_id, off) or ""
            if mname:
                msize = idc.get_member_size(frame_id, off)
                mtype = idc.get_member_type(frame_id, off) or ""
                rows.append("  +0x%X  size=%d  %s : %s"
                            % (off, msize, mname, mtype))
                off += max(msize, 1)
            else:
                off += 1
    return ("\n".join(rows) or "(empty frame)", False)


@tool(
    "list_structs",
    "List user-defined structures in the database.",
    {
        "type": "object",
        "properties": {
            "filter": {"type": "string"},
            "limit": {"type": "integer", "default": 200},
        },
    },
)
def list_structs(filter="", limit=200):
    needle = (filter or "").lower()
    rows = []
    if ida_struct is not None and hasattr(ida_struct, "get_first_struc_idx"):
        idx = ida_struct.get_first_struc_idx()
        while idx != idaapi.BADADDR:
            sid = ida_struct.get_struc_by_idx(idx)
            if sid != idaapi.BADADDR:
                name = ida_struct.get_struc_name(sid) or ""
                size = ida_struct.get_struc_size(sid)
                if not needle or needle in name.lower():
                    rows.append("%s  size=%d  (id=0x%X)" % (name, size, sid))
            idx = ida_struct.get_next_struc_idx(idx)
            if len(rows) >= limit:
                rows.append("... (truncated at %d)" % limit)
                break
        return ("\n".join(rows) or "(no structs)", False)
    # Modern IDA: iterate the idati type library.
    if ida_typeinf is not None:
        til = ida_typeinf.get_idati()
        qty = ida_typeinf.get_ordinal_limit(til) or 0
        for ord_ in range(1, qty):
            name = ida_typeinf.get_numbered_type_name(til, ord_) or ""
            if not name:
                continue
            ti = ida_typeinf.tinfo_t()
            if not ti.get_numbered_type(til, ord_):
                continue
            if not ti.is_struct():
                continue
            if needle and needle not in name.lower():
                continue
            rows.append("%s  size=%d  (ord=%d)" %
                        (name, ti.get_size() or 0, ord_))
            if len(rows) >= limit:
                rows.append("... (truncated at %d)" % limit)
                break
    return ("\n".join(rows) or "(no structs)", False)


@tool(
    "get_struct",
    "Return the layout of a named structure: offset, size, name, and type per member.",
    {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    },
)
def get_struct(name):
    if ida_struct is not None and hasattr(ida_struct, "get_struc_id"):
        sid = ida_struct.get_struc_id(name)
        if sid != idaapi.BADADDR:
            st = ida_struct.get_struc(sid)
            rows = ["struct %s  size=%d" % (name, ida_struct.get_struc_size(sid))]
            off = ida_struct.get_struc_first_offset(st)
            while off != idaapi.BADADDR:
                mem = ida_struct.get_member(st, off)
                if mem is not None:
                    mname = ida_struct.get_member_name(mem.id) or ""
                    msize = ida_struct.get_member_size(mem)
                    mtype = idc.get_member_type(sid, off) or ""
                    rows.append("  +0x%X  size=%d  %s : %s"
                                % (off, msize, mname, mtype))
                off = ida_struct.get_struc_next_offset(st, off)
            return ("\n".join(rows), False)
    if ida_typeinf is not None:
        ti = ida_typeinf.tinfo_t()
        if ti.get_named_type(ida_typeinf.get_idati(), name) and ti.is_struct():
            udt = ida_typeinf.udt_type_data_t()
            if ti.get_udt_details(udt):
                rows = ["struct %s  size=%d" % (name, ti.get_size() or 0)]
                for m in udt:
                    mt = str(m.type) if m.type else ""
                    rows.append("  +0x%X  size=%d  %s : %s"
                                % (m.offset // 8, (m.size or 0) // 8,
                                   m.name or "", mt))
                return ("\n".join(rows), False)
    return ("No struct named %r" % name, True)


@tool(
    "list_enums",
    "List user-defined enumerations in the database.",
    {
        "type": "object",
        "properties": {
            "filter": {"type": "string"},
            "limit": {"type": "integer", "default": 200},
        },
    },
)
def list_enums(filter="", limit=200):
    needle = (filter or "").lower()
    rows = []
    if ida_enum is not None and hasattr(ida_enum, "get_enum_qty"):
        qty = ida_enum.get_enum_qty()
        for i in range(qty):
            eid = ida_enum.getn_enum(i)
            name = ida_enum.get_enum_name(eid) or ""
            if needle and needle not in name.lower():
                continue
            rows.append("%s  (id=0x%X)" % (name, eid))
            if len(rows) >= limit:
                rows.append("... (truncated at %d)" % limit)
                break
        return ("\n".join(rows) or "(no enums)", False)
    # Fall back to iterating numbered types, filtering for is_enum.
    if ida_typeinf is not None:
        til = ida_typeinf.get_idati()
        qty = ida_typeinf.get_ordinal_limit(til) or 0
        for ord_ in range(1, qty):
            name = ida_typeinf.get_numbered_type_name(til, ord_) or ""
            if not name:
                continue
            ti = ida_typeinf.tinfo_t()
            if not ti.get_numbered_type(til, ord_):
                continue
            if not ti.is_enum():
                continue
            if needle and needle not in name.lower():
                continue
            rows.append("%s  (ord=%d)" % (name, ord_))
            if len(rows) >= limit:
                rows.append("... (truncated at %d)" % limit)
                break
    return ("\n".join(rows) or "(no enums)", False)


# ---------- write tools (guarded by 'allow edits' in the UI) ----------

@tool(
    "rename",
    "Rename a function, label, or address. Use for assigning meaningful names "
    "after understanding what code does.",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "new_name": {"type": "string"},
        },
        "required": ["target", "new_name"],
    },
)
def rename(target, new_name):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    old = idc.get_name(ea) or ""
    if _is_dry_run():
        return ("(dry-run) would rename 0x%X '%s' -> '%s'" % (ea, old, new_name), False)
    flags = ida_name.SN_NOWARN | ida_name.SN_FORCE
    ok = idaapi.set_name(ea, new_name, flags)
    if ok:
        _record_undo(
            "rename 0x%X '%s' <- '%s'" % (ea, new_name, old),
            lambda _ea=ea, _old=old: idaapi.set_name(_ea, _old, flags),
        )
    return (("Renamed 0x%X '%s' -> '%s'" % (ea, old, new_name)) if ok
            else ("set_name failed for 0x%X -> %s" % (ea, new_name)), not ok)


@tool(
    "add_comment",
    "Add a comment at a given address (regular or repeatable).",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "comment": {"type": "string"},
            "repeatable": {"type": "boolean", "default": False},
        },
        "required": ["address", "comment"],
    },
)
def add_comment(address, comment, repeatable=False):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    old = idc.get_cmt(ea, 1 if repeatable else 0) or ""
    if _is_dry_run():
        return ("(dry-run) would set comment at 0x%X to %r" % (ea, comment), False)
    ok = idc.set_cmt(ea, comment, 1 if repeatable else 0)
    if ok:
        rep = 1 if repeatable else 0
        _record_undo(
            "comment 0x%X" % ea,
            lambda _ea=ea, _old=old, _rep=rep: idc.set_cmt(_ea, _old, _rep),
        )
    return (("Comment set at 0x%X" % ea) if ok
            else ("Failed to set comment at 0x%X" % ea), not ok)


@tool(
    "set_function_comment",
    "Set the function-wide comment (shown at the top of the function).",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "comment": {"type": "string"},
            "repeatable": {"type": "boolean", "default": False},
        },
        "required": ["target", "comment"],
    },
)
def set_function_comment(target, comment, repeatable=False):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    old = idc.get_func_cmt(func.start_ea, 1 if repeatable else 0) or ""
    if _is_dry_run():
        return ("(dry-run) would set func comment on %s to %r"
                % (idc.get_func_name(func.start_ea) or "?", comment), False)
    ok = idc.set_func_cmt(func.start_ea, comment, 1 if repeatable else 0)
    if ok:
        rep = 1 if repeatable else 0
        start = func.start_ea
        _record_undo(
            "func comment on %s" % (idc.get_func_name(start) or "?"),
            lambda _s=start, _old=old, _rep=rep: idc.set_func_cmt(_s, _old, _rep),
        )
    return (("Function comment set on %s" % (idc.get_func_name(func.start_ea) or "?"))
            if ok else ("Failed to set function comment"), not ok)


@tool(
    "set_function_prototype",
    "Apply a C-style prototype to a function, e.g. 'int __cdecl main(int argc, char** argv)'.",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "prototype": {"type": "string"},
        },
        "required": ["target", "prototype"],
    },
)
def set_function_prototype(target, prototype):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    old = idc.get_type(func.start_ea) or ""
    if _is_dry_run():
        return ("(dry-run) would set prototype on %s to %r"
                % (idc.get_func_name(func.start_ea) or "?", prototype), False)
    if not idc.SetType(func.start_ea, prototype):
        return ("SetType failed (bad prototype?): %r" % prototype, True)
    start = func.start_ea
    _record_undo(
        "prototype on %s" % (idc.get_func_name(start) or "?"),
        lambda _s=start, _old=old: idc.SetType(_s, _old) if _old else None,
    )
    return ("Prototype applied to %s" % (idc.get_func_name(func.start_ea) or "?"), False)


@tool(
    "set_func_return_type",
    "Change just the return type of a function, keeping arguments and calling "
    "convention intact.",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "return_type": {"type": "string"},
        },
        "required": ["target", "return_type"],
    },
)
def set_func_return_type(target, return_type):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    if ida_typeinf is None:
        return ("ida_typeinf not available", True)
    ti = ida_typeinf.tinfo_t()
    if not ida_typeinf.guess_tinfo(ti, func.start_ea):
        # Fall back to the stored type if guess fails.
        if not ti.get_type_by_tid(func.start_ea):
            return ("Could not fetch current prototype", True)
    ftd = ida_typeinf.func_type_data_t()
    if not ti.get_func_details(ftd):
        return ("Not a function type", True)
    new_ret = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(new_ret, None, return_type + ";", 0):
        return ("Could not parse return type: %r" % return_type, True)
    old = idc.get_type(func.start_ea) or ""
    if _is_dry_run():
        return ("(dry-run) would set return type of %s to %r"
                % (idc.get_func_name(func.start_ea) or "?", return_type), False)
    ftd.rettype = new_ret
    new_ti = ida_typeinf.tinfo_t()
    if not new_ti.create_func(ftd):
        return ("create_func failed", True)
    if not ida_typeinf.apply_tinfo(func.start_ea, new_ti, 0):
        return ("apply_tinfo failed", True)
    start = func.start_ea
    _record_undo(
        "return type on %s" % (idc.get_func_name(start) or "?"),
        lambda _s=start, _old=old: idc.SetType(_s, _old) if _old else None,
    )
    return ("Return type of %s set to %s"
            % (idc.get_func_name(func.start_ea) or "?", return_type), False)


@tool(
    "rename_lvar",
    "Rename a local variable / argument in the Hex-Rays decompilation of a "
    "function. 'old_name' is the current name visible in the pseudocode.",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "old_name": {"type": "string"},
            "new_name": {"type": "string"},
        },
        "required": ["target", "old_name", "new_name"],
    },
)
def rename_lvar(target, old_name, new_name):
    if not _HEXRAYS_OK:
        return ("Hex-Rays not available", True)
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    if _is_dry_run():
        return ("(dry-run) would rename lvar '%s' -> '%s' in %s"
                % (old_name, new_name,
                   idc.get_func_name(func.start_ea) or "?"), False)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:
        return ("decompile failed: %s" % e, True)
    if cfunc is None:
        return ("decompile returned None", True)
    lv = None
    for v in cfunc.get_lvars():
        if v.name == old_name:
            lv = v
            break
    if lv is None:
        return ("No lvar named %r in %s"
                % (old_name, idc.get_func_name(func.start_ea) or "?"), True)
    lsi = ida_hexrays.lvar_saved_info_t()
    lsi.ll = lv
    lsi.name = new_name
    ok = ida_hexrays.modify_user_lvar_info(
        func.start_ea, ida_hexrays.MLI_NAME, lsi)
    if ok:
        start = func.start_ea
        revert = ida_hexrays.lvar_saved_info_t()
        revert.ll = lv
        revert.name = old_name
        _record_undo(
            "lvar rename %s: '%s' <- '%s'"
            % (idc.get_func_name(start) or "?", new_name, old_name),
            lambda _s=start, _r=revert: ida_hexrays.modify_user_lvar_info(
                _s, ida_hexrays.MLI_NAME, _r),
        )
    return (("Renamed lvar '%s' -> '%s'" % (old_name, new_name)) if ok
            else ("modify_user_lvar_info failed"), not ok)


@tool(
    "set_lvar_type",
    "Change the type of a local variable / argument in the Hex-Rays "
    "decompilation (e.g. 'char *', 'int', 'MY_STRUCT *').",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "lvar_name": {"type": "string"},
            "type": {"type": "string"},
        },
        "required": ["target", "lvar_name", "type"],
    },
)
def set_lvar_type(target, lvar_name, type):
    if not _HEXRAYS_OK:
        return ("Hex-Rays not available", True)
    if ida_typeinf is None:
        return ("ida_typeinf not available", True)
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    if _is_dry_run():
        return ("(dry-run) would set lvar '%s' type to %r in %s"
                % (lvar_name, type,
                   idc.get_func_name(func.start_ea) or "?"), False)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:
        return ("decompile failed: %s" % e, True)
    if cfunc is None:
        return ("decompile returned None", True)
    lv = None
    for v in cfunc.get_lvars():
        if v.name == lvar_name:
            lv = v
            break
    if lv is None:
        return ("No lvar named %r" % lvar_name, True)
    ti = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(ti, None, type + ";", 0):
        return ("Could not parse type %r" % type, True)
    old_type = str(lv.type()) if lv.type() else ""
    lsi = ida_hexrays.lvar_saved_info_t()
    lsi.ll = lv
    lsi.type = ti
    ok = ida_hexrays.modify_user_lvar_info(
        func.start_ea, ida_hexrays.MLI_TYPE, lsi)
    if ok and old_type:
        old_ti = ida_typeinf.tinfo_t()
        if ida_typeinf.parse_decl(old_ti, None, old_type + ";", 0):
            start = func.start_ea
            revert = ida_hexrays.lvar_saved_info_t()
            revert.ll = lv
            revert.type = old_ti
            _record_undo(
                "lvar %s.%s type" % (idc.get_func_name(start) or "?",
                                     lvar_name),
                lambda _s=start, _r=revert:
                    ida_hexrays.modify_user_lvar_info(
                        _s, ida_hexrays.MLI_TYPE, _r),
            )
    return (("Set lvar '%s' type to %s" % (lvar_name, type)) if ok
            else ("modify_user_lvar_info failed"), not ok)


@tool(
    "create_struct",
    "Create a new empty structure with the given name. Use add_struct_member "
    "afterwards to populate it.",
    {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    },
)
def create_struct(name):
    if _is_dry_run():
        return ("(dry-run) would create struct %r" % name, False)
    if ida_struct is not None and hasattr(ida_struct, "add_struc"):
        sid = ida_struct.add_struc(idaapi.BADADDR, name, False)
        if sid == idaapi.BADADDR:
            return ("add_struc failed (duplicate name?): %r" % name, True)
        _record_undo(
            "create_struct %s" % name,
            lambda _sid=sid: ida_struct.del_struc(ida_struct.get_struc(_sid)),
        )
        return ("Created struct %s (id=0x%X)" % (name, sid), False)
    # Modern IDA: create via tinfo_t.
    if ida_typeinf is None:
        return ("No API available to create struct", True)
    til = ida_typeinf.get_idati()
    ti = ida_typeinf.tinfo_t()
    udt = ida_typeinf.udt_type_data_t()
    udt.is_union = False
    if not ti.create_udt(udt, ida_typeinf.BTF_STRUCT):
        return ("create_udt failed", True)
    code = ti.set_named_type(til, name,
                             ida_typeinf.NTF_TYPE | ida_typeinf.NTF_REPLACE)
    if code != 0:
        return ("set_named_type failed (code=%d)" % code, True)
    _record_undo(
        "create_struct %s" % name,
        lambda _n=name: ida_typeinf.del_named_type(til, _n,
                                                   ida_typeinf.NTF_TYPE),
    )
    return ("Created struct %s" % name, False)


@tool(
    "add_struct_member",
    "Append a member to an existing struct. type is a C type ('int', 'char[16]', "
    "'MY_STRUCT*'). offset defaults to the end of the struct.",
    {
        "type": "object",
        "properties": {
            "struct_name": {"type": "string"},
            "member_name": {"type": "string"},
            "type": {"type": "string"},
            "offset": {"type": "integer"},
        },
        "required": ["struct_name", "member_name", "type"],
    },
)
def add_struct_member(struct_name, member_name, type, offset=None):
    if _is_dry_run():
        return ("(dry-run) would add %s %s to struct %s at offset %s"
                % (type, member_name, struct_name, offset), False)
    if ida_struct is None or not hasattr(ida_struct, "get_struc_id"):
        return ("ida_struct API required for this build", True)
    sid = ida_struct.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        return ("No struct named %r" % struct_name, True)
    st = ida_struct.get_struc(sid)
    if st is None:
        return ("get_struc failed", True)
    if offset is None:
        offset = ida_struct.get_struc_size(sid)
    # Determine flags/size via tinfo_t when available.
    ti = None
    size = 0
    if ida_typeinf is not None:
        ti = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(ti, None, type + ";", 0):
            ti = None
        else:
            size = ti.get_size() or 0
    # add_struc_member signature varies; use a conservative call that always works.
    flag = ida_bytes.FF_BYTE | ida_bytes.FF_DATA
    if size == 2:
        flag = ida_bytes.FF_WORD | ida_bytes.FF_DATA
    elif size == 4:
        flag = ida_bytes.FF_DWORD | ida_bytes.FF_DATA
    elif size == 8:
        flag = ida_bytes.FF_QWORD | ida_bytes.FF_DATA
    res = ida_struct.add_struc_member(st, member_name, offset, flag, None,
                                      max(size, 1))
    if res != 0:
        return ("add_struc_member failed (code=%d)" % res, True)
    if ti is not None:
        mem = ida_struct.get_member(st, offset)
        if mem is not None:
            ida_struct.set_member_tinfo(st, mem, 0, ti, 0)
    _record_undo(
        "struct member %s.%s" % (struct_name, member_name),
        lambda _st=st, _off=offset: ida_struct.del_struc_member(_st, _off),
    )
    return ("Added %s %s to %s at offset %d"
            % (type, member_name, struct_name, offset), False)


@tool(
    "make_data",
    "Convert the bytes at an address into a data item of the given element size. "
    "Sizes: 1 (byte), 2 (word), 4 (dword), 8 (qword). count defaults to 1.",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "element_size": {"type": "integer"},
            "count": {"type": "integer", "default": 1},
        },
        "required": ["address", "element_size"],
    },
)
def make_data(address, element_size, count=1):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    count = max(1, int(count))
    flag_for = {
        1: ida_bytes.FF_BYTE,
        2: ida_bytes.FF_WORD,
        4: ida_bytes.FF_DWORD,
        8: ida_bytes.FF_QWORD,
    }
    if element_size not in flag_for:
        return ("element_size must be 1/2/4/8", True)
    if _is_dry_run():
        return ("(dry-run) would make_data at 0x%X size=%d count=%d"
                % (ea, element_size, count), False)
    total = element_size * count
    ok = ida_bytes.create_data(ea, flag_for[element_size] | ida_bytes.FF_DATA,
                               total, idaapi.BADADDR)
    if ok:
        _record_undo(
            "make_data 0x%X" % ea,
            lambda _ea=ea, _n=total: ida_bytes.del_items(
                _ea, ida_bytes.DELIT_SIMPLE, _n),
        )
    return (("create_data at 0x%X (%d x %d)" % (ea, count, element_size))
            if ok else ("create_data failed"), not ok)


@tool(
    "undefine",
    "Undefine items at an address (convert back to unexplored bytes). "
    "size defaults to 1; use this when Claude wants to reinterpret code/data.",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "size": {"type": "integer", "default": 1},
        },
        "required": ["address"],
    },
)
def undefine(address, size=1):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    size = max(1, int(size))
    if _is_dry_run():
        return ("(dry-run) would undefine 0x%X size=%d" % (ea, size), False)
    ok = ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
    if ok:
        _record_undo(
            "undefine 0x%X" % ea,
            lambda _ea=ea: idaapi.auto_make_code(_ea),
        )
    return (("Undefined %d byte(s) at 0x%X" % (size, ea))
            if ok else ("del_items failed"), not ok)


@tool(
    "set_operand_enum",
    "Format an instruction operand as a named enum constant instead of a raw "
    "immediate (e.g. show 'ERROR_ACCESS_DENIED' instead of 0x5).",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "operand": {"type": "integer", "default": 1},
            "enum_name": {"type": "string"},
        },
        "required": ["address", "enum_name"],
    },
)
def set_operand_enum(address, enum_name, operand=1):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    if ida_enum is None or not hasattr(ida_enum, "get_enum"):
        return ("ida_enum not available", True)
    eid = ida_enum.get_enum(enum_name)
    if eid == idaapi.BADADDR:
        return ("No enum named %r" % enum_name, True)
    if _is_dry_run():
        return ("(dry-run) would format op %d at 0x%X as enum %s"
                % (operand, ea, enum_name), False)
    ok = idc.op_enum(ea, operand, eid, 0)
    if ok:
        _record_undo(
            "op_enum 0x%X op=%d" % (ea, operand),
            lambda _ea=ea, _op=operand: idc.op_num(_ea, _op),
        )
    return (("Operand %d at 0x%X set to enum %s" % (operand, ea, enum_name))
            if ok else ("op_enum failed"), not ok)


@tool(
    "patch_bytes",
    "Overwrite bytes at an address. 'data' is a hex string (e.g. '90 90 EB FE'). "
    "Use carefully -- this edits the IDB segment.",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "data": {"type": "string"},
        },
        "required": ["address", "data"],
    },
)
def patch_bytes(address, data):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    try:
        cleaned = data.replace(" ", "").replace(",", "").replace("0x", "")
        if len(cleaned) % 2:
            return ("Odd number of hex digits in data", True)
        buf = bytes.fromhex(cleaned)
    except ValueError as e:
        return ("Could not parse hex: %s" % e, True)
    if not buf:
        return ("data is empty", True)
    if _is_dry_run():
        return ("(dry-run) would patch 0x%X with %d bytes" % (ea, len(buf)), False)
    old = ida_bytes.get_bytes(ea, len(buf)) or b""
    for i, b in enumerate(buf):
        ida_bytes.patch_byte(ea + i, b)
    _record_undo(
        "patch 0x%X (%d bytes)" % (ea, len(buf)),
        lambda _ea=ea, _o=old: [ida_bytes.patch_byte(_ea + i, bb)
                                for i, bb in enumerate(_o)] and None,
    )
    return ("Patched %d bytes at 0x%X" % (len(buf), ea), False)


@tool(
    "apply_sig",
    "Apply a FLIRT signature file to the database by name (without path). "
    "Use list_sig / IDA's Signatures window to discover names.",
    {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    },
)
def apply_sig(name):
    if _is_dry_run():
        return ("(dry-run) would apply FLIRT signature %r" % name, False)
    try:
        import ida_loader
    except Exception as e:
        return ("FLIRT API not available: %s" % e, True)
    # plan_to_apply_idasgn enqueues, apply_idasgn_by returns count. Prefer
    # plan variant for robustness across IDA versions.
    fn = getattr(ida_loader, "plan_to_apply_idasgn", None) \
         or getattr(ida_loader, "apply_idasgn_by", None)
    if fn is None:
        return ("No apply-signature function found in ida_loader", True)
    rc = fn(name)
    return ("apply signature %r -> rc=%s" % (name, rc), False)


@tool(
    "load_til",
    "Load a type library (.til) by base name (e.g. 'mssdk64', 'gnulnx_x64') "
    "so subsequent types/prototypes resolve.",
    {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    },
)
def load_til(name):
    if ida_typeinf is None:
        return ("ida_typeinf not available", True)
    if _is_dry_run():
        return ("(dry-run) would load TIL %r" % name, False)
    ok = ida_typeinf.add_til(name, ida_typeinf.ADDTIL_DEFAULT)
    return (("Loaded TIL %r" % name) if ok else ("add_til failed for %r" % name),
            not ok)


@tool(
    "jump_to",
    "Move the IDA main view to a given name or address.",
    {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
    },
)
def jump_to(target):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    ida_kernwin.jumpto(ea)
    return ("Jumped to 0x%X" % ea, False)


# ---------- added read tools ----------

@tool(
    "int_convert",
    "Convert a value between representations: decimal, hex, binary, bytes, "
    "ASCII. Accepts a number literal (dec or 0x-prefixed hex) or a quoted "
    "string of characters. Pure utility -- does not read the database.",
    {
        "type": "object",
        "properties": {
            "value": {"type": "string"},
            "byte_order": {"type": "string", "default": "little"},
            "width": {"type": "integer", "default": 0,
                      "description": "Byte width for rendering. 0 picks the "
                                     "smallest fit."},
        },
        "required": ["value"],
    },
)
def int_convert(value, byte_order="little", width=0):
    s = str(value).strip()
    if not s:
        return ("empty input", True)
    # Try numeric parse first.
    try:
        v = int(s, 16) if s.lower().startswith("0x") else int(s, 0)
    except ValueError:
        # Fall back to treating as an ASCII string.
        raw = s.encode("utf-8", errors="replace")
        hexed = " ".join("%02X" % b for b in raw)
        lines = [
            "ascii: %r" % s,
            "hex:   %s" % hexed,
            "len:   %d" % len(raw),
        ]
        if len(raw) <= 8:
            lines.append("int(le): %d" % int.from_bytes(raw, "little",
                                                        signed=False))
            lines.append("int(be): %d" % int.from_bytes(raw, "big",
                                                        signed=False))
        return ("\n".join(lines), False)
    signed_v = v
    unsigned_v = v if v >= 0 else v & ((1 << 64) - 1)
    if width <= 0:
        if v < 0:
            width = 8
        elif v <= 0xFF:
            width = 1
        elif v <= 0xFFFF:
            width = 2
        elif v <= 0xFFFFFFFF:
            width = 4
        else:
            width = 8
    mask = (1 << (width * 8)) - 1
    masked = v & mask
    bo = "big" if str(byte_order).lower().startswith("b") else "little"
    b = masked.to_bytes(width, bo, signed=False)
    ascii_view = "".join(chr(x) if 32 <= x < 127 else "." for x in b)
    lines = [
        "dec:    %d" % signed_v,
        "hex:    0x%X" % unsigned_v,
        "bin:    0b%s" % bin(unsigned_v)[2:],
        "width:  %d bytes" % width,
        "bytes(%s): %s" % (bo, " ".join("%02X" % x for x in b)),
        "ascii:  %s" % ascii_view,
    ]
    return ("\n".join(lines), False)


@tool(
    "list_globals",
    "List global (non-function) named data items: address, name, size, and "
    "type. Useful to discover globals/tables separate from functions.",
    {
        "type": "object",
        "properties": {
            "filter": {"type": "string"},
            "limit": {"type": "integer", "default": 200},
        },
    },
)
def list_globals(filter="", limit=200):
    needle = (filter or "").lower()
    rows = []
    for ea, name in idautils.Names():
        if idaapi.get_func(ea) is not None:
            continue
        if needle and needle not in name.lower():
            continue
        sz = ida_bytes.get_item_size(ea) or 0
        t = idc.get_type(ea) or ""
        rows.append("0x%08X  %-40s  size=%-5d  %s" % (ea, name, sz, t))
        if len(rows) >= limit:
            rows.append("... (truncated at %d)" % limit)
            break
    return ("\n".join(rows) or "(no matching globals)", False)


@tool(
    "xrefs_to_field",
    "List cross-references to a struct field (by struct_name + member_name). "
    "Useful to find every site that reads or writes a specific field.",
    {
        "type": "object",
        "properties": {
            "struct_name": {"type": "string"},
            "member_name": {"type": "string"},
            "limit": {"type": "integer", "default": 200},
        },
        "required": ["struct_name", "member_name"],
    },
)
def xrefs_to_field(struct_name, member_name, limit=200):
    mid = idaapi.BADADDR
    if ida_struct is not None and hasattr(ida_struct, "get_struc_id"):
        sid = ida_struct.get_struc_id(struct_name)
        if sid != idaapi.BADADDR:
            st = ida_struct.get_struc(sid)
            if st is not None:
                mem = ida_struct.get_member_by_name(st, member_name)
                if mem is not None:
                    mid = mem.id
    if mid == idaapi.BADADDR and ida_typeinf is not None:
        ti = ida_typeinf.tinfo_t()
        if ti.get_named_type(ida_typeinf.get_idati(), struct_name) and ti.is_struct():
            tid = ti.get_tid() if hasattr(ti, "get_tid") else idaapi.BADADDR
            if tid != idaapi.BADADDR and hasattr(ida_typeinf, "get_udm_by_fullname"):
                full = "%s.%s" % (struct_name, member_name)
                try:
                    udm = ida_typeinf.udm_t()
                    idx = ida_typeinf.get_udm_by_fullname(udm, full)
                    if idx >= 0 and hasattr(ti, "get_udm_tid"):
                        mid = ti.get_udm_tid(idx)
                except Exception:
                    pass
    if mid == idaapi.BADADDR:
        return ("Could not resolve field %s.%s" % (struct_name, member_name), True)
    rows = []
    for x in idautils.XrefsTo(mid):
        caller = idaapi.get_func(x.frm)
        cname = idc.get_func_name(caller.start_ea) if caller else ""
        rows.append("0x%08X  in %s  (type=%d)" % (x.frm, cname or "?", x.type))
        if len(rows) >= limit:
            rows.append("... (truncated at %d)" % limit)
            break
    return ("\n".join(rows) or "(no xrefs to %s.%s)" % (struct_name, member_name),
            False)


@tool(
    "get_int",
    "Read a typed integer at an address. ty examples: 'i8', 'u8', 'i16', "
    "'u16', 'i32', 'u32', 'i64', 'u64' -- optionally suffixed 'le' or 'be' "
    "(default: little-endian).",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "ty": {"type": "string", "default": "u32"},
        },
        "required": ["address"],
    },
)
def get_int(address, ty="u32"):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    import struct as _st
    t = ty.strip().lower()
    endian = "<"
    if t.endswith("be"):
        endian = ">"
        t = t[:-2]
    elif t.endswith("le"):
        endian = "<"
        t = t[:-2]
    if not t or t[0] not in ("i", "u"):
        return ("Unknown integer type %r" % ty, True)
    signed = t[0] == "i"
    size_map = {"8": 1, "16": 2, "32": 4, "64": 8}
    fmt_map = {
        (1, False): "B", (1, True): "b",
        (2, False): "H", (2, True): "h",
        (4, False): "I", (4, True): "i",
        (8, False): "Q", (8, True): "q",
    }
    if t[1:] not in size_map:
        return ("Unknown integer size in %r" % ty, True)
    size = size_map[t[1:]]
    data = ida_bytes.get_bytes(ea, size) or b""
    if len(data) < size:
        return ("Short read at 0x%X (got %d, want %d)" % (ea, len(data), size), True)
    v = _st.unpack(endian + fmt_map[(size, signed)], data)[0]
    uv = v & ((1 << (size * 8)) - 1)
    return ("0x%X: %s = %d (0x%X)" % (ea, ty, v, uv), False)


@tool(
    "get_string",
    "Read a null-terminated string at an address. strtype: 'c' (ASCII/UTF-8, "
    "default) or 'u' (UTF-16LE).",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "strtype": {"type": "string", "default": "c"},
            "max_length": {"type": "integer", "default": 1024},
        },
        "required": ["address"],
    },
)
def get_string(address, strtype="c", max_length=1024):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    max_length = max(1, min(int(max_length), 65536))
    if str(strtype).lower().startswith("u"):
        out = bytearray()
        for i in range(0, max_length, 2):
            ch = ida_bytes.get_bytes(ea + i, 2) or b""
            if len(ch) < 2 or ch == b"\x00\x00":
                break
            out += ch
        s = bytes(out).decode("utf-16-le", errors="replace")
    else:
        buf = ida_bytes.get_bytes(ea, max_length) or b""
        nul = buf.find(b"\x00")
        if nul >= 0:
            buf = buf[:nul]
        try:
            s = buf.decode("utf-8")
        except UnicodeDecodeError:
            s = buf.decode("latin-1", errors="replace")
    return ("0x%X: %r" % (ea, s), False)


@tool(
    "get_global_value",
    "Read the compile-time value of a global, resolved by name or address. "
    "Uses the size/type IDA has recorded; prints as integer for 1/2/4/8-byte "
    "items, otherwise as hex bytes.",
    {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
    },
)
def get_global_value(target):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    size = ida_bytes.get_item_size(ea) or 0
    if size <= 0:
        size = 4
    size = min(size, 4096)
    data = ida_bytes.get_bytes(ea, size) or b""
    name = idc.get_name(ea) or ""
    t = idc.get_type(ea) or ""
    if size in (1, 2, 4, 8) and len(data) == size:
        v = int.from_bytes(data, "little", signed=False)
        return ("%s @ 0x%X [%s]: %d (0x%X)" %
                (name or "?", ea, t or "?", v, v), False)
    hexed = " ".join("%02X" % b for b in data)
    ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ("%s @ 0x%X [%s]: %s\n  %s" %
            (name or "?", ea, t or "?", hexed, ascii_view), False)


@tool(
    "read_struct",
    "Overlay a named struct at an address and return each field's value "
    "(offset, name, type, raw bytes, and decoded int for 1/2/4/8-byte fields).",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "struct_name": {"type": "string"},
        },
        "required": ["address", "struct_name"],
    },
)
def read_struct(address, struct_name):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    rows = []

    def _emit(off, mname, mtype, msize):
        raw = ida_bytes.get_bytes(ea + off, msize) or b""
        hexed = " ".join("%02X" % b for b in raw)
        extra = ""
        if msize in (1, 2, 4, 8) and len(raw) == msize:
            v = int.from_bytes(raw, "little", signed=False)
            extra = " (=0x%X / %d)" % (v, v)
        rows.append("  +0x%X  %-24s : %-20s = %s%s" %
                    (off, mname or "", mtype or "", hexed, extra))

    if ida_struct is not None and hasattr(ida_struct, "get_struc_id"):
        sid = ida_struct.get_struc_id(struct_name)
        if sid != idaapi.BADADDR:
            st = ida_struct.get_struc(sid)
            rows.append("struct %s @ 0x%X  size=%d" %
                        (struct_name, ea, ida_struct.get_struc_size(sid)))
            off = ida_struct.get_struc_first_offset(st)
            while off != idaapi.BADADDR:
                mem = ida_struct.get_member(st, off)
                if mem is not None:
                    mname = ida_struct.get_member_name(mem.id) or ""
                    msize = ida_struct.get_member_size(mem) or 0
                    mtype = idc.get_member_type(sid, off) or ""
                    _emit(off, mname, mtype, msize)
                off = ida_struct.get_struc_next_offset(st, off)
            return ("\n".join(rows), False)
    if ida_typeinf is not None:
        ti = ida_typeinf.tinfo_t()
        if (ti.get_named_type(ida_typeinf.get_idati(), struct_name)
                and ti.is_struct()):
            udt = ida_typeinf.udt_type_data_t()
            if ti.get_udt_details(udt):
                rows.append("struct %s @ 0x%X  size=%d" %
                            (struct_name, ea, ti.get_size() or 0))
                for m in udt:
                    moff = m.offset // 8
                    msize = (m.size or 0) // 8
                    mt = str(m.type) if m.type else ""
                    _emit(moff, m.name or "", mt, msize)
                return ("\n".join(rows), False)
    return ("No struct named %r" % struct_name, True)


# ---------- added write tools ----------

@tool(
    "patch_asm",
    "Assemble one or more instructions (e.g. 'nop', 'mov eax, 1', "
    "'jmp 0x401000') and patch the resulting bytes at an address. Redefines "
    "code at the site so the disassembly reflects the new instruction.",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "asm": {"type": "string"},
        },
        "required": ["address", "asm"],
    },
)
def patch_asm(address, asm):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    if not hasattr(idautils, "Assemble"):
        return ("idautils.Assemble not available in this IDA build", True)
    if _is_dry_run():
        return ("(dry-run) would assemble %r at 0x%X" % (asm, ea), False)
    try:
        ok, buf = idautils.Assemble(ea, asm)
    except Exception as e:
        return ("Assemble raised: %s" % e, True)
    if not ok or not buf:
        return ("Assembler rejected %r at 0x%X" % (asm, ea), True)
    old = ida_bytes.get_bytes(ea, len(buf)) or b""
    for i, b in enumerate(buf):
        ida_bytes.patch_byte(ea + i, b if isinstance(b, int) else ord(b))
    # Re-analyze the patched site so disasm reflects the new instruction.
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(buf))
    idc.create_insn(ea)
    _record_undo(
        "asm patch 0x%X" % ea,
        lambda _ea=ea, _o=old: ([ida_bytes.patch_byte(_ea + i, bb)
                                 for i, bb in enumerate(_o)] and
                                ida_bytes.del_items(_ea,
                                                    ida_bytes.DELIT_SIMPLE,
                                                    len(_o)) and
                                idc.create_insn(_ea)) and None,
    )
    return ("Assembled %r at 0x%X (%d bytes)" % (asm, ea, len(buf)), False)


@tool(
    "declare_type",
    "Parse and add C type declaration(s) to the local type library "
    "(e.g. 'struct foo { int a; char b[8]; };' or 'typedef unsigned int u32;'). "
    "Multiple declarations allowed in one call.",
    {
        "type": "object",
        "properties": {"decl": {"type": "string"}},
        "required": ["decl"],
    },
)
def declare_type(decl):
    if ida_typeinf is None:
        return ("ida_typeinf not available", True)
    if _is_dry_run():
        return ("(dry-run) would declare type(s): %r" % decl, False)
    til = ida_typeinf.get_idati()
    flags = getattr(ida_typeinf, "PT_SIL", 0)
    try:
        errs = ida_typeinf.parse_decls(til, decl, None, flags)
    except Exception as e:
        return ("parse_decls raised: %s" % e, True)
    if errs:
        return ("parse_decls reported %d error(s) -- check declaration syntax"
                % errs, True)
    return ("Declared type(s) from %r" % decl, False)


@tool(
    "define_func",
    "Define a function starting at the given address. Optionally provide "
    "'end' for explicit bounds; omit to let IDA auto-detect.",
    {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "end": {"type": "string"},
        },
        "required": ["address"],
    },
)
def define_func(address, end=None):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    end_ea = idaapi.BADADDR
    if end is not None:
        end_ea = _resolve(end)
        if end_ea == idaapi.BADADDR:
            return ("Could not resolve end: %r" % end, True)
    if _is_dry_run():
        end_str = "auto" if end is None else ("0x%X" % end_ea)
        return ("(dry-run) would define function 0x%X..%s" % (ea, end_str), False)
    ok = idc.add_func(ea, end_ea)
    if ok:
        _record_undo(
            "define_func 0x%X" % ea,
            lambda _ea=ea: idc.del_func(_ea),
        )
    return (("Defined function at 0x%X" % ea) if ok
            else ("add_func failed at 0x%X" % ea), not ok)


@tool(
    "define_code",
    "Convert bytes at an address into a code instruction (run auto-analysis "
    "to create an insn). Counterpart to 'undefine'.",
    {
        "type": "object",
        "properties": {"address": {"type": "string"}},
        "required": ["address"],
    },
)
def define_code(address):
    ea = _resolve(address)
    if ea == idaapi.BADADDR:
        return ("Could not resolve address: %r" % address, True)
    if _is_dry_run():
        return ("(dry-run) would make code at 0x%X" % ea, False)
    n = idc.create_insn(ea)
    if n <= 0:
        return ("create_insn failed at 0x%X" % ea, True)
    _record_undo(
        "define_code 0x%X" % ea,
        lambda _ea=ea, _n=n: ida_bytes.del_items(_ea,
                                                 ida_bytes.DELIT_SIMPLE, _n),
    )
    return ("Created instruction at 0x%X (size=%d)" % (ea, n), False)


@tool(
    "declare_stack",
    "Create (or replace) a stack variable in a function's frame at the given "
    "offset with a given name and type. Overwrites any existing member at "
    "that offset.",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "offset": {"type": "integer"},
            "name": {"type": "string"},
            "type": {"type": "string"},
        },
        "required": ["target", "offset", "name", "type"],
    },
)
def declare_stack(target, offset, name, type):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    if ida_struct is None or ida_typeinf is None:
        return ("ida_struct/ida_typeinf required for this operation", True)
    if _is_dry_run():
        return ("(dry-run) would declare stack %s %s at +0x%X in %s"
                % (type, name, offset,
                   idc.get_func_name(func.start_ea) or "?"), False)
    frame_id = idc.get_frame_id(func.start_ea)
    if frame_id == idaapi.BADADDR or frame_id is None:
        return ("No frame for function", True)
    st = ida_struct.get_struc(frame_id)
    if st is None:
        return ("get_struc(frame) failed", True)
    ti = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(ti, None, type + ";", 0):
        return ("Could not parse type %r" % type, True)
    size = max(ti.get_size() or 1, 1)
    # Replace any existing member at that offset.
    existing = ida_struct.get_member(st, offset)
    if existing is not None:
        ida_struct.del_struc_member(st, offset)
    flag = ida_bytes.FF_BYTE | ida_bytes.FF_DATA
    if size == 2:
        flag = ida_bytes.FF_WORD | ida_bytes.FF_DATA
    elif size == 4:
        flag = ida_bytes.FF_DWORD | ida_bytes.FF_DATA
    elif size == 8:
        flag = ida_bytes.FF_QWORD | ida_bytes.FF_DATA
    res = ida_struct.add_struc_member(st, name, offset, flag, None, size)
    if res != 0:
        return ("add_struc_member failed (code=%d)" % res, True)
    new_mem = ida_struct.get_member(st, offset)
    if new_mem is not None:
        ida_struct.set_member_tinfo(st, new_mem, 0, ti, 0)
    _record_undo(
        "declare_stack %s.%s" %
        (idc.get_func_name(func.start_ea) or "?", name),
        lambda _st=st, _off=offset: ida_struct.del_struc_member(_st, _off),
    )
    return ("Declared stack %s %s at +0x%X in %s"
            % (type, name, offset,
               idc.get_func_name(func.start_ea) or "?"), False)


@tool(
    "delete_stack",
    "Delete a named stack variable from a function's frame.",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "name": {"type": "string"},
        },
        "required": ["target", "name"],
    },
)
def delete_stack(target, name):
    ea = _resolve(target)
    if ea == idaapi.BADADDR:
        return ("Could not resolve target: %r" % target, True)
    func = idaapi.get_func(ea)
    if not func:
        return ("Not inside a function: 0x%X" % ea, True)
    if ida_struct is None:
        return ("ida_struct not available", True)
    frame_id = idc.get_frame_id(func.start_ea)
    if frame_id == idaapi.BADADDR or frame_id is None:
        return ("No frame for function", True)
    st = ida_struct.get_struc(frame_id)
    if st is None:
        return ("get_struc(frame) failed", True)
    mem = ida_struct.get_member_by_name(st, name)
    if mem is None:
        return ("No stack var named %r" % name, True)
    moff = mem.soff
    msize = ida_struct.get_member_size(mem) or 1
    mflag = mem.flag
    mtinfo = None
    if ida_typeinf is not None:
        mtinfo = ida_typeinf.tinfo_t()
        try:
            if not ida_struct.get_member_tinfo(mtinfo, mem):
                mtinfo = None
        except Exception:
            mtinfo = None
    if _is_dry_run():
        return ("(dry-run) would delete stack var %r at +0x%X" % (name, moff),
                False)
    ok = ida_struct.del_struc_member(st, moff)
    if ok:
        def _revert(_st=st, _name=name, _off=moff, _size=msize,
                    _flag=mflag, _ti=mtinfo):
            ida_struct.add_struc_member(_st, _name, _off, _flag, None, _size)
            if _ti is not None:
                new = ida_struct.get_member(_st, _off)
                if new is not None:
                    ida_struct.set_member_tinfo(_st, new, 0, _ti, 0)
        _record_undo(
            "delete_stack %s.%s" %
            (idc.get_func_name(func.start_ea) or "?", name),
            _revert,
        )
    return (("Deleted stack var %r at +0x%X" % (name, moff)) if ok
            else ("del_struc_member failed"), not ok)


# Set of tool names that modify the database; the UI gates these on
# 'Allow edits'.
WRITE_TOOLS = frozenset({
    "rename",
    "add_comment",
    "set_function_comment",
    "set_function_prototype",
    "set_func_return_type",
    "rename_lvar",
    "set_lvar_type",
    "create_struct",
    "add_struct_member",
    "make_data",
    "undefine",
    "set_operand_enum",
    "patch_bytes",
    "apply_sig",
    "load_til",
    "patch_asm",
    "declare_type",
    "define_func",
    "define_code",
    "declare_stack",
    "delete_stack",
})
