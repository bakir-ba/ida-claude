"""Extract context from the active IDA database for Claude."""
import idaapi
import idautils
import idc

try:
    import ida_ida
except Exception:
    ida_ida = None

try:
    import ida_kernwin
except Exception:
    ida_kernwin = None

try:
    import ida_hexrays
    _HEXRAYS_OK = True
except Exception:
    _HEXRAYS_OK = False


def _arch_blurb():
    # IDA 9.0 removed idaapi.get_inf_structure() in favor of the free
    # functions in ida_ida. Try the new API first, fall back to the old
    # one for IDA 7.x / 8.x.
    proc, bits = "", 0
    if ida_ida is not None and hasattr(ida_ida, "inf_get_procname"):
        try:
            proc = ida_ida.inf_get_procname() or ""
            if ida_ida.inf_is_64bit():
                bits = 64
            elif getattr(ida_ida, "inf_is_32bit_exactly", ida_ida.inf_is_32bit)():
                bits = 32
        except Exception:
            proc, bits = "", 0
    if not proc and hasattr(idaapi, "get_inf_structure"):
        try:
            infs = idaapi.get_inf_structure()
            proc = getattr(infs, "procname", "") or ""
            if infs.is_64bit():
                bits = 64
            elif infs.is_32bit():
                bits = 32
        except Exception:
            pass
    try:
        ftype = idaapi.get_file_type_name() or ""
    except Exception:
        ftype = ""
    return "Processor: %s | Bits: %s | File: %s" % (proc or "?", bits or "?", ftype or "?")


def current_ea():
    return idc.get_screen_ea()


def _func_disasm(func, max_lines=400):
    lines = []
    for insn_ea in idautils.FuncItems(func.start_ea):
        line = idc.generate_disasm_line(insn_ea, 0) or ""
        lines.append("  %08X  %s" % (insn_ea, line))
        if len(lines) >= max_lines:
            lines.append("  ... (truncated at %d lines)" % max_lines)
            break
    return "\n".join(lines)


def _try_decompile(start_ea):
    if not _HEXRAYS_OK:
        return None
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        cfunc = ida_hexrays.decompile(start_ea)
        if cfunc is None:
            return None
        return str(cfunc)
    except Exception as e:
        return "(decompilation failed: %s)" % e


def get_current_function_context(include_decomp=True, max_disasm_lines=400):
    """Build a text block describing the function the cursor is in."""
    ea = current_ea()
    if ea == idaapi.BADADDR:
        return ""

    func = idaapi.get_func(ea)
    if not func:
        return "Cursor at 0x%X (not inside any function). %s" % (ea, _arch_blurb())

    name = idc.get_func_name(func.start_ea) or ("sub_%X" % func.start_ea)

    parts = [
        _arch_blurb(),
        "",
        "Function: %s  (start=0x%X, end=0x%X, size=%d)" % (name, func.start_ea, func.end_ea, func.end_ea - func.start_ea),
        "Cursor at: 0x%X" % ea,
        "",
        "Disassembly:",
        _func_disasm(func, max_disasm_lines),
    ]

    if include_decomp:
        pc = _try_decompile(func.start_ea)
        if pc:
            parts.extend(["", "Decompilation (Hex-Rays):", pc])

    return "\n".join(parts)


def _pseudocode_with_selection_marked(func, sea, eea):
    """Render the function's Hex-Rays pseudocode and prefix every line whose
    associated EA falls in [sea, eea) with '>>' so Claude can see which C lines
    the user highlighted. Returns None if decompilation is unavailable."""
    if not _HEXRAYS_OK or func is None:
        return None
    try:
        import ida_lines
    except Exception:
        ida_lines = None
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:
        return "(decompilation failed: %s)" % e
    if cfunc is None:
        return None
    try:
        pc = cfunc.get_pseudocode()
    except Exception:
        return None
    out = []
    for i in range(pc.size()):
        sl = pc[i]
        raw = sl.line
        if ida_lines is not None:
            try:
                raw = ida_lines.tag_remove(raw)
            except Exception:
                pass
        line_ea = idaapi.BADADDR
        try:
            loc = ida_hexrays.ctree_item_t()
            if cfunc.get_line_item(sl.line, 0, True, None, loc, None):
                if getattr(loc, "it", None) is not None:
                    line_ea = loc.it.ea
        except Exception:
            pass
        hit = (line_ea != idaapi.BADADDR and sea <= line_ea < eea)
        out.append("%s %3d  %s" % (">>" if hit else "  ", i + 1, raw))
    return "\n".join(out) if out else None


def get_selection_context(include_decomp=True, max_disasm_lines=400):
    """Return a focused context block describing the user's current UI
    selection (disasm or pseudocode). Returns None if there is no highlight,
    so callers can fall back to the full-function context.
    """
    if ida_kernwin is None:
        return None
    w = ida_kernwin.get_current_widget()
    if w is None:
        return None
    try:
        res = ida_kernwin.read_range_selection(w)
    except Exception:
        return None
    if not res:
        return None
    try:
        ok, sea, eea = res[0], res[1], res[2]
    except Exception:
        return None
    if (not ok or sea == idaapi.BADADDR or eea == idaapi.BADADDR
            or sea >= eea):
        return None

    wtype = ida_kernwin.get_widget_type(w)
    PSEUDO = getattr(ida_kernwin, "BWN_PSEUDOCODE", -1)
    view_name = "Pseudocode" if wtype == PSEUDO else "Disassembly"

    func = idaapi.get_func(sea)
    parts = [
        _arch_blurb(),
        "",
        "NOTE: the user has a highlighted region. Focus your answer on this "
        "selection; the surrounding function is included only for context.",
        "Selection in %s view: 0x%X - 0x%X  (%d bytes)"
        % (view_name, sea, eea, eea - sea),
    ]
    if func:
        fname = idc.get_func_name(func.start_ea) or ("sub_%X" % func.start_ea)
        parts.append("Containing function: %s  (0x%X - 0x%X)"
                     % (fname, func.start_ea, func.end_ea))
    parts.append("")

    # Always include the disasm slice for the selection.
    parts.append("Selected disassembly:")
    lines = []
    for insn_ea in idautils.Heads(sea, eea):
        dis = idc.generate_disasm_line(insn_ea, 0) or ""
        lines.append("  %08X  %s" % (insn_ea, dis))
        if len(lines) >= max_disasm_lines:
            lines.append("  ... (truncated at %d lines)" % max_disasm_lines)
            break
    parts.append("\n".join(lines) or "(empty range)")

    if include_decomp and func:
        if wtype == PSEUDO:
            marked = _pseudocode_with_selection_marked(func, sea, eea)
            if marked:
                parts += [
                    "",
                    "Full decompilation (lines in selection marked '>>'):",
                    marked,
                ]
            else:
                pc = _try_decompile(func.start_ea)
                if pc:
                    parts += ["", "Full decompilation (for context):", pc]
        else:
            pc = _try_decompile(func.start_ea)
            if pc:
                parts += ["", "Full decompilation (for context):", pc]

    return "\n".join(parts)


def get_function_context_by_name(name, include_decomp=True, max_disasm_lines=400):
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        return None
    func = idaapi.get_func(ea)
    if not func:
        return None
    parts = [
        "Function: %s  (start=0x%X, end=0x%X)" % (name, func.start_ea, func.end_ea),
        "",
        "Disassembly:",
        _func_disasm(func, max_disasm_lines),
    ]
    if include_decomp:
        pc = _try_decompile(func.start_ea)
        if pc:
            parts.extend(["", "Decompilation (Hex-Rays):", pc])
    return "\n".join(parts)
