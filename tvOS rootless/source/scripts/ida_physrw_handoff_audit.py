import json
import os
import sys

import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import idaapi
import idautils
import idc


def _name_ea(name):
    ea = ida_name.get_name_ea(idaapi.BADADDR, name)
    if ea != idaapi.BADADDR:
        return ea
    ea = idc.get_name_ea_simple(name)
    if ea != idaapi.BADADDR:
        return ea
    return idaapi.BADADDR


def _func_record_for_ea(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    return {
        "start": hex(f.start_ea),
        "end": hex(f.end_ea),
        "name": ida_funcs.get_func_name(f.start_ea),
        "offset_in_func": hex(ea - f.start_ea),
    }


def _symbol_record(name):
    ea = _name_ea(name)
    if ea == idaapi.BADADDR:
        return {"query": name, "found": False}
    rec = {
        "query": name,
        "found": True,
        "ea": hex(ea),
        "image_offset": hex(ea - idaapi.get_imagebase()),
        "ida_name": ida_name.get_name(ea),
    }
    f = _func_record_for_ea(ea)
    if f:
        rec["function"] = f
    xrefs = []
    for xr in idautils.XrefsTo(ea, 0):
        xref_func = _func_record_for_ea(xr.frm)
        xrefs.append(
            {
                "from": hex(xr.frm),
                "from_name": ida_name.get_name(xr.frm),
                "from_disasm": idc.generate_disasm_line(xr.frm, 0) or "",
                "from_function": xref_func,
                "type": int(xr.type),
            }
        )
    rec["xrefs_to"] = xrefs[:32]
    return rec


def _offset_record(offset):
    ea = idaapi.get_imagebase() + offset
    rec = {
        "image_offset": hex(offset),
        "ea": hex(ea),
        "name": ida_name.get_name(ea),
        "bytes": ida_bytes.get_bytes(ea, 16).hex() if ida_bytes.get_bytes(ea, 16) else "",
    }
    f = _func_record_for_ea(ea)
    if f:
        rec["function"] = f
    return rec


def main():
    ida_auto.auto_wait()

    names = [
        "_krkw_kread",
        "krkw_kread",
        "_dt_build_physrw_handoff_only",
        "dt_build_physrw_handoff_only",
        "_DTPhysPteInitFromCurrentProc",
        "DTPhysPteInitFromCurrentProc",
        "_DTPhysCheckedKread64",
        "_DTPhysCheckedKreadPtr",
        "_libjailbreak_physrw_pte_init",
        "_physrw_pte_handoff",
        "_pmap_expand_range",
        "_flush_tlb",
    ]

    offsets = []
    for item in os.environ.get("IDA_AUDIT_OFFSETS", "").split(","):
        item = item.strip()
        if not item:
            continue
        offsets.append(int(item, 0))

    payload = {
        "input": idc.get_input_file_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "symbols": [_symbol_record(n) for n in names],
        "offsets": [_offset_record(o) for o in offsets],
    }

    out = os.environ.get("IDA_AUDIT_OUT")
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out:
        with open(out, "w") as fp:
            fp.write(text)
            fp.write("\n")
    else:
        print(text)

    idc.qexit(0)


if __name__ == "__main__":
    main()
