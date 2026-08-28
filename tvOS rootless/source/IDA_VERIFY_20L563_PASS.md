# IDA verification — kernelcache.j105a.20L563.macho (AppleTV6,2 / tvOS 16.5)

**Image base:** `0xfffffff007004000`  
**Verified:** IDA Pro MCP `py_eval` on disk database  
**Build 23 symbol table** — all PASS

## Tier 1 — boot constants / ksymbol path

| Symbol | Unslid VA | Offset | Xrefs | Sample xref funcs | PASS |
|--------|-----------|--------|-------|-------------------|------|
| staticBase | `0xfffffff007004000` | `0x0` | 2628 | start, sub_… | **PASS** |
| MH_MAGIC_64 @ staticBase | — | — | — | magic `0xfeedfacf` | **PASS** |
| gVirtBase | `0xfffffff007150e18` | `0x14ce18` | 34 | `_ml_static_ptovirt_0`, pmap/vm | **PASS** |
| gPhysBase | `0xfffffff007152c00` | `0x14ec00` | 49 | physmap / pmap paths | **PASS** |
| gPhysSize | `0xfffffff007152c08` | `0x14ec08` | 11 | paired with gPhysBase | **PASS** |
| cpu_ttep | `0xfffffff007128010` | `0x124010` | 9 | pmap_switch / CPU TTBR | **PASS** |
| ptov_table | `0xfffffff0071069a8` | `0x1029a8` | 9 | `_ml_static_ptovirt_0`, phystokv | **PASS** |

## Tier 2 — phys-rw handoff

| Symbol | Unslid VA | Offset | Xrefs | Sample xref funcs | PASS |
|--------|-----------|--------|-------|-------------------|------|
| allproc | `0xfffffff0078d8a70` | `0x8d4a70` | 30 | `sub_FFFFFFF0075A5528` (list init) | **PASS** |
| vm_first_phys | `0xfffffff007128148` | `0x124148` | 253 | pmap_enter / vm_phys | **PASS** |
| pv_head_table | `0xfffffff007105908` | `0x101908` | 176 | pmap_remove / PV | **PASS** |
| pmap_enter_options_addr | `0xfffffff0072fc814` | `0x2f8814` | 20 | pmap_enter_options | **PASS** |
| pmap_remove_options | `0xfffffff00730268c` | `0x2fe68c` | 12 | pmap_remove_options_internal | **PASS** |

## Tier 1 + Tier 2 summary

- **TIER1_ALL:** true  
- **TIER2_ALL:** true  

Matches `dt_baked_offsets.m` and `kfund_offsets_decoded.json` `symbols_absolute` entries.

## Tier 3 — trust cache (Build 26)

**Verified:** IDA Pro MCP on `kernelcache.j105a.20L563.macho` (tvOS 16.5 / XNU 22.x, iOS 16+ trust-cache path)

### Symbols

| Symbol | Unslid VA | Offset | Xrefs | Evidence | PASS |
|--------|-----------|--------|-------|----------|------|
| `ppl_trust_cache_rt` | `0xfffffff007143c10` | `0x13fc10` | 11 | `xmmword_FFFFFFF007143C10`; init in `sub_FFFFFFF0076119BC` from `trust_cache_init` @ `sub_FFFFFFF0072295A8` | **PASS** |
| `tc_list_head_indirect` (`qword_143C30`) | `0xfffffff007143c30` | `0x13fc30` | 2 | `ppl_trust_cache_rt + 0x20`; init stores ptr to `qword_8D4450` | **PASS** |
| `tc_list_head` (`qword_8D4450`) | `0xfffffff0078d4450` | `0x8d0450` | 3 | Cleared at init; `lck` at `+8` (`unk_8D4458`) | **PASS** |
| `trust_cache_lck` | `0xfffffff0078d4458` | `0x8d0458` | 4 | `query_trust_cache` / `load_trust_cache` lock | **PASS** |
| `pmap_image4_trust_caches` | — | — | 0 | Not present (iOS ≤15 path unused) | **PASS** (absent) |

### List head resolution (matches libjailbreak `trustcache.c`)

```c
// iOS 16+: kread64(kread64(ksymbol(ppl_trust_cache_rt) + 0x20))
```

IDA init (`sub_FFFFFFF0076119BC`):

1. `STR XZR, [rt + 0x20]`
2. `STR XZR, [qword_8D4450]`
3. `STR X10, [rt + 0x20]` where `X10 = &qword_8D4450`

So: `ppl_trust_cache_rt + 0x20` → pointer to `0xfffffff0078d4450` → first `trustcache` kaddr.

| Check | Value | PASS |
|-------|-------|------|
| List-head offset in `ppl_trust_cache_rt` | `0x20` | **PASS** |
| Indirect list-head global | `0xfffffff0078d4450` | **PASS** |

### Related kernel functions (reference)

| Function | VA | Notes |
|----------|-----|-------|
| `trust_cache_init` caller | `sub_FFFFFFF0072295A8` | Boot: calls `sub_FFFFFFF0076119BC` |
| Runtime init | `sub_FFFFFFF0076119BC` | Zeros `ppl_trust_cache_rt`, wires list head |
| Static TC load | `sub_FFFFFFF007612114` | Loads TrustCache from device-tree `chosen/memory-map` |
| `query_trust_cache` | `0xfffffff007612070` | PPL vtable dispatch via `off_18E190` |
| `pmap_lookup_in_loaded_trust_caches` | `0xfffffff007309cd8` | Wraps `query_trust_cache(2, …)` |

### `trustcache` struct layout (kernel linked-list node)

No tvOS-specific struct type in IDA. Use **Dopamine iOS 16+ / XNU 22.x** `jbinfo` layout (same branch as tvOS 16.5):

| Field | Offset | PASS |
|-------|--------|------|
| `nextptr` | `0x0` | **LIKELY** (iOS 16+ standard; no tvOS delta found) |
| `prevptr` | `0x8` | **LIKELY** |
| `size` | `0x18` | **LIKELY** |
| `fileptr` | `0x20` | **LIKELY** |
| `struct_size` | `0x28` | **LIKELY** |

`jb_trustcache` upload blob uses `trustcache[0x40]` + `JB_MAGIC` at `offsetof(jb_trustcache, magic)` per `trustcache_structs.h`.

### Not required for Build 26 smoke

| Item | Reason |
|------|--------|
| `pmap_query_trust_cache_safe` | XPF helper to *find* `ppl_trust_cache_rt`; not used at runtime once VA is baked |
| PPL vtable (`off_18E190`) | Populated at runtime from PPL; not a static kernel VA |
| `developer_mode_enabled` | Build 27+ |

## Tier 3 summary

- **TIER3_SYMBOLS:** true (`ppl_trust_cache_rt`, list-head chain, `+0x20` offset)
- **TIER3_STRUCT:** likely PASS (iOS 16+ defaults; no contradicting tvOS evidence in IDA)

Ready to implement Build 26: bake `ppl_trust_cache_rt`, set `kernelStruct.trustcache` iOS 16+ overrides, wire `trustcache.c` + `kalloc_pt`.

## Tier 4 — proc / unsandbox / platformize (Build 27)

**Verified:** misaka `_offsets_init` 16.4+ table (`J/misaka_offsets_ida_dump.json`) cross-checked against Dopamine `jbinfo` XNU 22.x branch (`info.c`). No tvOS-specific deltas found.

| Field | Offset | Sources | PASS |
|-------|--------|---------|------|
| `proc.proc_ro` | `0x18` | misaka + jbinfo iOS16 | **PASS** |
| `proc.pid` | `0x60` | misaka `off_p_pid=96` | **PASS** |
| `proc.svuid` / `svgid` | `0x3C` / `0x40` | misaka 60/64 | **PASS** |
| `proc.flag` | `0x25C` | jbinfo iOS16 + misaka `off_p_flag` | **PASS** |
| `proc.struct_size` | `0x720` | `dt_baked_offsets.m` | **PASS** |
| `proc_ro.ucred` | `0x20` | misaka `off_p_ro_p_ucred=32` | **PASS** |
| `proc_ro.csflags` | `0x1C` | misaka `off_p_ro_p_csflags=28` | **PASS** |
| `ucred.label` | `0x78` | misaka `off_u_cr_label=120` | **PASS** |
| `ucred posix rgid/svgid/groups` | `+0x50/+0x54/+0x10` | jbinfo + misaka | **PASS** |
| `mac_label` slot | `1` → `-1` | Dopamine `elevatePrivileges` | **PASS** (iOS recipe) |
| `CS_PLATFORM_BINARY` | `0x04000000` | `codesign.h` | **PASS** |
| `developer_mode_enabled` | — | **Not required** on tvOS (no Settings gate; kernel has force-enable path) | **N/A** |
