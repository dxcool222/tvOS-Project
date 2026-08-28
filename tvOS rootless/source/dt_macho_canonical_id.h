#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical Mach-O identity (TrollStore CS-invariant). See tools/rootless_macho_canonical_id.py.
 * Bytes after the bounded LC_CODE_SIGNATURE region are deliberately not identity-significant;
 * strict consumers must additionally call dt_macho_cs_end_valid().
 * out_hex must hold >= 65 bytes (64 hex + NUL). Returns 0 on success. */
int dt_macho_canonical_sha256_hex(const char *path, char *out_hex, size_t out_hex_sz);

/* Raw whole-file SHA-256 hex. out_hex must hold >= 65 bytes. */
int dt_macho_raw_sha256_hex(const char *path, char *out_hex, size_t out_hex_sz);

/* LC_UUID as uppercase 8-4-4-4-12 string. out must hold >= 37 bytes. */
int dt_macho_uuid_string(const char *path, char *out, size_t out_sz);

/* Require LC_CODE_SIGNATURE.dataoff + datasize == file size (fail-closed). */
int dt_macho_cs_end_valid(const char *path);

typedef struct {
    uint64_t file_size;
    uint64_t cs_end;
    uint64_t trailer_size;
    uint64_t max_non_signature_end;
    uint64_t jbinfo_fileoff;
    uint64_t jbinfo_size;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t cs_off;
    uint32_t cs_size;
} dt_macho_runtime_layout_t;

enum {
    DT_MACHO_RUNTIME_LAYOUT_HEADER = 1001,
    DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE,
    DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE,
    DT_MACHO_RUNTIME_LAYOUT_CARDINALITY,
    DT_MACHO_RUNTIME_LAYOUT_CS_BOUNDS,
    DT_MACHO_RUNTIME_LAYOUT_LINKEDIT_BOUNDS,
    DT_MACHO_RUNTIME_LAYOUT_NON_SIGNATURE_BOUNDARY,
    DT_MACHO_RUNTIME_LAYOUT_JBINFO_BOUNDS,
    DT_MACHO_RUNTIME_LAYOUT_SYMBOL_BOUNDS,
};

/* Validate the installed generated-dyld layout without requiring CS-at-EOF.
 * This is deliberately separate from the D0 canonical identity path.  It
 * requires exact command cardinality, bounded file-backed ranges, the pinned
 * generated-dyld command count/CS offset/non-signature boundary, and the
 * expected __DATA,__jbinfo size.  Returns 0 and fills out_layout on success. */
int dt_macho_runtime_layout_validate(const char *path,
                                     uint32_t expected_ncmds,
                                     uint32_t expected_cs_off,
                                     uint64_t expected_max_non_signature_end,
                                     uint64_t expected_jbinfo_size,
                                     dt_macho_runtime_layout_t *out_layout);

/* Compare file bytes at offset to expected (hex pairs, lowercase). */
int dt_macho_bytes_match_hex(const char *path, uint32_t offset, const char *expected_hex);

/* Validate __DATA,__jbinfo exists with expected size and in-file bounds. */
int dt_macho_jbinfo_section_valid(const char *path, uint64_t expected_size);

#ifdef __cplusplus
}
#endif
