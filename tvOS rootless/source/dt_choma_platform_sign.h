#pragma once

#include <stdint.h>
#include <choma/CodeDirectory.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t file_size;
    uint32_t cs_dataoff;
    uint32_t cs_datasize;
    uint64_t cs_end;
    uint64_t linkedit_fileoff;
    uint64_t linkedit_filesize;
    uint64_t linkedit_end;
    uint64_t linkedit_vmaddr;
    uint64_t linkedit_vmsize;
    uint8_t platform;
    cdhash_t cdhash;
    int layout_valid;
    int full_parse_ok;
} dt_choma_macho_layout_info_t;

/// Parse CSMAGIC_CODEDIRECTORY platform byte (offset 28, version >= 0x20100) from Mach-O file.
int dt_choma_macho_codedirectory_platform(const char *path, uint8_t *platform_out);

/// Full on-disk cdhash via Fat + macho_read_code_signature (same path as dt_macho_best_cdhash_from_path).
int dt_choma_macho_best_cdhash_from_path(const char *path, cdhash_t out);

/// Read LC_CODE_SIGNATURE + __LINKEDIT geometry and run full parser when possible.
int dt_choma_read_macho_layout(const char *path, dt_choma_macho_layout_info_t *out);

/// Require layout valid, platform match, full parse, cdhash match.
int dt_choma_validate_signed_macho(const char *path, uint8_t expected_platform,
    const cdhash_t expected_cdhash, dt_choma_macho_layout_info_t *out);

typedef struct {
    dt_choma_macho_layout_info_t pre_repair;
    dt_choma_macho_layout_info_t post_repair;
} dt_choma_sign_layout_report_t;

typedef struct {
    char first_defect[160];
    int postsign_file_parse;
    int linkedit_geometry;
    int codesig_geometry;
    int codedirectory_coverage;
    int final_cdhash_reparse;
    int structural_gate;
    dt_choma_macho_layout_info_t layout;
    uint64_t codeLimit;
    uint32_t page_bytes;
    uint32_t expected_code_slots;
    uint32_t actual_code_slots;
} dt_choma_structural_gate_result_t;

/// BUILD102723: on-disk structural gate before any dlopen probe.
int dt_choma_validate_signed_hook_structural(const char *path, uint8_t expected_platform,
    const cdhash_t expected_cdhash, dt_choma_structural_gate_result_t *out);

/// In-process ChOma sign with post-replace load-command repair and temp-file validation before rename.
/// report may be NULL; when set, pre_repair is geometry after replace before repair, post_repair after repair on temp file.
int dt_choma_platform_sign_staged_file(const char *target_path,
    const char *entitlements_path,
    const char *identifier,
    uint8_t platform_id,
    uint8_t *out_platform,
    cdhash_t out_cdhash,
    dt_choma_sign_layout_report_t *report);

#ifdef __cplusplus
}
#endif
