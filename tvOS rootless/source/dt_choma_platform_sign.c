/*
 * dt_choma_platform_sign — in-process ChOma platform signing (tvOS main app).
 * Build 102704: repair LC_CODE_SIGNATURE + __LINKEDIT after macho_replace_code_signature trim.
 */
#include "dt_choma_platform_sign.h"

#include <choma/MachO.h>
#include <choma/CSBlob.h>
#include <choma/Entitlements.h>
#include <choma/CodeDirectory.h>
#include <choma/MachOLoadCommand.h>
#include <choma/Fat.h>
#include <choma/FileStream.h>
#include <choma/Util.h>

#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_file_size(const char *path, uint64_t *size_out)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    *size_out = (uint64_t)st.st_size;
    return 0;
}

static int parse_lc_and_linkedit_from_file(const char *path, dt_choma_macho_layout_info_t *out)
{
    if (!path || !out)
        return -1;

    memset(out, 0, sizeof(*out));
    if (read_file_size(path, &out->file_size) != 0)
        return -2;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -3;

    MemoryStream *stream = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
    close(fd);
    if (!stream)
        return -4;

    Fat *fat = fat_init_from_memory_stream(stream);
    if (!fat) {
        memory_stream_free(stream);
        return -5;
    }

    MachO *macho = fat_get_single_slice(fat);
    if (!macho) {
        fat_free(fat);
        return -6;
    }

    uint32_t cs_off = 0, cs_sz = 0;
    if (macho_find_code_signature_bounds(macho, &cs_off, &cs_sz) != 0) {
        fat_free(fat);
        return -7;
    }

    out->cs_dataoff = cs_off;
    out->cs_datasize = cs_sz;
    out->cs_end = (uint64_t)cs_off + (uint64_t)cs_sz;

    __block int linkedit_found = 0;
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        (void)offset;
        if (loadCommand.cmd != LC_SEGMENT_64)
            return;
        struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
        SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(seg, LITTLE_TO_HOST_APPLIER);
        if (strcmp(seg->segname, "__LINKEDIT") != 0)
            return;
        out->linkedit_fileoff = seg->fileoff;
        out->linkedit_filesize = seg->filesize;
        out->linkedit_vmaddr = seg->vmaddr;
        out->linkedit_vmsize = seg->vmsize;
        out->linkedit_end = seg->fileoff + seg->filesize;
        linkedit_found = 1;
        *stop = true;
    });

    fat_free(fat);

    if (!linkedit_found)
        return -8;

    out->layout_valid = (out->cs_end <= out->file_size
        && out->linkedit_end <= out->file_size
        && out->cs_dataoff >= out->linkedit_fileoff
        && out->cs_end <= out->linkedit_end) ? 1 : 0;

    return 0;
}

int dt_choma_macho_best_cdhash_from_path(const char *path, cdhash_t out)
{
    if (!path || !out)
        return EINVAL;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return errno > 0 ? errno : -1;

    MemoryStream *stream = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
    close(fd);
    if (!stream)
        return EIO;

    Fat *fat = fat_init_from_memory_stream(stream);
    if (!fat) {
        memory_stream_free(stream);
        return ENOEXEC;
    }

    __block int result = ENOENT;
    fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
        CS_SuperBlob *superblob = macho_read_code_signature(macho);
        if (!superblob)
            return;

        CS_DecodedSuperBlob *decoded = csd_superblob_decode(superblob);
        if (!decoded) {
            free(superblob);
            return;
        }

        if (csd_superblob_calculate_best_cdhash(decoded, out, NULL) == 0)
            result = 0;

        csd_superblob_free(decoded);
        free(superblob);
        *stop = true;
    });

    fat_free(fat);
    return result;
}

int dt_choma_read_macho_layout(const char *path, dt_choma_macho_layout_info_t *out)
{
    if (!path || !out)
        return -1;

    int r = parse_lc_and_linkedit_from_file(path, out);
    if (r != 0)
        return r;

    uint8_t plat = 0;
    if (dt_choma_macho_codedirectory_platform(path, &plat) == 0)
        out->platform = plat;

    memset(out->cdhash, 0, sizeof(out->cdhash));
    out->full_parse_ok = (dt_choma_macho_best_cdhash_from_path(path, out->cdhash) == 0) ? 1 : 0;

    return 0;
}

int dt_choma_validate_signed_macho(const char *path, uint8_t expected_platform,
    const cdhash_t expected_cdhash, dt_choma_macho_layout_info_t *out)
{
    dt_choma_macho_layout_info_t local = {0};
    dt_choma_macho_layout_info_t *info = out ? out : &local;

    if (dt_choma_read_macho_layout(path, info) != 0)
        return -1;
    if (!info->layout_valid)
        return -2;
    if (!info->full_parse_ok)
        return -3;
    if (info->platform != expected_platform)
        return -4;
    if (memcmp(info->cdhash, expected_cdhash, CS_CDHASH_LEN) != 0)
        return -5;

    return 0;
}

int dt_choma_macho_codedirectory_platform(const char *path, uint8_t *platform_out)
{
    if (!path || !platform_out)
        return -1;

    FILE *f = fopen(path, "rb");
    if (!f)
        return -2;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -3;
    }
    long sz = ftell(f);
    if (sz < 32) {
        fclose(f);
        return -4;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -3;
    }

    uint8_t *data = malloc((size_t)sz);
    if (!data) {
        fclose(f);
        return -5;
    }
    if (fread(data, 1, (size_t)sz, f) != (size_t)sz) {
        free(data);
        fclose(f);
        return -6;
    }
    fclose(f);

    const uint8_t magic[4] = { 0xfa, 0xde, 0x0c, 0x02 };
    int found = 0;
    for (size_t i = 0; i + 32 < (size_t)sz; i++) {
        if (memcmp(data + i, magic, 4) != 0)
            continue;
        uint32_t ver = (uint32_t)(data[i + 8] << 24 | data[i + 9] << 16 | data[i + 10] << 8 | data[i + 11]);
        if (ver >= 0x20100) {
            *platform_out = data[i + offsetof(CS_CodeDirectory, platform)];
            found = 1;
            break;
        }
    }
    free(data);
    return found ? 0 : -7;
}

static int dt_choma_repair_codesign_layout(MachO *macho, uint64_t new_sig_size, uint64_t *desired_eof_out)
{
    uint32_t cs_off = 0, cs_old = 0;
    if (macho_find_code_signature_bounds(macho, &cs_off, &cs_old) != 0)
        return -30;

    __block uint64_t linkedit_fileoff = 0;
    __block uint64_t linkedit_vmaddr = 0;
    __block int found = 0;

    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        (void)offset;
        if (loadCommand.cmd != LC_SEGMENT_64)
            return;
        struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
        SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(seg, LITTLE_TO_HOST_APPLIER);
        if (strcmp(seg->segname, "__LINKEDIT") != 0)
            return;
        linkedit_fileoff = seg->fileoff;
        linkedit_vmaddr = seg->vmaddr;
        found = 1;
        *stop = true;
    });

    if (!found || cs_off < linkedit_fileoff)
        return -31;

    uint64_t desired_eof = (uint64_t)cs_off + new_sig_size;
    uint64_t new_linkedit_filesize = desired_eof - linkedit_fileoff;
    uint64_t new_vmsize = align_to_size((int)new_linkedit_filesize, 0x4000);

    update_lc_code_signature(macho, new_sig_size);
    update_segment_command_64(macho, "__LINKEDIT", linkedit_vmaddr, new_vmsize,
        linkedit_fileoff, new_linkedit_filesize);

    if (desired_eof_out)
        *desired_eof_out = desired_eof;

    return 0;
}

static void fill_layout_from_macho(MachO *macho, dt_choma_macho_layout_info_t *out)
{
    if (!macho || !out)
        return;
    memset(out, 0, sizeof(*out));
    out->file_size = memory_stream_get_size(macho->stream);
    if (macho_find_code_signature_bounds(macho, &out->cs_dataoff, &out->cs_datasize) == 0)
        out->cs_end = (uint64_t)out->cs_dataoff + (uint64_t)out->cs_datasize;
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        (void)offset;
        if (loadCommand.cmd != LC_SEGMENT_64)
            return;
        struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
        SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(seg, LITTLE_TO_HOST_APPLIER);
        if (strcmp(seg->segname, "__LINKEDIT") != 0)
            return;
        out->linkedit_fileoff = seg->fileoff;
        out->linkedit_filesize = seg->filesize;
        out->linkedit_vmaddr = seg->vmaddr;
        out->linkedit_vmsize = seg->vmsize;
        out->linkedit_end = seg->fileoff + seg->filesize;
        *stop = true;
    });
    out->layout_valid = (out->cs_end <= out->file_size && out->linkedit_end <= out->file_size) ? 1 : 0;
}

static void dt_choma_update_last_code_slot_hash(CS_DecodedBlob *codeDir, MachO *macho)
{
    CS_CodeDirectory cd;
    csd_blob_read(codeDir, 0, sizeof(cd), &cd);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&cd, BIG_TO_HOST_APPLIER);
    if (cd.nCodeSlots == 0)
        return;

    int lastSlot = (int)cd.nCodeSlots - 1;
    uint32_t cs_off = 0, cs_sz = 0;
    if (macho_find_code_signature_bounds(macho, &cs_off, &cs_sz) != 0 || cs_off == 0)
        return;

    uint32_t page_size = (uint32_t)(1u << cd.pageSize);
    uint32_t page_off = (uint32_t)lastSlot * page_size;
    if (page_off >= cs_off)
        return;

    uint32_t page_len = cs_off - page_off;
    uint8_t *page = malloc(page_len);
    if (!page)
        return;
    if (macho_read_at_offset(macho, page_off, page_len, page) != 0) {
        free(page);
        return;
    }

    uint8_t full_hash[CC_SHA384_DIGEST_LENGTH] = {0};
    switch (cd.hashType) {
    case CS_HASHTYPE_SHA160_160:
        CC_SHA1(page, (CC_LONG)page_len, full_hash);
        break;
    case CS_HASHTYPE_SHA256_256:
    case CS_HASHTYPE_SHA256_160:
        CC_SHA256(page, (CC_LONG)page_len, full_hash);
        break;
    case CS_HASHTYPE_SHA384_384:
        CC_SHA384(page, (CC_LONG)page_len, full_hash);
        break;
    default:
        free(page);
        return;
    }
    free(page);

    uint32_t slot_off = cd.hashOffset + (uint32_t)lastSlot * cd.hashSize;
    csd_blob_write(codeDir, slot_off, cd.hashSize, full_hash);
}

static int dt_choma_update_code_limit(CS_DecodedBlob *codeDir, MachO *macho)
{
    uint32_t cs_off = 0, cs_sz = 0;
    if (macho_find_code_signature_bounds(macho, &cs_off, &cs_sz) != 0 || cs_off == 0)
        return -1;

    uint32_t code_limit_be = HOST_TO_BIG(cs_off);
    if (csd_blob_write(codeDir, offsetof(CS_CodeDirectory, codeLimit), sizeof(uint32_t), &code_limit_be) != 0)
        return -2;
    return 0;
}

static int dt_choma_sync_codedirectory_slot_count(CS_DecodedBlob *codeDir, MachO *macho)
{
    uint32_t cs_off = 0, cs_sz = 0;
    if (macho_find_code_signature_bounds(macho, &cs_off, &cs_sz) != 0 || cs_off == 0)
        return -1;

    CS_CodeDirectory cd;
    csd_blob_read(codeDir, 0, sizeof(cd), &cd);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&cd, BIG_TO_HOST_APPLIER);
    if (cd.pageSize > 31)
        return -2;

    uint32_t page_bytes = 1u << cd.pageSize;
    if (page_bytes == 0)
        return -3;

    uint32_t new_slots = (cs_off + page_bytes - 1) / page_bytes;
    uint32_t slots_be = HOST_TO_BIG(new_slots);
    if (csd_blob_write(codeDir, offsetof(CS_CodeDirectory, nCodeSlots), sizeof(uint32_t), &slots_be) != 0)
        return -4;
    return 0;
}

static int dt_choma_apply_code_directory_hashes(CS_DecodedBlob *codeDir, MachO *macho,
    CS_DecodedBlob *xmlEntitlements, CS_DecodedBlob *derEntitlements, uint8_t platform_id)
{
    if (platform_id && csd_blob_write(codeDir, offsetof(CS_CodeDirectory, platform), 1, &platform_id) != 0)
        return -1;
    if (dt_choma_update_code_limit(codeDir, macho) != 0)
        return -2;
    if (dt_choma_sync_codedirectory_slot_count(codeDir, macho) != 0)
        return -3;
    csd_code_directory_update(codeDir, macho);
    dt_choma_update_last_code_slot_hash(codeDir, macho);
    csd_code_directory_update_special_slots(codeDir, xmlEntitlements, derEntitlements, NULL);
    return 0;
}

static int dt_choma_replace_repair_truncate(MachO *macho, const char *path,
    CS_DecodedSuperBlob *decoded, cdhash_t out_cdhash, uint8_t *out_platform)
{
    decoded->magic = CSMAGIC_EMBEDDED_SIGNATURE;

    CS_DecodedBlob *codeDir = csd_superblob_find_blob(decoded, CSSLOT_CODEDIRECTORY, NULL);
    if (!codeDir)
        return -47;

    if (out_cdhash)
        csd_superblob_calculate_best_cdhash(decoded, out_cdhash, NULL);
    if (out_platform) {
        uint8_t verifyPlatform = 0;
        csd_blob_read(codeDir, offsetof(CS_CodeDirectory, platform), 1, &verifyPlatform);
        *out_platform = verifyPlatform;
    }

    CS_SuperBlob *encoded = csd_superblob_encode(decoded);
    if (!encoded)
        return -44;

    if (macho_replace_code_signature(macho, encoded) != 0) {
        free(encoded);
        return -45;
    }

    uint64_t new_sig_size = BIG_TO_HOST(encoded->length);
    uint64_t desired_eof = 0;
    int rr = dt_choma_repair_codesign_layout(macho, new_sig_size, &desired_eof);
    free(encoded);
    if (rr != 0)
        return rr;

    macho_free(macho);

    if (truncate(path, (off_t)desired_eof) != 0)
        return -35;

    return 0;
}

static int dt_choma_post_replace_hash_closure(const char *path, uint8_t platform_id,
    cdhash_t out_cdhash, uint8_t *out_platform)
{
    MachO *macho = macho_init_for_writing(path);
    if (!macho)
        return -50;

    CS_SuperBlob *existing = macho_read_code_signature(macho);
    if (!existing) {
        macho_free(macho);
        return -51;
    }

    CS_DecodedSuperBlob *decoded = csd_superblob_decode(existing);
    free(existing);
    if (!decoded) {
        macho_free(macho);
        return -52;
    }

    CS_DecodedBlob *codeDir = csd_superblob_find_blob(decoded, CSSLOT_CODEDIRECTORY, NULL);
    CS_DecodedBlob *xmlEntitlements = csd_superblob_find_blob(decoded, CSSLOT_ENTITLEMENTS, NULL);
    CS_DecodedBlob *derEntitlements = csd_superblob_find_blob(decoded, CSSLOT_DER_ENTITLEMENTS, NULL);
    if (!derEntitlements)
        derEntitlements = csd_superblob_find_blob_by_magic(decoded, CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, NULL);

    if (!codeDir) {
        csd_superblob_free(decoded);
        macho_free(macho);
        return -53;
    }

    if (dt_choma_apply_code_directory_hashes(codeDir, macho, xmlEntitlements, derEntitlements, platform_id) != 0) {
        csd_superblob_free(decoded);
        macho_free(macho);
        return -54;
    }

    int rr = dt_choma_replace_repair_truncate(macho, path, decoded, out_cdhash, out_platform);
    csd_superblob_free(decoded);
    return rr;
}

static int dt_choma_verify_codedirectory_page_hashes(const char *path, uint32_t *mismatch_count_out)
{
    if (mismatch_count_out)
        *mismatch_count_out = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    MemoryStream *stream = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
    close(fd);
    if (!stream)
        return -2;

    Fat *fat = fat_init_from_memory_stream(stream);
    if (!fat) {
        memory_stream_free(stream);
        return -3;
    }

    MachO *macho = fat_get_single_slice(fat);
    if (!macho) {
        fat_free(fat);
        return -4;
    }

    CS_SuperBlob *superblob = macho_read_code_signature(macho);
    if (!superblob) {
        fat_free(fat);
        return -5;
    }

    CS_DecodedSuperBlob *decoded = csd_superblob_decode(superblob);
    free(superblob);
    if (!decoded) {
        fat_free(fat);
        return -6;
    }

    CS_DecodedBlob *codeDir = csd_superblob_find_blob(decoded, CSSLOT_CODEDIRECTORY, NULL);
    if (!codeDir) {
        csd_superblob_free(decoded);
        fat_free(fat);
        return -7;
    }

    CS_CodeDirectory cd;
    csd_blob_read(codeDir, 0, sizeof(cd), &cd);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&cd, BIG_TO_HOST_APPLIER);

    uint32_t cs_off = 0, cs_sz = 0;
    if (macho_find_code_signature_bounds(macho, &cs_off, &cs_sz) != 0 || cs_off == 0) {
        csd_superblob_free(decoded);
        fat_free(fat);
        return -8;
    }

    uint32_t page_bytes = 1u << cd.pageSize;
    uint32_t mismatches = 0;

    for (uint32_t slot = 0; slot < cd.nCodeSlots; slot++) {
        uint32_t page_off = slot * page_bytes;
        uint32_t page_len = page_bytes;
        if (page_off + page_len > cs_off)
            page_len = cs_off - page_off;
        if (page_len == 0 || page_off >= cs_off)
            break;

        uint8_t page[page_len];
        if (macho_read_at_offset(macho, page_off, page_len, page) != 0) {
            mismatches++;
            continue;
        }

        uint8_t full_hash[CC_SHA384_DIGEST_LENGTH] = {0};
        switch (cd.hashType) {
        case CS_HASHTYPE_SHA160_160:
            CC_SHA1(page, (CC_LONG)page_len, full_hash);
            break;
        case CS_HASHTYPE_SHA256_256:
        case CS_HASHTYPE_SHA256_160:
            CC_SHA256(page, (CC_LONG)page_len, full_hash);
            break;
        case CS_HASHTYPE_SHA384_384:
            CC_SHA384(page, (CC_LONG)page_len, full_hash);
            break;
        default:
            mismatches++;
            continue;
        }

        uint32_t slot_off = cd.hashOffset + slot * cd.hashSize;
        uint8_t stored[CC_SHA384_DIGEST_LENGTH] = {0};
        csd_blob_read(codeDir, slot_off, cd.hashSize, stored);
        if (memcmp(stored, full_hash, cd.hashSize) != 0)
            mismatches++;
    }

    csd_superblob_free(decoded);
    fat_free(fat);

    if (mismatch_count_out)
        *mismatch_count_out = mismatches;
    return mismatches == 0 ? 0 : -9;
}

int dt_choma_validate_signed_hook_structural(const char *path, uint8_t expected_platform,
    const cdhash_t expected_cdhash, dt_choma_structural_gate_result_t *out)
{
    dt_choma_structural_gate_result_t local = {0};
    dt_choma_structural_gate_result_t *r = out ? out : &local;
    memset(r, 0, sizeof(*r));

    if (!path) {
        snprintf(r->first_defect, sizeof(r->first_defect), "NULL_PATH");
        return -1;
    }

    if (dt_choma_read_macho_layout(path, &r->layout) != 0) {
        snprintf(r->first_defect, sizeof(r->first_defect), "POSTSIGN_FILE_PARSE_FAIL");
        return -2;
    }
    r->postsign_file_parse = 1;

    uint64_t cs_end = r->layout.cs_end;
    uint64_t le_end = r->layout.linkedit_end;
    uint64_t fs = r->layout.file_size;

    if (cs_end != fs || le_end != fs
        || r->layout.cs_dataoff < r->layout.linkedit_fileoff
        || cs_end > le_end) {
        snprintf(r->first_defect, sizeof(r->first_defect), "LINKEDIT_OR_CODESIG_GEOMETRY");
        r->linkedit_geometry = (le_end == fs) ? 1 : 0;
        r->codesig_geometry = (cs_end == fs) ? 1 : 0;
        return -3;
    }
    r->linkedit_geometry = 1;
    r->codesig_geometry = 1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(r->first_defect, sizeof(r->first_defect), "OPEN_FAIL");
        return -4;
    }

    MemoryStream *stream = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
    close(fd);
    if (!stream) {
        snprintf(r->first_defect, sizeof(r->first_defect), "STREAM_FAIL");
        return -5;
    }

    Fat *fat = fat_init_from_memory_stream(stream);
    if (!fat) {
        snprintf(r->first_defect, sizeof(r->first_defect), "FAT_PARSE_FAIL");
        return -6;
    }

    MachO *macho = fat_get_single_slice(fat);
    CS_SuperBlob *superblob = macho ? macho_read_code_signature(macho) : NULL;
    CS_DecodedSuperBlob *decoded = superblob ? csd_superblob_decode(superblob) : NULL;
    if (superblob)
        free(superblob);

    if (!decoded) {
        fat_free(fat);
        snprintf(r->first_defect, sizeof(r->first_defect), "SUPERBLOB_DECODE_FAIL");
        return -7;
    }

    CS_DecodedBlob *codeDir = csd_superblob_find_blob(decoded, CSSLOT_CODEDIRECTORY, NULL);
    if (!codeDir) {
        csd_superblob_free(decoded);
        fat_free(fat);
        snprintf(r->first_defect, sizeof(r->first_defect), "CODEDIRECTORY_MISSING");
        return -8;
    }

    CS_CodeDirectory cd;
    csd_blob_read(codeDir, 0, sizeof(cd), &cd);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&cd, BIG_TO_HOST_APPLIER);

    r->codeLimit = cd.codeLimit;
    r->page_bytes = 1u << cd.pageSize;
    r->actual_code_slots = cd.nCodeSlots;
    if (r->page_bytes)
        r->expected_code_slots = (uint32_t)((cd.codeLimit + r->page_bytes - 1) / r->page_bytes);

  __block uint64_t max_exec_end = 0;
    if (macho) {
        macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
            (void)offset; (void)stop;
            if (loadCommand.cmd != LC_SEGMENT_64)
                return;
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(seg, LITTLE_TO_HOST_APPLIER);
            if ((seg->initprot & 4) == 0)
                return;
            uint64_t end = seg->fileoff + seg->filesize;
            if (end > max_exec_end)
                max_exec_end = end;
        });
    }

    if (cd.codeLimit != r->layout.cs_dataoff) {
        snprintf(r->first_defect, sizeof(r->first_defect), "CODELIMIT_NE_CS_DATAOFF");
        csd_superblob_free(decoded);
        fat_free(fat);
        return -9;
    }
    if (r->expected_code_slots != r->actual_code_slots) {
        snprintf(r->first_defect, sizeof(r->first_defect), "NCODESLOTS_MISMATCH");
        csd_superblob_free(decoded);
        fat_free(fat);
        return -10;
    }
    if (max_exec_end > cd.codeLimit) {
        snprintf(r->first_defect, sizeof(r->first_defect), "EXEC_EXCEEDS_CODELIMIT");
        csd_superblob_free(decoded);
        fat_free(fat);
        return -11;
    }
    if (cd.platform != expected_platform) {
        snprintf(r->first_defect, sizeof(r->first_defect), "PLATFORM_NOT_%u", (unsigned)expected_platform);
        csd_superblob_free(decoded);
        fat_free(fat);
        return -12;
    }

    csd_superblob_free(decoded);
    fat_free(fat);

    uint32_t hash_mismatches = 0;
    if (dt_choma_verify_codedirectory_page_hashes(path, &hash_mismatches) != 0) {
        snprintf(r->first_defect, sizeof(r->first_defect), "PAGE_HASH_MISMATCH_%u", hash_mismatches);
        return -13;
    }
    r->codedirectory_coverage = 1;

    cdhash_t disk_cd = {0};
    if (!r->layout.full_parse_ok || dt_choma_macho_best_cdhash_from_path(path, disk_cd) != 0
        || memcmp(disk_cd, expected_cdhash, CS_CDHASH_LEN) != 0) {
        snprintf(r->first_defect, sizeof(r->first_defect), "FINAL_CDHASH_REPARSE_FAIL");
        return -14;
    }
    r->final_cdhash_reparse = 1;

    r->structural_gate = 1;
    return 0;
}

static int rehash_codesignature_on_final_file(const char *path, cdhash_t out_cdhash, uint8_t *out_platform,
    uint8_t platform_id)
{
    MachO *macho = macho_init_for_writing(path);
    if (!macho)
        return -40;

    CS_SuperBlob *existing = macho_read_code_signature(macho);
    if (!existing) {
        macho_free(macho);
        return -41;
    }

    CS_DecodedSuperBlob *decoded = csd_superblob_decode(existing);
    free(existing);
    if (!decoded) {
        macho_free(macho);
        return -42;
    }

    CS_DecodedBlob *codeDir = csd_superblob_find_blob(decoded, CSSLOT_CODEDIRECTORY, NULL);
    CS_DecodedBlob *xmlEntitlements = csd_superblob_find_blob(decoded, CSSLOT_ENTITLEMENTS, NULL);
    CS_DecodedBlob *derEntitlements = csd_superblob_find_blob(decoded, CSSLOT_DER_ENTITLEMENTS, NULL);
    if (!derEntitlements)
        derEntitlements = csd_superblob_find_blob_by_magic(decoded, CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, NULL);

    if (!codeDir) {
        csd_superblob_free(decoded);
        macho_free(macho);
        return -43;
    }

    if (dt_choma_apply_code_directory_hashes(codeDir, macho, xmlEntitlements, derEntitlements, platform_id) != 0) {
        csd_superblob_free(decoded);
        macho_free(macho);
        return -46;
    }

    int rr = dt_choma_replace_repair_truncate(macho, path, decoded, out_cdhash, out_platform);
    csd_superblob_free(decoded);
    if (rr != 0)
        return rr;

    return dt_choma_post_replace_hash_closure(path, platform_id, out_cdhash, out_platform);
}

static int sign_macho_at_path(const char *path, const char *entitlements_path,
    const char *identifier, uint8_t platform_id, uint8_t *out_platform, cdhash_t out_cdhash,
    dt_choma_sign_layout_report_t *report)
{
    MachO *macho = macho_init_for_writing(path);
    if (!macho)
        return -10;

    CS_DecodedBlob *xmlEntitlements = NULL;
    CS_DecodedBlob *derEntitlements = NULL;
    if (entitlements_path) {
        xmlEntitlements = create_xml_entitlements_blob(entitlements_path);
        derEntitlements = create_der_entitlements_blob(entitlements_path);
        if (!xmlEntitlements || !derEntitlements) {
            macho_free(macho);
            return -11;
        }
        csd_blob_set_type(derEntitlements, CSSLOT_DER_ENTITLEMENTS);
    }

    CS_DecodedBlob *codeDir = csd_code_directory_init(macho, CS_HASHTYPE_SHA256_256, false);
    if (!codeDir) {
        if (xmlEntitlements)
            csd_blob_free(xmlEntitlements);
        if (derEntitlements)
            csd_blob_free(derEntitlements);
        macho_free(macho);
        return -12;
    }

    if (identifier && csd_code_directory_set_identifier(codeDir, (char *)identifier) != 0) {
        csd_blob_free(codeDir);
        if (xmlEntitlements)
            csd_blob_free(xmlEntitlements);
        if (derEntitlements)
            csd_blob_free(derEntitlements);
        macho_free(macho);
        return -13;
    }

    if (csd_blob_write(codeDir, offsetof(CS_CodeDirectory, platform), 1, &platform_id) != 0) {
        csd_blob_free(codeDir);
        if (xmlEntitlements)
            csd_blob_free(xmlEntitlements);
        if (derEntitlements)
            csd_blob_free(derEntitlements);
        macho_free(macho);
        return -14;
    }

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_init();
    if (!decodedSuperblob) {
        csd_blob_free(codeDir);
        if (xmlEntitlements)
            csd_blob_free(xmlEntitlements);
        if (derEntitlements)
            csd_blob_free(derEntitlements);
        macho_free(macho);
        return -15;
    }
    decodedSuperblob->magic = CSMAGIC_EMBEDDED_SIGNATURE;
    csd_superblob_append_blob(decodedSuperblob, codeDir);
    if (xmlEntitlements)
        csd_superblob_append_blob(decodedSuperblob, xmlEntitlements);
    if (derEntitlements)
        csd_superblob_append_blob(decodedSuperblob, derEntitlements);

    csd_code_directory_update(codeDir, macho);
    csd_code_directory_update_special_slots(codeDir, xmlEntitlements, derEntitlements, NULL);

    CS_SuperBlob *encoded = csd_superblob_encode(decodedSuperblob);
    if (!encoded) {
        csd_superblob_free(decodedSuperblob);
        macho_free(macho);
        return -15;
    }

    if (macho_replace_code_signature(macho, encoded) != 0) {
        free(encoded);
        csd_superblob_free(decodedSuperblob);
        macho_free(macho);
        return -16;
    }

    if (report)
        fill_layout_from_macho(macho, &report->pre_repair);

    uint64_t new_sig_size = BIG_TO_HOST(encoded->length);
    uint64_t desired_eof = 0;
    int rr = dt_choma_repair_codesign_layout(macho, new_sig_size, &desired_eof);
    if (rr != 0) {
        free(encoded);
        csd_superblob_free(decodedSuperblob);
        macho_free(macho);
        return rr;
    }

    if (report)
        fill_layout_from_macho(macho, &report->post_repair);

    csd_superblob_free(decodedSuperblob);
    free(encoded);
    macho_free(macho);

    if (truncate(path, (off_t)desired_eof) != 0)
        return -35;

    return rehash_codesignature_on_final_file(path, out_cdhash, out_platform, platform_id);
}

int dt_choma_platform_sign_staged_file(const char *target_path,
    const char *entitlements_path,
    const char *identifier,
    uint8_t platform_id,
    uint8_t *out_platform,
    cdhash_t out_cdhash,
    dt_choma_sign_layout_report_t *report)
{
    if (!target_path || !entitlements_path)
        return -1;
    if (access(target_path, R_OK) != 0)
        return -2;
    if (access(entitlements_path, R_OK) != 0)
        return -3;

    char tmp_path[512];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.choma.tmp", target_path);
    if (n <= 0 || n >= (int)sizeof(tmp_path))
        return -4;

    unlink(tmp_path);
    if (copyfile(target_path, tmp_path, NULL, COPYFILE_ALL) != 0)
        return -5;
    chmod(tmp_path, 0755);

    cdhash_t mem_cd = {0};
    uint8_t mem_platform = 0;

    int sr = sign_macho_at_path(tmp_path, entitlements_path, identifier, platform_id,
        &mem_platform, mem_cd, report);
    if (sr != 0) {
        unlink(tmp_path);
        return sr;
    }

    int vr = dt_choma_validate_signed_macho(tmp_path, platform_id, mem_cd, NULL);
    if (vr != 0) {
        unlink(tmp_path);
        return -50 - vr;
    }

    if (out_platform)
        *out_platform = mem_platform;
    if (out_cdhash)
        memcpy(out_cdhash, mem_cd, CS_CDHASH_LEN);

    if (rename(tmp_path, target_path) != 0) {
        unlink(tmp_path);
        return -20;
    }
    chmod(target_path, 0755);

    if (dt_choma_validate_signed_macho(target_path, platform_id, mem_cd, NULL) != 0)
        return -41;

    return 0;
}
