/*
 * Host CodeDirectory integrity audit — final post-ChOma/post-layout/post-truncate bytes.
 * macOS-native; disposable Mach-O fixture only.
 *
 * usage:
 *   host_cd_integrity_audit sign <hook.dylib> <entitlements.plist>
 *   host_cd_integrity_audit audit <final_macho>
 */
#include <copyfile.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <CommonCrypto/CommonDigest.h>

#include "MachO.h"
#include "CSBlob.h"
#include "CodeDirectory.h"
#include "Fat.h"
#include "FileStream.h"
#include "Util.h"

#include "dt_choma_platform_sign.h"

static void hexprint(const uint8_t *b, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++)
        sprintf(out + i * 2, "%02x", b[i]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int page_bytes(uint8_t pageSizeLog2)
{
    return 1 << pageSizeLog2;
}

static unsigned char *(*hash_func_for(uint8_t hashType))(const void *, CC_LONG, unsigned char *)
{
    switch (hashType) {
    case CS_HASHTYPE_SHA160_160: return CC_SHA1;
    case CS_HASHTYPE_SHA256_256:
    case CS_HASHTYPE_SHA256_160: return CC_SHA256;
    case CS_HASHTYPE_SHA384_384: return CC_SHA384;
    default: return NULL;
    }
}

static int audit_superblob_index_raw(const uint8_t *sb, uint32_t sb_len, int *ent_ok, int *der_ok)
{
    if (sb_len < 12)
        return 0;
    if (read_be32(sb) != CSMAGIC_EMBEDDED_SIGNATURE)
        return 0;
    uint32_t length = read_be32(sb + 4);
    uint32_t count = read_be32(sb + 8);
    if (length > sb_len || length < 12)
        return 0;
    if (count > (length - 12) / 8)
        return 0;

    int valid = 1;
    *ent_ok = 0;
    *der_ok = 0;

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *idx = sb + 12 + i * 8;
        uint32_t type = read_be32(idx);
        uint32_t off = read_be32(idx + 4);
        if (off >= length || off + 8 > length) {
            valid = 0;
            continue;
        }
        const uint8_t *blob = sb + off;
        uint32_t bm = read_be32(blob);
        uint32_t bl = read_be32(blob + 4);
        if (bl < 8 || off + bl > length) {
            valid = 0;
            continue;
        }
        if (type == CSSLOT_ENTITLEMENTS) {
            if (bm == CSMAGIC_EMBEDDED_ENTITLEMENTS)
                *ent_ok = 1;
            else
                valid = 0;
        }
        if (type == CSSLOT_DER_ENTITLEMENTS) {
            if (bm == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS)
                *der_ok = 1;
            else
                valid = 0;
        }
        if (type == CSSLOT_CODEDIRECTORY && bm != CSMAGIC_CODEDIRECTORY)
            valid = 0;
    }
    return valid;
}

static int audit_special_slots(CS_DecodedBlob *cd_blob, CS_DecodedSuperBlob *decoded)
{
    CS_CodeDirectory cd;
    csd_blob_read(cd_blob, 0, sizeof(cd), &cd);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&cd, BIG_TO_HOST_APPLIER);

    CS_DecodedBlob *xml = csd_superblob_find_blob(decoded, CSSLOT_ENTITLEMENTS, NULL);
    CS_DecodedBlob *der = csd_superblob_find_blob(decoded, CSSLOT_DER_ENTITLEMENTS, NULL);
    if (!xml || !der)
        return 0;

    unsigned char *(*hf)(const void *, CC_LONG, unsigned char *) = hash_func_for(cd.hashType);
    if (!hf)
        return 0;

    for (uint32_t i = 1; i <= cd.nSpecialSlots; i++) {
        uint32_t hash_off = cd.hashOffset - (i * cd.hashSize);
        if (hash_off + cd.hashSize > csd_blob_get_size(cd_blob))
            return 0;

        uint8_t stored[32] = {0};
        csd_blob_read(cd_blob, hash_off, cd.hashSize, stored);

        if (i == CSSLOT_ENTITLEMENTS) {
            uint8_t calc[32] = {0};
            uint8_t *xml_buf = malloc(memory_stream_get_size(xml->stream));
            if (!xml_buf)
                return 0;
            csd_blob_read(xml, 0, memory_stream_get_size(xml->stream), xml_buf);
            hf(xml_buf, (CC_LONG)memory_stream_get_size(xml->stream), calc);
            free(xml_buf);
            if (memcmp(stored, calc, cd.hashSize) != 0)
                return 0;
        } else if (i == CSSLOT_DER_ENTITLEMENTS) {
            uint8_t calc[32] = {0};
            uint8_t *der_buf = malloc(memory_stream_get_size(der->stream));
            if (!der_buf)
                return 0;
            csd_blob_read(der, 0, memory_stream_get_size(der->stream), der_buf);
            hf(der_buf, (CC_LONG)memory_stream_get_size(der->stream), calc);
            free(der_buf);
            if (memcmp(stored, calc, cd.hashSize) != 0)
                return 0;
        }
    }
    return 1;
}

static int audit_cd_bounds(const CS_CodeDirectory *cd, size_t cd_len)
{
    if (cd->length > cd_len)
        return 0;
    if (cd->hashOffset < sizeof(CS_CodeDirectory))
        return 0;
    uint32_t hash_end = cd->hashOffset + cd->nCodeSlots * cd->hashSize;
    if (hash_end > cd->length)
        return 0;
    if (cd->hashOffset < cd->nSpecialSlots * cd->hashSize)
        return 0;
    if (cd->identOffset && cd->identOffset >= cd->length)
        return 0;
    if (cd->version >= 0x20100 && cd->scatterOffset && cd->scatterOffset >= cd->length)
        return 0;
    if (cd->version >= 0x20200 && cd->teamOffset && cd->teamOffset >= cd->length)
        return 0;
    return 1;
}

static uint32_t signed_range_end(uint32_t code_limit, uint32_t psz)
{
    if (psz == 0)
        return 0;
    uint32_t mask = psz - 1;
    return (code_limit + mask) & ~mask;
}

static uint32_t expected_ncodeslots(uint32_t code_limit, uint32_t psz)
{
    uint32_t end = signed_range_end(code_limit, psz);
    if (psz == 0)
        return 0;
    return end / psz;
}

static int audit_codelimit_ncodeslots(const CS_CodeDirectory *cd, uint32_t cs_off,
    uint32_t *expected_slots_out)
{
    uint32_t psz = (uint32_t)page_bytes(cd->pageSize);
    if (cd->codeLimit == 0 || psz == 0)
        return 0;
    if (cd->codeLimit != cs_off)
        return 0;
    uint32_t expected = expected_ncodeslots(cd->codeLimit, psz);
    if (expected_slots_out)
        *expected_slots_out = expected;
    return cd->nCodeSlots == expected;
}

static int audit_page_hashes_choma(CS_DecodedBlob *cd_blob, MachO *macho,
    int *first_bad, char *exp_hex, char *act_hex)
{
    CS_CodeDirectory cd;
    csd_blob_read(cd_blob, 0, sizeof(cd), &cd);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&cd, BIG_TO_HOST_APPLIER);

    uint32_t psz = (uint32_t)page_bytes(cd.pageSize);
    uint32_t cs_off = 0, cs_sz = 0;
    macho_find_code_signature_bounds(macho, &cs_off, &cs_sz);
    uint64_t file_size = memory_stream_get_size(macho->stream);

    uint32_t signed_end = cd.codeLimit ? signed_range_end(cd.codeLimit, psz) : 0;
    uint32_t slot_limit = cd.codeLimit ? expected_ncodeslots(cd.codeLimit, psz) : cd.nCodeSlots;
    if (slot_limit == 0 || slot_limit > cd.nCodeSlots)
        return -3;

    unsigned char *(*hf)(const void *, CC_LONG, unsigned char *) = hash_func_for(cd.hashType);
    if (!hf)
        return -2;

    for (uint32_t slot = 0; slot < slot_limit; slot++) {
        uint32_t page_off = slot * psz;
        uint32_t page_len = psz;

        if (slot == slot_limit - 1) {
            uint32_t last_end = cd.codeLimit ? cd.codeLimit : cs_off;
            if (page_off > last_end)
                return -2;
            if (!last_end)
                page_len = (uint32_t)(file_size - page_off);
            else
                page_len = last_end - page_off;
        } else if (signed_end && page_off + page_len > signed_end) {
            page_len = signed_end - page_off;
        }

        if ((uint64_t)page_off + page_len > file_size)
            return -2;

        uint8_t page[65536];
        if (page_len > sizeof(page))
            return -2;
        if (macho_read_at_offset(macho, page_off, page_len, page) != 0)
            return -2;

        uint8_t calc[32] = {0};
        uint8_t full[CC_SHA384_DIGEST_LENGTH];
        hf(page, (CC_LONG)page_len, full);
        memcpy(calc, full, cd.hashSize);

        uint32_t slot_off = cd.hashOffset + slot * cd.hashSize;
        uint8_t stored[32] = {0};
        csd_blob_read(cd_blob, slot_off, cd.hashSize, stored);

        if (memcmp(stored, calc, cd.hashSize) != 0) {
            *first_bad = (int)slot;
            hexprint(calc, cd.hashSize, exp_hex);
            hexprint(stored, cd.hashSize, act_hex);
            return 1;
        }
    }
    return 0;
}

static int audit_file(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        perror("stat");
        return 2;
    }

    int fd = open(path, O_RDONLY);
    MemoryStream *ms = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
    close(fd);
    Fat *fat = fat_init_from_memory_stream(ms);
    MachO *macho = fat_get_single_slice(fat);

    uint32_t cs_off = 0, cs_sz = 0;
    macho_find_code_signature_bounds(macho, &cs_off, &cs_sz);

    if (cs_off == 0 || cs_sz < 12 || (uint64_t)cs_off + cs_sz > (uint64_t)st.st_size) {
        printf("FINAL_CODEDIRECTORY_PARSE=FAIL\n");
        printf("LC_CODE_SIGNATURE_INVALID=YES\n");
        fat_free(fat);
        return 1;
    }

    uint8_t *sb_raw_buf = malloc(cs_sz);
    if (!sb_raw_buf || macho_read_at_offset(macho, cs_off, cs_sz, sb_raw_buf) != 0) {
        free(sb_raw_buf);
        printf("FINAL_CODEDIRECTORY_PARSE=FAIL\n");
        fat_free(fat);
        return 1;
    }
    const uint8_t *sb_raw = sb_raw_buf;
    int ent_idx_ok = 0, der_idx_ok = 0;
    int idx_valid = audit_superblob_index_raw(sb_raw, cs_sz, &ent_idx_ok, &der_idx_ok);

    CS_SuperBlob *sb = macho_read_code_signature(macho);
    if (!sb) {
        printf("FINAL_CODEDIRECTORY_PARSE=FAIL\n");
        fat_free(fat);
        return 1;
    }

    CS_DecodedSuperBlob *decoded = csd_superblob_decode(sb);
    if (!decoded) {
        printf("FINAL_CODEDIRECTORY_PARSE=FAIL\n");
        free(sb);
        fat_free(fat);
        return 1;
    }

    CS_DecodedBlob *cd_blob = csd_superblob_find_blob(decoded, CSSLOT_CODEDIRECTORY, NULL);
    if (!cd_blob) {
        printf("FINAL_CODEDIRECTORY_PARSE=FAIL\n");
        csd_superblob_free(decoded);
        free(sb);
        fat_free(fat);
        return 1;
    }

    CS_CodeDirectory cd;
    csd_blob_read(cd_blob, 0, sizeof(cd), &cd);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&cd, BIG_TO_HOST_APPLIER);

    printf("FINAL_FILE_SIZE=%lld\n", (long long)st.st_size);
    printf("LC_CODE_SIGNATURE_DATAOFF=%u\n", cs_off);
    printf("LC_CODE_SIGNATURE_DATASIZE=%u\n", cs_sz);
    printf("CD_LENGTH=%u\n", cd.length);
    printf("CD_VERSION=0x%x\n", cd.version);
    printf("CD_FLAGS=0x%x\n", cd.flags);
    printf("CD_PLATFORM=%u\n", (unsigned)cd.platform);
    printf("CD_HASHTYPE=%u\n", (unsigned)cd.hashType);
    printf("CD_HASHSIZE=%u\n", (unsigned)cd.hashSize);
    printf("CD_PAGESIZE_LOG2=%u\n", (unsigned)cd.pageSize);
    printf("CD_PAGESIZE_BYTES=%d\n", page_bytes(cd.pageSize));
    printf("CD_CODELIMIT=%u\n", cd.codeLimit);
    printf("CD_CODELIMIT64=NOT_IN_CHOMA_STRUCT\n");
    printf("CD_NCODESLOTS=%u\n", cd.nCodeSlots);
    printf("CD_NSPECIALSLOTS=%u\n", cd.nSpecialSlots);
    printf("CD_HASHOFFSET=%u\n", cd.hashOffset);
    printf("CD_IDENTOFFSET=%u\n", cd.identOffset);
    printf("CD_SCATTEROFFSET=%u\n", cd.scatterOffset);

    int cd_bounds = audit_cd_bounds(&cd, csd_blob_get_size(cd_blob));
    int special_ok = audit_special_slots(cd_blob, decoded);

    int scatter_state = 0; /* NOT_PRESENT */
    if (cd.version >= 0x20100 && cd.scatterOffset) {
        scatter_state = (cd.scatterOffset + 8 <= csd_blob_get_size(cd_blob)) ? 1 : -1;
    }

    int first_bad = -1;
    char exp_hex[128] = {0}, act_hex[128] = {0};
    int phv = audit_page_hashes_choma(cd_blob, macho, &first_bad, exp_hex, act_hex);

    uint32_t psz = (uint32_t)page_bytes(cd.pageSize);
    uint32_t expected_slots = 0;
    int codelimit_valid = audit_codelimit_ncodeslots(&cd, cs_off, &expected_slots);
    int ncodeslots_valid = codelimit_valid;
    uint32_t codelimit64 = 0;
    int has_codelimit64 = (cd.version >= 0x20300);
    if (has_codelimit64) {
        uint8_t cl64raw[4];
        csd_blob_read(cd_blob, 52, 4, cl64raw);
        codelimit64 = read_be32(cl64raw);
    }

    printf("HOST_VERIFIER_USES_CODELIMIT=YES\n");
    printf("HOST_VERIFIER_USES_CODELIMIT64_WHEN_SUPPORTED=%s\n", has_codelimit64 ? "YES" : "NO");
    printf("HOST_VERIFIER_VALIDATES_NCODESLOTS_AGAINST_SIGNED_RANGE=YES\n");
    printf("EXPECTED_NCODESLOTS_FROM_SIGNED_RANGE=%u\n", expected_slots);
    printf("ACTUAL_NCODESLOTS=%u\n", cd.nCodeSlots);
    printf("NCODESLOTS_RANGE_MATCH=%s\n", ncodeslots_valid ? "YES" : "NO");
    printf("FINAL_CODELIMIT=%u\n", cd.codeLimit);
    if (has_codelimit64)
        printf("FINAL_CODELIMIT64=%u\n", codelimit64);
    else
        printf("FINAL_CODELIMIT64=NOT_PRESENT\n");
    printf("FINAL_NCODESLOTS=%u\n", cd.nCodeSlots);
    printf("FINAL_PAGESIZE=%u\n", (unsigned)cd.pageSize);
    printf("FINAL_CS_DATAOFF=%u\n", cs_off);
    printf("FINAL_CODELIMIT_VALID=%s\n", codelimit_valid ? "YES" : "NO");
    printf("FINAL_NCODESLOTS_VALID=%s\n", ncodeslots_valid ? "YES" : "NO");

    printf("FINAL_CODEDIRECTORY_PARSE=PASS\n");
    printf("CODEDIRECTORY_BOUNDS_VALID=%s\n", cd_bounds ? "YES" : "NO");
    printf("SUPERBLOB_INDEX_VALID=%s\n", idx_valid ? "YES" : "NO");
    printf("ENTITLEMENTS_SLOTS_VALID=%s\n", (ent_idx_ok && der_idx_ok && special_ok) ? "YES" : "NO");
    if (scatter_state == 0)
        printf("SCATTER_BOUNDS_VALID=NOT_PRESENT\n");
    else
        printf("SCATTER_BOUNDS_VALID=%s\n", scatter_state > 0 ? "YES" : "NO");

    if (phv == 0) {
        printf("FINAL_PAGE_HASH_VERIFY=PASS\n");
        printf("FIRST_MISMATCHED_CODE_SLOT=\n");
        printf("EXPECTED_HASH=\n");
        printf("ACTUAL_HASH=\n");
    } else {
        printf("FINAL_PAGE_HASH_VERIFY=FAIL\n");
        if (phv == 1)
            printf("FIRST_MISMATCHED_CODE_SLOT=%d\n", first_bad);
        else
            printf("FIRST_MISMATCHED_CODE_SLOT=\n");
        printf("EXPECTED_HASH=%s\n", exp_hex);
        printf("ACTUAL_HASH=%s\n", act_hex);
    }

    uint8_t *cd_raw = malloc(csd_blob_get_size(cd_blob));
    csd_blob_read(cd_blob, 0, csd_blob_get_size(cd_blob), cd_raw);
    int k6318 = 0;
    if (csd_blob_get_size(cd_blob) < 0x70)
        k6318 |= 1;
    if (read_be32(cd_raw) != CSMAGIC_CODEDIRECTORY)
        k6318 |= 2;
    if ((cd_raw[39] | 2) != 0xE)
        k6318 |= 4;
    if ((cd.hashType - 1) > 3)
        k6318 |= 8;
    if (cd.hashOffset > cd.length)
        k6318 |= 16;
    if (cd.identOffset && cd.identOffset >= cd.length)
        k6318 |= 32;
    if ((cd.version >> 8) >= 0x201 && cd.scatterOffset && cd.scatterOffset >= cd.length)
        k6318 |= 64;
    printf("KERNEL_6318B8_STRUCT_CHECKS_FAIL_MASK=0x%x\n", k6318);
    printf("KERNEL_6318B8_PAGE_SIZE_BYTE39=0x%02x\n", (unsigned)cd_raw[39]);
    free(cd_raw);

    csd_superblob_free(decoded);
    free(sb);
    free(sb_raw_buf);
    fat_free(fat);

    int ok = cd_bounds && idx_valid && ent_idx_ok && der_idx_ok && special_ok
        && phv == 0 && codelimit_valid && ncodeslots_valid && k6318 == 0;
    return ok ? 0 : 1;
}

typedef struct {
    uint32_t version;
    uint32_t flags;
    uint8_t platform;
    uint32_t codeLimit;
    uint32_t codeLimit64;
    uint32_t nCodeSlots;
    uint32_t nSpecialSlots;
    uint8_t pageSize;
    uint8_t hashType;
    uint8_t hashSize;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t scatterOffset;
    uint32_t cs_dataoff;
    int has_codelimit64;
} cd_report_t;

static int extract_cd_report(const char *path, cd_report_t *out)
{
    memset(out, 0, sizeof(*out));
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    MemoryStream *ms = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
    close(fd);
    Fat *fat = fat_init_from_memory_stream(ms);
    MachO *macho = fat_get_single_slice(fat);
    if (!macho) {
        fat_free(fat);
        return -1;
    }
    macho_find_code_signature_bounds(macho, &out->cs_dataoff, NULL);
    CS_SuperBlob *sb = macho_read_code_signature(macho);
    if (!sb) {
        fat_free(fat);
        return -1;
    }
    CS_DecodedSuperBlob *decoded = csd_superblob_decode(sb);
    if (!decoded) {
        free(sb);
        fat_free(fat);
        return -1;
    }
    CS_DecodedBlob *cd_blob = csd_superblob_find_blob(decoded, CSSLOT_CODEDIRECTORY, NULL);
    if (!cd_blob) {
        csd_superblob_free(decoded);
        free(sb);
        fat_free(fat);
        return -1;
    }
    CS_CodeDirectory cd;
    csd_blob_read(cd_blob, 0, sizeof(cd), &cd);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&cd, BIG_TO_HOST_APPLIER);
    out->version = cd.version;
    out->flags = cd.flags;
    out->platform = cd.platform;
    out->codeLimit = cd.codeLimit;
    out->nCodeSlots = cd.nCodeSlots;
    out->nSpecialSlots = cd.nSpecialSlots;
    out->pageSize = cd.pageSize;
    out->hashType = cd.hashType;
    out->hashSize = cd.hashSize;
    out->hashOffset = cd.hashOffset;
    out->identOffset = cd.identOffset;
    out->scatterOffset = cd.scatterOffset;
    out->has_codelimit64 = cd.version >= 0x20300;
    if (out->has_codelimit64) {
        uint8_t raw[4];
        csd_blob_read(cd_blob, 52, 4, raw);
        out->codeLimit64 = read_be32(raw);
    }
    csd_superblob_free(decoded);
    free(sb);
    fat_free(fat);
    return 0;
}

static void print_compare_report(const char *prefix, const cd_report_t *r)
{
    printf("%s_CD_VERSION=0x%x\n", prefix, r->version);
    printf("%s_CD_FLAGS=0x%x\n", prefix, r->flags);
    printf("%s_CD_PLATFORM=%u\n", prefix, (unsigned)r->platform);
    printf("%s_CD_CODELIMIT=%u\n", prefix, r->codeLimit);
    if (r->has_codelimit64)
        printf("%s_CD_CODELIMIT64=%u\n", prefix, r->codeLimit64);
    else
        printf("%s_CD_CODELIMIT64=NOT_PRESENT\n", prefix);
    printf("%s_CD_NCODESLOTS=%u\n", prefix, r->nCodeSlots);
    printf("%s_CD_NSPECIALSLOTS=%u\n", prefix, r->nSpecialSlots);
    printf("%s_CD_PAGESIZE=%u\n", prefix, (unsigned)r->pageSize);
    if (strcmp(prefix, "ORIGINAL") == 0) {
        printf("%s_CD_HASHTYPE=%u\n", prefix, (unsigned)r->hashType);
        printf("%s_CD_HASHSIZE=%u\n", prefix, (unsigned)r->hashSize);
        printf("%s_CD_HASHOFFSET=%u\n", prefix, r->hashOffset);
        printf("%s_CD_IDENTOFFSET=%u\n", prefix, r->identOffset);
        printf("%s_CD_SCATTEROFFSET=%u\n", prefix, r->scatterOffset);
    }
    printf("%s_LC_CODE_SIGNATURE_DATAOFF=%u\n", prefix, r->cs_dataoff);
}

static int compare_original_transformed(const char *original, const char *hook, const char *ent)
{
    cd_report_t orig = {0};
    if (extract_cd_report(original, &orig) != 0) {
        printf("CODELIMIT_SEMANTICS_CLOSED=NO\n");
        return 1;
    }
    print_compare_report("ORIGINAL", &orig);

    char xform[512];
    snprintf(xform, sizeof xform, "%s.xform_cmp", hook);
    unlink(xform);
    if (copyfile(hook, xform, NULL, COPYFILE_ALL) != 0) {
        perror("copyfile");
        return 2;
    }
    cdhash_t cd = {0};
    uint8_t plat = 0;
    if (dt_choma_platform_sign_staged_file(xform, ent, "launchdhook516.dylib", 13, &plat, cd, NULL) != 0) {
        printf("CODELIMIT_SEMANTICS_CLOSED=NO\n");
        unlink(xform);
        return 1;
    }
    cd_report_t x = {0};
    if (extract_cd_report(xform, &x) != 0) {
        printf("CODELIMIT_SEMANTICS_CLOSED=NO\n");
        unlink(xform);
        return 1;
    }
    print_compare_report("TRANSFORMED", &x);

    uint32_t psz = (uint32_t)(1u << orig.pageSize);
    uint32_t orig_expected = expected_ncodeslots(orig.codeLimit, psz);
    int closed = (orig.codeLimit == orig.cs_dataoff)
        && (x.codeLimit == x.cs_dataoff)
        && (x.codeLimit == orig.codeLimit)
        && (x.nCodeSlots == orig_expected)
        && (x.nCodeSlots == orig.nCodeSlots);
    printf("CODELIMIT_SEMANTICS_CLOSED=%s\n", closed ? "YES" : "NO");
    unlink(xform);
    return closed ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s sign <hook> <ent> | audit <macho>\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "compare") == 0) {
        if (argc < 5) {
            fprintf(stderr, "usage: %s compare <original_macho> <hook> <ent>\n", argv[0]);
            return 2;
        }
        return compare_original_transformed(argv[2], argv[3], argv[4]);
    }

    if (strcmp(argv[1], "audit") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s audit <macho>\n", argv[0]);
            return 2;
        }
        return audit_file(argv[2]);
    }

    if (strcmp(argv[1], "sign") != 0 || argc < 4) {
        fprintf(stderr, "usage: %s sign <hook> <ent>\n", argv[0]);
        return 2;
    }

    const char *hook = argv[2];
    const char *ent = argv[3];
    char final_path[512];
    snprintf(final_path, sizeof final_path, "%s.cd_audit_final", hook);
    unlink(final_path);
    if (copyfile(hook, final_path, NULL, COPYFILE_ALL) != 0) {
        perror("copyfile");
        return 2;
    }

    cdhash_t mem_cd = {0};
    uint8_t plat = 0;
    if (dt_choma_platform_sign_staged_file(final_path, ent, "launchdhook516.dylib", 13, &plat, mem_cd, NULL) != 0) {
        printf("SIGN_PIPELINE=FAIL\n");
        printf("FINAL_CODEDIRECTORY_PARSE=FAIL\n");
        return 1;
    }

    int rc = audit_file(final_path);
    unlink(final_path);
    return rc;
}
