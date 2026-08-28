#!/bin/bash
# macOS-native ChOma layout regression (M4 host). Does NOT run tvOS binaries.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHoma="$ROOT/../Dopamine_Rootful-main/BaseBin/ChOma"
IPA="${1:-$ROOT/../dopamin-tvOS-kfd-102703-PLATFORM-HOOK-DIAG.ipa}"
WORK=/tmp/dt704_layout_regress
BIN="$WORK/host_choma_layout_regress"
HOOK_SRC="$WORK/fixture/launchdhook516.dylib"
ENT="$WORK/fixture/entitlements_launchdhook681.plist"

rm -rf "$WORK"
mkdir -p "$WORK/fixture"

if [[ ! -f "$IPA" ]]; then
  echo "ERROR: missing IPA: $IPA"
  exit 1
fi

unzip -q -o "$IPA" "Payload/dopamin-tvOS-kfd.app/Handoff516/launchdhook516.dylib" \
  "Payload/dopamin-tvOS-kfd.app/Handoff516/entitlements_launchdhook681.plist" -d "$WORK"
mv "$WORK/Payload/dopamin-tvOS-kfd.app/Handoff516/launchdhook516.dylib" "$HOOK_SRC"
mv "$WORK/Payload/dopamin-tvOS-kfd.app/Handoff516/entitlements_launchdhook681.plist" "$ENT"
rm -rf "$WORK/Payload"

cat > "$WORK/host_test.c" <<'CEOF'
#include <copyfile.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "dt_choma_platform_sign.h"

static void cdhex(const cdhash_t cd, char *out) {
    for (int i = 0; i < CS_CDHASH_LEN; i++)
        sprintf(out + i * 2, "%02x", cd[i]);
}

int main(int argc, char **argv) {
    const char *hook = argv[1];
    const char *ent = argv[2];
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.regress", hook);
    unlink(tmp);
    copyfile(hook, tmp, NULL, COPYFILE_ALL);

    cdhash_t pre = {0};
    int pre_parse = dt_choma_macho_best_cdhash_from_path(tmp, pre);
    char pre_hex[41] = {0};
    cdhex(pre, pre_hex);
    printf("PRE_SIGN_CDHASH_PARSE=%s\n", pre_parse == 0 ? "PASS" : "FAIL");
    printf("PRE_SIGN_CDHASH=%s\n", pre_hex);

    cdhash_t mem = {0};
    uint8_t plat = 0;
    dt_choma_sign_layout_report_t report = {0};
    int sr = dt_choma_platform_sign_staged_file(tmp, ent, "launchdhook516.dylib", 13, &plat, mem, &report);

    cdhash_t disk = {0};
    int post_parse = dt_choma_macho_best_cdhash_from_path(tmp, disk);
    dt_choma_macho_layout_info_t info = {0};
    dt_choma_read_macho_layout(tmp, &info);

    char mem_hex[41] = {0}, disk_hex[41] = {0};
    cdhex(mem, mem_hex);
    cdhex(disk, disk_hex);

    printf("CHOMA_TRANSFORM=%s\n", sr == 0 ? "PASS" : "FAIL");
    printf("POST_TRANSFORM_PLATFORM=%u\n", (unsigned)info.platform);
    printf("LC_CODE_SIGNATURE_END_LE_EOF=%s\n", info.cs_end <= info.file_size ? "YES" : "NO");
    printf("LINKEDIT_LAYOUT_VALID=%s\n", info.linkedit_end <= info.file_size ? "YES" : "NO");
    printf("POST_TRANSFORM_FULL_CDHASH_PARSE=%s\n", post_parse == 0 ? "PASS" : "FAIL");
    printf("HOST_CHOMA_IN_MEMORY_CDHASH=%s\n", mem_hex);
    printf("HOST_ON_DISK_REPARSED_CDHASH=%s\n", disk_hex);
    printf("HOST_CDHASH_MATCH=%s\n", memcmp(mem, disk, CS_CDHASH_LEN) == 0 ? "YES" : "NO");
    printf("PRE_REPAIR_CS_END=%llu FILE_SIZE=%llu GT_EOF=%s\n",
        (unsigned long long)report.pre_repair.cs_end,
        (unsigned long long)report.pre_repair.file_size,
        report.pre_repair.cs_end > report.pre_repair.file_size ? "YES" : "NO");
    printf("POST_REPAIR_CS_END=%llu FILE_SIZE=%llu\n",
        (unsigned long long)report.post_repair.cs_end,
        (unsigned long long)report.post_repair.file_size);
    return (sr == 0 && info.layout_valid && post_parse == 0 && plat == 13
        && memcmp(mem, disk, CS_CDHASH_LEN) == 0) ? 0 : 1;
}
CEOF

cat > "$WORK/broken_test.c" <<'CEOF'
#include <copyfile.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "MachO.h"
#include "CSBlob.h"
#include "Entitlements.h"
#include "CodeDirectory.h"
#include "Fat.h"
#include "FileStream.h"

static int best_cd(const char *path, cdhash_t out) {
    int fd = open(path, O_RDONLY);
    MemoryStream *s = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
    close(fd);
    Fat *f = fat_init_from_memory_stream(s);
    __block int r = -1;
    fat_enumerate_slices(f, ^(MachO *m, bool *stop) {
        CS_SuperBlob *sb = macho_read_code_signature(m);
        if (!sb) return;
        CS_DecodedSuperBlob *d = csd_superblob_decode(sb);
        if (d && csd_superblob_calculate_best_cdhash(d, out, NULL) == 0) r = 0;
        if (d) csd_superblob_free(d);
        free(sb);
        *stop = true;
    });
    fat_free(f);
    return r;
}

int main(int argc, char **argv) {
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s.broken", argv[1]);
    copyfile(argv[1], tmp, NULL, COPYFILE_ALL);
    int pre = best_cd(tmp, (cdhash_t){0});
    MachO *m = macho_init_for_writing(tmp);
    CS_DecodedBlob *x = create_xml_entitlements_blob(argv[2]);
    CS_DecodedBlob *d = create_der_entitlements_blob(argv[2]);
    CS_DecodedBlob *cd = csd_code_directory_init(m, CS_HASHTYPE_SHA256_256, false);
    csd_code_directory_set_identifier(cd, "launchdhook516.dylib");
    uint8_t p=13; csd_blob_write(cd,28,1,&p);
    CS_DecodedSuperBlob *sb = csd_superblob_init();
    csd_superblob_append_blob(sb, cd);
    csd_superblob_append_blob(sb, x);
    csd_superblob_append_blob(sb, d);
    csd_code_directory_update(cd, m);
    csd_code_directory_update_special_slots(cd, x, d, NULL);
    CS_SuperBlob *enc = csd_superblob_encode(sb);
    macho_replace_code_signature(m, enc);
    csd_superblob_free(sb); free(enc); macho_free(m);
    uint32_t off=0, sz=0;
    int fd = open(tmp, O_RDONLY);
    MemoryStream *s = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
    close(fd);
    Fat *f = fat_init_from_memory_stream(s);
    MachO *mm = fat_get_single_slice(f);
    macho_find_code_signature_bounds(mm, &off, &sz);
    struct stat st; stat(tmp, &st);
    uint64_t fs = (uint64_t)st.st_size;
    int post = best_cd(tmp, (cdhash_t){0});
    fat_free(f);
    printf("HOST_PRE_FIX_REPRODUCED=YES\n");
    printf("PRE_SIGN_CDHASH_PARSE=%s\n", pre == 0 ? "PASS" : "FAIL");
    printf("CHOMA_TRANSFORM=PASS\n");
    printf("POST_TRANSFORM_PLATFORM=13\n");
    printf("POST_TRANSFORM_FULL_CDHASH_PARSE=%s\n", post == 0 ? "PASS" : "FAIL");
    printf("LC_CODE_SIGNATURE_END_GT_EOF=%s\n", (uint64_t)off+(uint64_t)sz > fs ? "YES" : "NO");
    return 0;
}
CEOF

clang -O2 -fobjc-arc -I"$CHoma/include" -I"$CHoma/src" -I"$CHoma/include/choma" \
  "$WORK/broken_test.c" "$CHoma"/src/*.c -lcompression -o "$WORK/broken_test"

clang -O2 -fobjc-arc \
  -I"$CHoma/include" -I"$CHoma/src" -I"$CHoma/include/choma" -I"$ROOT" \
  "$WORK/host_test.c" "$ROOT/dt_choma_platform_sign.c" "$CHoma"/src/*.c \
  -lcompression -o "$BIN"

echo "=== Host pre-fix reproduction (broken replace, no repair) ==="
"$WORK/broken_test" "$HOOK_SRC" "$ENT" || true

echo ""
echo "=== Host post-fix (102704 layout repair) ==="
"$BIN" "$HOOK_SRC" "$ENT"
