/*
 * dt_sign_platform_hook — adhoc Mach-O sign with CodeDirectory.platform != 0
 * Uses ChOma (same library as basebin). Host macOS build only.
 *
 * Verified: CS_CodeDirectory.platform @ byte offset 28 (see CodeDirectory.h).
 * Procursus ldid -P documents default platform id 13 for Apple platform binaries.
 */
#include "Fat.h"
#include "MachO.h"
#include "Host.h"
#include "CSBlob.h"
#include "Entitlements.h"
#include "CodeDirectory.h"

#include <copyfile.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s -i INPUT -o OUTPUT -e ENTITLEMENTS.plist [-I IDENTIFIER] [-p PLATFORM_ID]\n"
        "  PLATFORM_ID defaults to 13 (nonzero marks platform binary in CodeDirectory)\n",
        argv0);
    exit(2);
}

static int sign_platform_hook(const char *inPath, const char *outPath,
    const char *entitlementsPath, const char *identifier, uint8_t platformId)
{
    if (access(inPath, R_OK) != 0) {
        perror(inPath);
        return 1;
    }

    if (copyfile(inPath, outPath, NULL, COPYFILE_ALL) != 0) {
        perror("copyfile");
        return 1;
    }
    chmod(outPath, 0755);

    MachO *macho = macho_init_for_writing(outPath);
    if (!macho) {
        fprintf(stderr, "macho_init_for_writing failed\n");
        return 1;
    }

    CS_DecodedBlob *xmlEntitlements = NULL;
    CS_DecodedBlob *derEntitlements = NULL;
    if (entitlementsPath) {
        xmlEntitlements = create_xml_entitlements_blob(entitlementsPath);
        derEntitlements = create_der_entitlements_blob(entitlementsPath);
        if (!xmlEntitlements || !derEntitlements) {
            fprintf(stderr, "entitlements blob generation failed\n");
            macho_free(macho);
            return 1;
        }
    }

    CS_DecodedBlob *codeDir = csd_code_directory_init(macho, CS_HASHTYPE_SHA256_256, false);
    if (!codeDir) {
        fprintf(stderr, "csd_code_directory_init failed\n");
        macho_free(macho);
        return 1;
    }

    if (identifier && csd_code_directory_set_identifier(codeDir, (char *)identifier) != 0) {
        fprintf(stderr, "csd_code_directory_set_identifier failed\n");
        macho_free(macho);
        return 1;
    }

    /* CS_CodeDirectory.platform @ offset 28 — nonzero => platform Mach-O */
    if (csd_blob_write(codeDir, 28, 1, &platformId) != 0) {
        fprintf(stderr, "csd_blob_write platform failed\n");
        macho_free(macho);
        return 1;
    }

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_init();
    csd_superblob_append_blob(decodedSuperblob, codeDir);
    if (xmlEntitlements)
        csd_superblob_append_blob(decodedSuperblob, xmlEntitlements);
    if (derEntitlements)
        csd_superblob_append_blob(decodedSuperblob, derEntitlements);

    csd_code_directory_update(codeDir, macho);
    csd_code_directory_update_special_slots(codeDir, xmlEntitlements, derEntitlements, NULL);

    CS_SuperBlob *encoded = csd_superblob_encode(decodedSuperblob);
    if (!encoded) {
        fprintf(stderr, "csd_superblob_encode failed\n");
        macho_free(macho);
        return 1;
    }

    if (macho_replace_code_signature(macho, encoded) != 0) {
        fprintf(stderr, "macho_replace_code_signature failed\n");
        free(encoded);
        macho_free(macho);
        return 1;
    }

    cdhash_t cdhash = {0};
    if (csd_superblob_calculate_best_cdhash(decodedSuperblob, cdhash, NULL) == 0) {
        printf("PLATFORM_HOOK_CDHASH=");
        for (int i = 0; i < CS_CDHASH_LEN; i++)
            printf("%02x", cdhash[i]);
        printf("\n");
    }

    uint8_t verifyPlatform = 0;
    csd_blob_read(codeDir, 28, 1, &verifyPlatform);
    printf("CODEDIRECTORY_PLATFORM_BYTE=%u\n", (unsigned)verifyPlatform);

    csd_superblob_free(decodedSuperblob);
    free(encoded);
    macho_free(macho);
    return 0;
}

int main(int argc, char **argv)
{
    const char *inPath = NULL;
    const char *outPath = NULL;
    const char *entPath = NULL;
    const char *identifier = "launchdhook516.dylib";
    uint8_t platformId = 13;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc)
            inPath = argv[++i];
        else if (!strcmp(argv[i], "-o") && i + 1 < argc)
            outPath = argv[++i];
        else if (!strcmp(argv[i], "-e") && i + 1 < argc)
            entPath = argv[++i];
        else if (!strcmp(argv[i], "-I") && i + 1 < argc)
            identifier = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc)
            platformId = (uint8_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "-h"))
            usage(argv[0]);
        else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            usage(argv[0]);
        }
    }

    if (!inPath || !outPath || !entPath)
        usage(argv[0]);

    return sign_platform_hook(inPath, outPath, entPath, identifier, platformId) != 0 ? 1 : 0;
}
