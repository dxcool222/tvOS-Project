#include "dt_macho_canonical_id.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    DT_MH_MAGIC_64 = 0xFEEDFACFu,
    DT_LC_SYMTAB = 0x02u,
    DT_LC_DYSYMTAB = 0x0Bu,
    DT_LC_TWOLEVEL_HINTS = 0x16u,
    DT_LC_SEGMENT_64 = 0x19u,
    DT_LC_UUID = 0x1Bu,
    DT_LC_CODE_SIGNATURE = 0x1Du,
    DT_LC_SEGMENT_SPLIT_INFO = 0x1Eu,
    DT_LC_DYLD_INFO = 0x22u,
    DT_LC_DYLD_INFO_ONLY = 0x80000022u,
    DT_LC_FUNCTION_STARTS = 0x26u,
    DT_LC_DATA_IN_CODE = 0x29u,
    DT_LC_DYLIB_CODE_SIGN_DRS = 0x2Bu,
    DT_LC_ENCRYPTION_INFO_64 = 0x2Cu,
    DT_LC_LINKER_OPTIMIZATION_HINT = 0x2Eu,
    DT_LC_NOTE = 0x31u,
    DT_LC_DYLD_EXPORTS_TRIE = 0x80000033u,
    DT_LC_DYLD_CHAINED_FIXUPS = 0x80000034u,
};

enum {
    DT_S_ZEROFILL = 0x1u,
    DT_S_GB_ZEROFILL = 0xCu,
    DT_S_THREAD_LOCAL_ZEROFILL = 0x12u,
};

static uint32_t dt_rd_u32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint64_t dt_rd_u64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static void dt_wr_u32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

static void dt_wr_u64(uint8_t *p, uint64_t v)
{
    memcpy(p, &v, 8);
}

static int dt_read_file(const char *path, uint8_t **out_buf, size_t *out_len)
{
    if (!path || !out_buf || !out_len)
        return EINVAL;
    *out_buf = NULL;
    *out_len = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return errno > 0 ? errno : EIO;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int e = errno > 0 ? errno : EIO;
        close(fd);
        return e;
    }
    if (st.st_size <= 0 || st.st_size > (off_t)(64u * 1024u * 1024u)) {
        close(fd);
        return EFBIG;
    }
    size_t n = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(n);
    if (!buf) {
        close(fd);
        return ENOMEM;
    }
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0) {
            int e = errno > 0 ? errno : EIO;
            free(buf);
            close(fd);
            return e;
        }
        if (r == 0)
            break;
        got += (size_t)r;
    }
    close(fd);
    if (got != n) {
        free(buf);
        return EIO;
    }
    *out_buf = buf;
    *out_len = n;
    return 0;
}

static int dt_hex64(const uint8_t digest[CC_SHA256_DIGEST_LENGTH], char *out, size_t out_sz)
{
    if (!out || out_sz < 65)
        return EINVAL;
    static const char *hexd = "0123456789abcdef";
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        out[i * 2] = hexd[(digest[i] >> 4) & 0xf];
        out[i * 2 + 1] = hexd[digest[i] & 0xf];
    }
    out[64] = '\0';
    return 0;
}

int dt_macho_canonical_sha256_hex(const char *path, char *out_hex, size_t out_hex_sz)
{
    uint8_t *data = NULL;
    size_t len = 0;
    int rc = dt_read_file(path, &data, &len);
    if (rc != 0)
        return rc;
    if (len < 32 || dt_rd_u32(data) != DT_MH_MAGIC_64) {
        free(data);
        return ENOEXEC;
    }
    uint32_t ncmds = dt_rd_u32(data + 16);
    uint32_t sizeofcmds = dt_rd_u32(data + 20);
    if ((size_t)32 + sizeofcmds > len) {
        free(data);
        return ENOEXEC;
    }

    size_t off = 32;
    size_t end = 32 + sizeofcmds;
    size_t le_cmd = 0;
    size_t cs_cmd = 0;
    uint32_t cs_off = 0;
    uint32_t cs_sz = 0;
    int have_le = 0;
    int have_cs = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + 8 > end) {
            free(data);
            return ENOEXEC;
        }
        uint32_t cmd = dt_rd_u32(data + off);
        uint32_t cmdsize = dt_rd_u32(data + off + 4);
        if (cmdsize < 8 || off + cmdsize > end) {
            free(data);
            return ENOEXEC;
        }
        if (cmd == DT_LC_SEGMENT_64) {
            if (cmdsize < 72) {
                free(data);
                return ENOEXEC;
            }
            char name[17];
            memcpy(name, data + off + 8, 16);
            name[16] = '\0';
            if (strcmp(name, "__LINKEDIT") == 0) {
                le_cmd = off;
                have_le = 1;
            }
        } else if (cmd == DT_LC_CODE_SIGNATURE) {
            if (cmdsize < 16) {
                free(data);
                return ENOEXEC;
            }
            cs_off = dt_rd_u32(data + off + 8);
            cs_sz = dt_rd_u32(data + off + 12);
            cs_cmd = off;
            have_cs = 1;
        }
        off += cmdsize;
    }

    if (!have_le || !have_cs) {
        free(data);
        return ENOEXEC;
    }
    if (cs_off < 32 + sizeofcmds || (size_t)cs_off > len) {
        free(data);
        return ENOEXEC;
    }
    if ((size_t)cs_sz > len - cs_off) {
        free(data);
        return ENOEXEC;
    }
    uint64_t le_fileoff = dt_rd_u64(data + le_cmd + 40);
    if (le_fileoff > cs_off) {
        free(data);
        return ENOEXEC;
    }
    uint64_t filesize_norm = (uint64_t)cs_off - le_fileoff;

    /* Normalize signing-mutated metadata in the pre-CS prefix, then hash. */
    uint8_t *prefix = (uint8_t *)malloc(cs_off);
    if (!prefix) {
        free(data);
        return ENOMEM;
    }
    memcpy(prefix, data, cs_off);
    free(data);
    data = NULL;

    dt_wr_u64(prefix + le_cmd + 32, filesize_norm); /* vmsize */
    dt_wr_u64(prefix + le_cmd + 48, filesize_norm); /* filesize */
    dt_wr_u32(prefix + cs_cmd + 12, 0);              /* datasize */

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(prefix, (CC_LONG)cs_off, digest);
    free(prefix);
    return dt_hex64(digest, out_hex, out_hex_sz);
}

int dt_macho_raw_sha256_hex(const char *path, char *out_hex, size_t out_hex_sz)
{
    uint8_t *data = NULL;
    size_t len = 0;
    int rc = dt_read_file(path, &data, &len);
    if (rc != 0)
        return rc;
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, (CC_LONG)len, digest);
    free(data);
    return dt_hex64(digest, out_hex, out_hex_sz);
}

int dt_macho_cs_end_valid(const char *path)
{
    uint8_t *data = NULL;
    size_t len = 0;
    int rc = dt_read_file(path, &data, &len);
    if (rc != 0)
        return rc;
    if (len < 32 || dt_rd_u32(data) != DT_MH_MAGIC_64) {
        free(data);
        return ENOEXEC;
    }
    uint32_t ncmds = dt_rd_u32(data + 16);
    uint32_t sizeofcmds = dt_rd_u32(data + 20);
    if ((size_t)32 + sizeofcmds > len) {
        free(data);
        return ENOEXEC;
    }
    size_t off = 32;
    size_t end = 32 + sizeofcmds;
    uint32_t cs_off = 0;
    uint32_t cs_sz = 0;
    int have_cs = 0;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + 8 > end) {
            free(data);
            return ENOEXEC;
        }
        uint32_t cmd = dt_rd_u32(data + off);
        uint32_t cmdsize = dt_rd_u32(data + off + 4);
        if (cmdsize < 8 || off + cmdsize > end) {
            free(data);
            return ENOEXEC;
        }
        if (cmd == DT_LC_CODE_SIGNATURE) {
            if (cmdsize < 16) {
                free(data);
                return ENOEXEC;
            }
            cs_off = dt_rd_u32(data + off + 8);
            cs_sz = dt_rd_u32(data + off + 12);
            have_cs = 1;
        }
        off += cmdsize;
    }
    free(data);
    if (!have_cs)
        return ENOEXEC;
    if ((size_t)cs_off + cs_sz != len)
        return EINVAL;
    return 0;
}

static int dt_u64_range_end(uint64_t off, uint64_t count, uint64_t width,
                            uint64_t limit, uint64_t *end_out)
{
    if (width != 0 && count > UINT64_MAX / width)
        return ERANGE;
    uint64_t size = count * width;
    if (off > UINT64_MAX - size)
        return ERANGE;
    uint64_t end = off + size;
    if (end > limit)
        return ERANGE;
    if (end_out)
        *end_out = end;
    return 0;
}

static int dt_track_non_signature_range(uint64_t off, uint64_t count,
                                        uint64_t width, uint64_t file_len,
                                        uint64_t *max_end)
{
    if (count == 0)
        return 0;
    uint64_t end = 0;
    int rc = dt_u64_range_end(off, count, width, file_len, &end);
    if (rc != 0)
        return rc;
    if (end > *max_end)
        *max_end = end;
    return 0;
}

int dt_macho_runtime_layout_validate(const char *path,
                                     uint32_t expected_ncmds,
                                     uint32_t expected_cs_off,
                                     uint64_t expected_max_non_signature_end,
                                     uint64_t expected_jbinfo_size,
                                     dt_macho_runtime_layout_t *out_layout)
{
    if (!out_layout)
        return EINVAL;
    memset(out_layout, 0, sizeof(*out_layout));

    uint8_t *data = NULL;
    size_t len = 0;
    int rc = dt_read_file(path, &data, &len);
    if (rc != 0)
        return rc;
    if (len < 32 || dt_rd_u32(data) != DT_MH_MAGIC_64) {
        free(data);
        return DT_MACHO_RUNTIME_LAYOUT_HEADER;
    }

    uint32_t ncmds = dt_rd_u32(data + 16);
    uint32_t sizeofcmds = dt_rd_u32(data + 20);
    if (ncmds != expected_ncmds || (size_t)32 + sizeofcmds > len) {
        free(data);
        return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
    }

    size_t off = 32;
    size_t command_end = 32 + sizeofcmds;
    uint32_t cs_count = 0;
    uint32_t uuid_count = 0;
    uint32_t linkedit_count = 0;
    uint32_t jbinfo_count = 0;
    uint32_t symtab_count = 0;
    uint32_t dysymtab_count = 0;
    uint32_t cs_off = 0;
    uint32_t cs_size = 0;
    uint64_t linkedit_fileoff = 0;
    uint64_t linkedit_end = 0;
    uint64_t jbinfo_fileoff = 0;
    uint64_t jbinfo_size = 0;
    uint64_t max_non_signature_end = 0;
    uint32_t symtab_nsyms = 0;
    uint32_t dysym_ilocalsym = 0, dysym_nlocalsym = 0;
    uint32_t dysym_iextdefsym = 0, dysym_nextdefsym = 0;
    uint32_t dysym_iundefsym = 0, dysym_nundefsym = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + 8 > command_end) {
            free(data);
            return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
        }
        uint32_t cmd = dt_rd_u32(data + off);
        uint32_t cmdsize = dt_rd_u32(data + off + 4);
        if (cmdsize < 8 || off + cmdsize > command_end) {
            free(data);
            return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
        }

        if (cmd == DT_LC_SEGMENT_64) {
            if (cmdsize < 72) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            uint32_t nsects = dt_rd_u32(data + off + 64);
            if ((uint64_t)nsects > (UINT64_MAX - 72) / 80
                || (uint64_t)72 + (uint64_t)nsects * 80 != cmdsize) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            char segname[17];
            memcpy(segname, data + off + 8, 16);
            segname[16] = '\0';
            uint64_t seg_fileoff = dt_rd_u64(data + off + 40);
            uint64_t seg_filesize = dt_rd_u64(data + off + 48);
            uint64_t seg_end = 0;
            if (dt_u64_range_end(seg_fileoff, 1, seg_filesize, len, &seg_end) != 0) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
            }
            int is_linkedit = strcmp(segname, "__LINKEDIT") == 0;
            if (is_linkedit) {
                linkedit_count++;
                linkedit_fileoff = seg_fileoff;
                linkedit_end = seg_end;
            } else if (seg_filesize != 0 && seg_end > max_non_signature_end) {
                max_non_signature_end = seg_end;
            }

            size_t section_off = off + 72;
            for (uint32_t s = 0; s < nsects; s++, section_off += 80) {
                uint64_t section_size = dt_rd_u64(data + section_off + 40);
                uint32_t section_fileoff = dt_rd_u32(data + section_off + 48);
                uint32_t reloff = dt_rd_u32(data + section_off + 56);
                uint32_t nreloc = dt_rd_u32(data + section_off + 60);
                uint32_t section_type = dt_rd_u32(data + section_off + 64) & 0xffu;
                int zero_fill = section_type == DT_S_ZEROFILL
                    || section_type == DT_S_GB_ZEROFILL
                    || section_type == DT_S_THREAD_LOCAL_ZEROFILL;
                if (!zero_fill && section_size != 0) {
                    uint64_t section_end = 0;
                    if (dt_u64_range_end(section_fileoff, 1, section_size, len,
                                         &section_end) != 0
                        || section_fileoff < seg_fileoff || section_end > seg_end) {
                        free(data);
                        return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
                    }
                    if (section_end > max_non_signature_end)
                        max_non_signature_end = section_end;
                }
                if (dt_track_non_signature_range(reloff, nreloc, 8, len,
                                                 &max_non_signature_end) != 0) {
                    free(data);
                    return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
                }

                char section_name[17];
                char section_segname[17];
                memcpy(section_name, data + section_off, 16);
                memcpy(section_segname, data + section_off + 16, 16);
                section_name[16] = '\0';
                section_segname[16] = '\0';
                if (strcmp(section_segname, "__DATA") == 0
                    && strcmp(section_name, "__jbinfo") == 0) {
                    jbinfo_count++;
                    jbinfo_fileoff = section_fileoff;
                    jbinfo_size = section_size;
                }
            }
        } else if (cmd == DT_LC_CODE_SIGNATURE) {
            if (cmdsize != 16) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            cs_count++;
            cs_off = dt_rd_u32(data + off + 8);
            cs_size = dt_rd_u32(data + off + 12);
        } else if (cmd == DT_LC_UUID) {
            if (cmdsize != 24) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            uuid_count++;
        } else if (cmd == DT_LC_SYMTAB) {
            if (cmdsize != 24) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            symtab_count++;
            uint32_t symoff = dt_rd_u32(data + off + 8);
            symtab_nsyms = dt_rd_u32(data + off + 12);
            uint32_t stroff = dt_rd_u32(data + off + 16);
            uint32_t strsize = dt_rd_u32(data + off + 20);
            if (dt_track_non_signature_range(symoff, symtab_nsyms, 16, len,
                                             &max_non_signature_end) != 0
                || dt_track_non_signature_range(stroff, strsize, 1, len,
                                                &max_non_signature_end) != 0) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
            }
        } else if (cmd == DT_LC_DYSYMTAB) {
            if (cmdsize != 80) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            dysymtab_count++;
            dysym_ilocalsym = dt_rd_u32(data + off + 8);
            dysym_nlocalsym = dt_rd_u32(data + off + 12);
            dysym_iextdefsym = dt_rd_u32(data + off + 16);
            dysym_nextdefsym = dt_rd_u32(data + off + 20);
            dysym_iundefsym = dt_rd_u32(data + off + 24);
            dysym_nundefsym = dt_rd_u32(data + off + 28);
            const uint32_t offsets[] = {
                dt_rd_u32(data + off + 32), dt_rd_u32(data + off + 40),
                dt_rd_u32(data + off + 48), dt_rd_u32(data + off + 56),
                dt_rd_u32(data + off + 64), dt_rd_u32(data + off + 72),
            };
            const uint32_t counts[] = {
                dt_rd_u32(data + off + 36), dt_rd_u32(data + off + 44),
                dt_rd_u32(data + off + 52), dt_rd_u32(data + off + 60),
                dt_rd_u32(data + off + 68), dt_rd_u32(data + off + 76),
            };
            const uint32_t widths[] = { 8, 56, 4, 4, 8, 8 };
            for (size_t j = 0; j < 6; j++) {
                if (dt_track_non_signature_range(offsets[j], counts[j], widths[j],
                                                 len, &max_non_signature_end) != 0) {
                    free(data);
                    return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
                }
            }
        } else if (cmd == DT_LC_DYLD_INFO || cmd == DT_LC_DYLD_INFO_ONLY) {
            if (cmdsize != 48) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            for (size_t j = 0; j < 5; j++) {
                uint32_t dataoff = dt_rd_u32(data + off + 8 + j * 8);
                uint32_t datasize = dt_rd_u32(data + off + 12 + j * 8);
                if (dt_track_non_signature_range(dataoff, datasize, 1, len,
                                                 &max_non_signature_end) != 0) {
                    free(data);
                    return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
                }
            }
        } else if (cmd == DT_LC_SEGMENT_SPLIT_INFO
                   || cmd == DT_LC_FUNCTION_STARTS
                   || cmd == DT_LC_DATA_IN_CODE
                   || cmd == DT_LC_DYLIB_CODE_SIGN_DRS
                   || cmd == DT_LC_LINKER_OPTIMIZATION_HINT
                   || cmd == DT_LC_DYLD_EXPORTS_TRIE
                   || cmd == DT_LC_DYLD_CHAINED_FIXUPS) {
            if (cmdsize != 16) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            uint32_t dataoff = dt_rd_u32(data + off + 8);
            uint32_t datasize = dt_rd_u32(data + off + 12);
            if (dt_track_non_signature_range(dataoff, datasize, 1, len,
                                             &max_non_signature_end) != 0) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
            }
        } else if (cmd == DT_LC_TWOLEVEL_HINTS) {
            if (cmdsize != 16) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            if (dt_track_non_signature_range(dt_rd_u32(data + off + 8),
                                             dt_rd_u32(data + off + 12), 4,
                                             len, &max_non_signature_end) != 0) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
            }
        } else if (cmd == DT_LC_ENCRYPTION_INFO_64) {
            if (cmdsize != 24) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            if (dt_track_non_signature_range(dt_rd_u32(data + off + 8),
                                             dt_rd_u32(data + off + 12), 1,
                                             len, &max_non_signature_end) != 0) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
            }
        } else if (cmd == DT_LC_NOTE) {
            if (cmdsize != 40) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
            }
            uint64_t note_off = dt_rd_u64(data + off + 24);
            uint64_t note_size = dt_rd_u64(data + off + 32);
            if (dt_track_non_signature_range(note_off, note_size, 1, len,
                                             &max_non_signature_end) != 0) {
                free(data);
                return DT_MACHO_RUNTIME_LAYOUT_FILE_RANGE;
            }
        }
        off += cmdsize;
    }

    if (off != command_end) {
        free(data);
        return DT_MACHO_RUNTIME_LAYOUT_COMMAND_TABLE;
    }
    if (cs_count != 1 || uuid_count != 1 || linkedit_count != 1
        || jbinfo_count != 1 || symtab_count != 1 || dysymtab_count != 1) {
        free(data);
        return DT_MACHO_RUNTIME_LAYOUT_CARDINALITY;
    }
    if (cs_off != expected_cs_off || cs_off < command_end
        || (size_t)cs_off > len || cs_size > len - cs_off) {
        free(data);
        return DT_MACHO_RUNTIME_LAYOUT_CS_BOUNDS;
    }
    if (linkedit_fileoff > cs_off || linkedit_end < (uint64_t)cs_off + cs_size) {
        free(data);
        return DT_MACHO_RUNTIME_LAYOUT_LINKEDIT_BOUNDS;
    }
    if (max_non_signature_end != expected_max_non_signature_end
        || max_non_signature_end > cs_off) {
        free(data);
        return DT_MACHO_RUNTIME_LAYOUT_NON_SIGNATURE_BOUNDARY;
    }
    if (jbinfo_size != expected_jbinfo_size || jbinfo_fileoff > cs_off
        || jbinfo_size > cs_off - jbinfo_fileoff) {
        free(data);
        return DT_MACHO_RUNTIME_LAYOUT_JBINFO_BOUNDS;
    }
    if ((uint64_t)dysym_ilocalsym + dysym_nlocalsym > symtab_nsyms
        || (uint64_t)dysym_iextdefsym + dysym_nextdefsym > symtab_nsyms
        || (uint64_t)dysym_iundefsym + dysym_nundefsym > symtab_nsyms) {
        free(data);
        return DT_MACHO_RUNTIME_LAYOUT_SYMBOL_BOUNDS;
    }

    uint64_t cs_end = (uint64_t)cs_off + cs_size;
    out_layout->file_size = len;
    out_layout->cs_end = cs_end;
    out_layout->trailer_size = len - cs_end;
    out_layout->max_non_signature_end = max_non_signature_end;
    out_layout->jbinfo_fileoff = jbinfo_fileoff;
    out_layout->jbinfo_size = jbinfo_size;
    out_layout->ncmds = ncmds;
    out_layout->sizeofcmds = sizeofcmds;
    out_layout->cs_off = cs_off;
    out_layout->cs_size = cs_size;
    free(data);
    return 0;
}

static int dt_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

int dt_macho_bytes_match_hex(const char *path, uint32_t offset, const char *expected_hex)
{
    if (!expected_hex)
        return EINVAL;
    size_t hex_len = strlen(expected_hex);
    if (hex_len == 0 || (hex_len % 2) != 0)
        return EINVAL;
    size_t need = hex_len / 2;
    uint8_t *data = NULL;
    size_t len = 0;
    int rc = dt_read_file(path, &data, &len);
    if (rc != 0)
        return rc;
    if ((size_t)offset + need > len) {
        free(data);
        return ERANGE;
    }
    for (size_t i = 0; i < need; i++) {
        int hi = dt_hex_nibble(expected_hex[i * 2]);
        int lo = dt_hex_nibble(expected_hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            free(data);
            return EINVAL;
        }
        if (data[offset + i] != (uint8_t)((hi << 4) | lo)) {
            free(data);
            return EDOM;
        }
    }
    free(data);
    return 0;
}

int dt_macho_jbinfo_section_valid(const char *path, uint64_t expected_size)
{
    uint8_t *data = NULL;
    size_t len = 0;
    int rc = dt_read_file(path, &data, &len);
    if (rc != 0)
        return rc;
    if (len < 32 || dt_rd_u32(data) != DT_MH_MAGIC_64) {
        free(data);
        return ENOEXEC;
    }
    uint32_t ncmds = dt_rd_u32(data + 16);
    uint32_t sizeofcmds = dt_rd_u32(data + 20);
    if ((size_t)32 + sizeofcmds > len) {
        free(data);
        return ENOEXEC;
    }
    size_t off = 32;
    size_t end = 32 + sizeofcmds;
    uint32_t cs_off = 0;
    int have_cs = 0;
    int have_jbinfo = 0;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + 8 > end) {
            free(data);
            return ENOEXEC;
        }
        uint32_t cmd = dt_rd_u32(data + off);
        uint32_t cmdsize = dt_rd_u32(data + off + 4);
        if (cmdsize < 8 || off + cmdsize > end) {
            free(data);
            return ENOEXEC;
        }
        if (cmd == DT_LC_SEGMENT_64 && cmdsize >= 72) {
            char seg[17];
            memcpy(seg, data + off + 8, 16);
            seg[16] = '\0';
            if (strcmp(seg, "__DATA") == 0) {
                uint32_t nsects = dt_rd_u32(data + off + 64);
                size_t so = off + 72;
                for (uint32_t s = 0; s < nsects; s++) {
                    if (so + 80 > end) {
                        free(data);
                        return ENOEXEC;
                    }
                    char sect[17];
                    memcpy(sect, data + so, 16);
                    sect[16] = '\0';
                    if (strcmp(sect, "__jbinfo") == 0) {
                        uint64_t size = dt_rd_u64(data + so + 40);
                        uint32_t fileoff = dt_rd_u32(data + so + 48);
                        if (size != expected_size) {
                            free(data);
                            return EDOM;
                        }
                        if ((size_t)fileoff + size > len) {
                            free(data);
                            return ERANGE;
                        }
                        have_jbinfo = 1;
                    }
                    so += 80;
                }
            }
        } else if (cmd == DT_LC_CODE_SIGNATURE && cmdsize >= 16) {
            cs_off = dt_rd_u32(data + off + 8);
            have_cs = 1;
        }
        off += cmdsize;
    }
    free(data);
    if (!have_cs || !have_jbinfo)
        return ENOENT;
    if (cs_off == 0)
        return ENOEXEC;
    return 0;
}

int dt_macho_uuid_string(const char *path, char *out, size_t out_sz)
{
    if (!out || out_sz < 37)
        return EINVAL;
    uint8_t *data = NULL;
    size_t len = 0;
    int rc = dt_read_file(path, &data, &len);
    if (rc != 0)
        return rc;
    if (len < 32 || dt_rd_u32(data) != DT_MH_MAGIC_64) {
        free(data);
        return ENOEXEC;
    }
    uint32_t ncmds = dt_rd_u32(data + 16);
    uint32_t sizeofcmds = dt_rd_u32(data + 20);
    if ((size_t)32 + sizeofcmds > len) {
        free(data);
        return ENOEXEC;
    }
    size_t off = 32;
    size_t end = 32 + sizeofcmds;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + 8 > end) {
            free(data);
            return ENOEXEC;
        }
        uint32_t cmd = dt_rd_u32(data + off);
        uint32_t cmdsize = dt_rd_u32(data + off + 4);
        if (cmdsize < 8 || off + cmdsize > end) {
            free(data);
            return ENOEXEC;
        }
        if (cmd == DT_LC_UUID) {
            if (cmdsize < 24) {
                free(data);
                return ENOEXEC;
            }
            const uint8_t *u = data + off + 8;
            snprintf(out, out_sz,
                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
                u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
            free(data);
            return 0;
        }
        off += cmdsize;
    }
    free(data);
    return ENOENT;
}
