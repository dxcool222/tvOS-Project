#define _DARWIN_C_SOURCE 1

#include "dt_rootless_tree_ops.h"

#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * HOST_SIM exact-string reproduction of the R12 leftover-dest realpath follow.
 * Separate TU so product copy/postverify objects contain zero nftw relocs.
 * Product FRESH_FS does not call this. 0 BL from install/bringup.
 */

static int set_err(char *err, size_t errlen, const char *fmt, const char *a, const char *b)
{
    if (!err || errlen == 0)
        return -1;
    if (b)
        snprintf(err, errlen, fmt, a ? a : "", b);
    else
        snprintf(err, errlen, fmt, a ? a : "");
    return -1;
}

static const char *g_leg_src;
static const char *g_leg_dst;
static char *g_leg_err;
static size_t g_leg_errlen;
static int g_leg_rc;
static char g_leg_dst_real[PATH_MAX];

static int r12_legacy_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    char rel[PATH_MAX];
    char dest[PATH_MAX];
    char dest_real[PATH_MAX];
    size_t src_len;

    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    if (g_leg_rc != 0)
        return 1;
    src_len = strlen(g_leg_src);
    if (strncmp(fpath, g_leg_src, src_len) != 0)
        return 0;
    if (fpath[src_len] == '\0' || fpath[src_len] != '/')
        return 0;
    snprintf(rel, sizeof(rel), "%s", fpath + src_len + 1);
    if (snprintf(dest, sizeof(dest), "%s/%s", g_leg_dst, rel) >= (int)sizeof(dest)) {
        set_err(g_leg_err, g_leg_errlen, "JBROOT escape %s", rel, NULL);
        g_leg_rc = -1;
        return 1;
    }
    /* Pre-fix copier: realpath follows leftover dest symlink. */
    if (realpath(dest, dest_real)) {
        size_t dl = strlen(g_leg_dst_real);
        if (strncmp(dest_real, g_leg_dst_real, dl) != 0
                || (dest_real[dl] != '\0' && dest_real[dl] != '/')) {
            set_err(g_leg_err, g_leg_errlen, "JBROOT escape %s", rel, NULL);
            g_leg_rc = -1;
            return 1;
        }
    }
    return 0;
}

int dt_rootless_r12_legacy_dest_follow_escape(const char *src_root, const char *dst_root,
                                              char *err, size_t errlen)
{
    char src[PATH_MAX], dst[PATH_MAX];
    char src_real[PATH_MAX];

    if (!src_root || !src_root[0] || !dst_root || !dst_root[0])
        return set_err(err, errlen, "unsafe payload path %s", "(null)", NULL);
    snprintf(src, sizeof(src), "%s", src_root);
    snprintf(dst, sizeof(dst), "%s", dst_root);
    size_t L = strlen(src);
    while (L > 1 && src[L - 1] == '/')
        src[--L] = '\0';
    L = strlen(dst);
    while (L > 1 && dst[L - 1] == '/')
        dst[--L] = '\0';
    if (!realpath(src, src_real))
        return set_err(err, errlen, "payload missing: %s", src_root, NULL);
    if (!realpath(dst, g_leg_dst_real))
        return set_err(err, errlen, "copy mkdir %s", dst_root, NULL);

    g_leg_src = src_real;
    g_leg_dst = g_leg_dst_real;
    g_leg_err = err;
    g_leg_errlen = errlen;
    g_leg_rc = 0;
    if (err && errlen)
        err[0] = '\0';
    if (nftw(src_real, r12_legacy_cb, 16, FTW_PHYS) != 0 && g_leg_rc == 0)
        return set_err(err, errlen, "copy file %s", src_root, NULL);
    return g_leg_rc;
}
