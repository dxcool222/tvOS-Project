#define _DARWIN_C_SOURCE 1

#include "dt_rootless_path_policy.h"

#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* POSIX-normalize a relative path. Returns 0, or -1 if it escapes above root. */
static int normalize_rel(const char *in, char *out, size_t outlen)
{
    const char *comp[128];
    int n = 0;
    char buf[PATH_MAX];
    size_t len;

    if (!in || !out || outlen == 0)
        return -1;
    len = strlen(in);
    if (len == 0 || len >= sizeof(buf))
        return -1;
    memcpy(buf, in, len + 1);

    char *save = NULL;
    for (char *tok = strtok_r(buf, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
        if (tok[0] == '\0' || strcmp(tok, ".") == 0)
            continue;
        if (strcmp(tok, "..") == 0) {
            if (n == 0)
                return -1;
            n--;
            continue;
        }
        if (n >= (int)(sizeof(comp) / sizeof(comp[0])))
            return -1;
        comp[n++] = tok;
    }
    if (n == 0) {
        if (outlen < 2)
            return -1;
        out[0] = '.';
        out[1] = '\0';
        return 0;
    }
    size_t w = 0;
    for (int i = 0; i < n; i++) {
        size_t cl = strlen(comp[i]);
        if (w + cl + (w ? 1 : 0) + 1 > outlen)
            return -1;
        if (w)
            out[w++] = '/';
        memcpy(out + w, comp[i], cl);
        w += cl;
    }
    out[w] = '\0';
    return 0;
}

int dt_rootless_payload_rel_ok(const char *rel, char *err, size_t errlen)
{
    char norm[PATH_MAX];

    if (!rel || rel[0] == '\0' || rel[0] == '/')
        return set_err(err, errlen, "unsafe payload path %s", rel ? rel : "", NULL);
    /* rel itself must not use ".." components — enumerator paths are payload-relative. */
    if (normalize_rel(rel, norm, sizeof(norm)) != 0)
        return set_err(err, errlen, "unsafe payload path %s", rel, NULL);
    if (strstr(rel, "/../") || strncmp(rel, "../", 3) == 0 || strcmp(rel, "..") == 0)
        return set_err(err, errlen, "unsafe payload path %s", rel, NULL);
    return 0;
}

int dt_rootless_symlink_target_ok(const char *rel, const char *tgt, char *err, size_t errlen)
{
    char parent[PATH_MAX];
    char joined[PATH_MAX];
    char norm[PATH_MAX];
    const char *slash;

    if (dt_rootless_payload_rel_ok(rel, err, errlen) != 0)
        return -1;
    if (!tgt || tgt[0] == '\0')
        return set_err(err, errlen, "dotdot symlink %s -> %s", rel, tgt ? tgt : "");

    if (tgt[0] == '/') {
        if (strncmp(tgt, "/var/jb/", 8) == 0
            || strncmp(tgt, "/private/var/jb/", 16) == 0
            || strncmp(tgt, "/var/db/timezone/", 17) == 0
            || strstr(tgt, "/dopamin-tvos-102710/procursus") != NULL)
            return 0;
        return set_err(err, errlen, "unsafe abs symlink %s -> %s", rel, tgt);
    }

    slash = strrchr(rel, '/');
    if (slash) {
        size_t pl = (size_t)(slash - rel);
        if (pl >= sizeof(parent))
            return set_err(err, errlen, "dotdot symlink %s -> %s", rel, tgt);
        memcpy(parent, rel, pl);
        parent[pl] = '\0';
        if (snprintf(joined, sizeof(joined), "%s/%s", parent, tgt) >= (int)sizeof(joined))
            return set_err(err, errlen, "dotdot symlink %s -> %s", rel, tgt);
    } else {
        if (snprintf(joined, sizeof(joined), "%s", tgt) >= (int)sizeof(joined))
            return set_err(err, errlen, "dotdot symlink %s -> %s", rel, tgt);
    }

    if (normalize_rel(joined, norm, sizeof(norm)) != 0)
        return set_err(err, errlen, "dotdot symlink %s -> %s", rel, tgt);
    return 0;
}

static const char *g_walk_root;
static char *g_walk_err;
static size_t g_walk_errlen;
static int g_walk_rc;
static int g_walk_legacy;

static int walk_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    char rel[PATH_MAX];
    char tgt[PATH_MAX];
    ssize_t n;
    size_t root_len;

    (void)sb;
    (void)ftwbuf;
    if (g_walk_rc != 0)
        return 1;
    if (!g_walk_root)
        return 1;
    root_len = strlen(g_walk_root);
    if (strncmp(fpath, g_walk_root, root_len) != 0)
        return 0;
    if (fpath[root_len] == '\0')
        return 0;
    if (fpath[root_len] != '/')
        return 0;
    snprintf(rel, sizeof(rel), "%s", fpath + root_len + 1);

    if (typeflag != FTW_SL && typeflag != FTW_SLN) {
        if (dt_rootless_payload_rel_ok(rel, g_walk_err, g_walk_errlen) != 0) {
            g_walk_rc = -1;
            return 1;
        }
        return 0;
    }

    n = readlink(fpath, tgt, sizeof(tgt) - 1);
    if (n < 0) {
        set_err(g_walk_err, g_walk_errlen, "dotdot symlink %s -> %s", rel, "?");
        g_walk_rc = -1;
        return 1;
    }
    tgt[n] = '\0';

    if (g_walk_legacy) {
        if (strstr(tgt, "..") != NULL) {
            set_err(g_walk_err, g_walk_errlen, "dotdot symlink %s -> %s", rel, tgt);
            g_walk_rc = -1;
            return 1;
        }
        return 0;
    }
    if (dt_rootless_symlink_target_ok(rel, tgt, g_walk_err, g_walk_errlen) != 0) {
        g_walk_rc = -1;
        return 1;
    }
    return 0;
}

static int walk_tree(const char *payload_root, int legacy, char *err, size_t errlen)
{
    char root[PATH_MAX];
    char resolved[PATH_MAX];

    if (!payload_root || payload_root[0] == '\0')
        return set_err(err, errlen, "unsafe payload path %s", "(null)", NULL);
    snprintf(root, sizeof(root), "%s", payload_root);
    size_t L = strlen(root);
    while (L > 1 && root[L - 1] == '/') {
        root[--L] = '\0';
    }
    if (!realpath(root, resolved))
        snprintf(resolved, sizeof(resolved), "%s", root);

    g_walk_root = resolved;
    g_walk_err = err;
    g_walk_errlen = errlen;
    g_walk_rc = 0;
    g_walk_legacy = legacy;
    if (err && errlen)
        err[0] = '\0';
    if (nftw(resolved, walk_cb, 16, FTW_PHYS) != 0 && g_walk_rc == 0)
        return set_err(err, errlen, "unsafe payload path %s", payload_root, NULL);
    return g_walk_rc;
}

int dt_rootless_payload_tree_install_check(const char *payload_root, char *err, size_t errlen)
{
    return walk_tree(payload_root, 0, err, errlen);
}

int dt_rootless_r10_legacy_dotdot_scan(const char *payload_root, char *err, size_t errlen)
{
    return walk_tree(payload_root, 1, err, errlen);
}
