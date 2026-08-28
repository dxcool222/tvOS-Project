#define _DARWIN_C_SOURCE 1

#include "dt_rootless_tree_ops.h"
#include "dt_rootless_path_policy.h"

#include <CommonCrypto/CommonDigest.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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

/* Last-component recursive delete. lstat first so a leftover symlink is unlinked,
 * never opened. A leftover non-empty directory is removed rather than rmdir-fail. */
static int rm_tree_nofollow(const char *path)
{
    struct stat st;
    DIR *d;
    struct dirent *de;
    char child[PATH_MAX];

    char **names = NULL;
    int nn = 0, cap = 0, i, rc = -1;

    if (!path || !path[0] || strcmp(path, "/") == 0)
        return -1;
    if (lstat(path, &st) != 0)
        return (errno == ENOENT) ? 0 : -1;
    if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
        return unlink(path) == 0 || errno == ENOENT ? 0 : -1;
    d = opendir(path);
    if (!d)
        return -1;
    while ((de = readdir(d)) != NULL) {
        char **nv;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (nn == cap) {
            cap = cap ? cap * 2 : 16;
            nv = realloc(names, (size_t)cap * sizeof(*nv));
            if (!nv)
                goto done;
            names = nv;
        }
        names[nn] = strdup(de->d_name);
        if (!names[nn])
            goto done;
        nn++;
    }
    closedir(d);
    d = NULL;
    for (i = 0; i < nn; i++) {
        if (snprintf(child, sizeof(child), "%s/%s", path, names[i]) >= (int)sizeof(child))
            goto done;
        if (rm_tree_nofollow(child) != 0)
            goto done;
    }
    rc = rmdir(path) == 0 || errno == ENOENT ? 0 : -1;
done:
    if (d)
        closedir(d);
    for (i = 0; i < nn; i++)
        free(names[i]);
    free(names);
    return rc;
}

static int ensure_real_dir(const char *path, mode_t mode)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno != ENOENT)
            return -1;
        if (mkdir(path, mode) != 0)
            return -1;
        if (lstat(path, &st) != 0)
            return -1;
        if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
            return -1;
        return 0;
    }
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode))
        return 0;
    if (rm_tree_nofollow(path) != 0)
        return -1;
    if (mkdir(path, mode) != 0)
        return -1;
    if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
        return -1;
    return 0;
}

static int dest_lexically_inside(const char *dest, const char *dst_real);

/* Create prefixes of path that sit under dst_real. Never ensure_real_dir("/") or "/tmp". */
static int mkdir_p_under(const char *path, const char *dst_real, mode_t mode)
{
    char tmp[PATH_MAX];
    size_t dl;
    if (!dest_lexically_inside(path, dst_real))
        return -1;
    dl = strlen(dst_real);
    if (strcmp(path, dst_real) == 0)
        return 0;
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + dl + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = 0;
        if (ensure_real_dir(tmp, mode) != 0)
            return -1;
        *p = '/';
    }
    return ensure_real_dir(tmp, mode);
}

#define PACKED_MACHO_WRAP "R14MACHO"
#define PACKED_MACHO_WRAP_LEN 8

/* IPA zip RootlessPayload Mach-Os are 0755 MH_MAGIC. tvOS installd/TrollStore
 * re-signs nested executables in the .app, so packed SHA of bin/sync fails on
 * device (21:51 all_logs: n_src=215 macho_fail=1). Skip this 8-byte wrap when
 * hashing packed source and when writing dest; dest bytes stay the TSV Mach-O. */
static int fd_skip_packed_macho_wrap(int fd)
{
    unsigned char hdr[PACKED_MACHO_WRAP_LEN];
    ssize_t n;

    n = read(fd, hdr, PACKED_MACHO_WRAP_LEN);
    if (n < 0)
        return -1;
    if (n == PACKED_MACHO_WRAP_LEN
            && memcmp(hdr, PACKED_MACHO_WRAP, PACKED_MACHO_WRAP_LEN) == 0)
        return 0;
    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;
    return 0;
}

static int copy_reg_nofollow(const char *src, const char *dst, mode_t mode,
                             int unwrap_packed_macho)
{
    int in_fd = -1, out_fd = -1;
    char buf[1 << 16];
    ssize_t n;
    int rc = -1;

    in_fd = open(src, O_RDONLY | O_NOFOLLOW);
    if (in_fd < 0)
        return -1;
    if (unwrap_packed_macho && fd_skip_packed_macho_wrap(in_fd) != 0)
        goto done;
    /* Keep setuid/setgid/sticky (07777). open() may ignore high bits; fchmod applies them. */
    out_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode & 07777);
    if (out_fd < 0)
        goto done;
    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        char *w = buf;
        ssize_t left = n;
        while (left > 0) {
            ssize_t wn = write(out_fd, w, (size_t)left);
            if (wn < 0)
                goto done;
            left -= wn;
            w += wn;
        }
    }
    if (n < 0)
        goto done;
    if (fchmod(out_fd, mode & 07777) != 0)
        goto done;
    if (fsync(out_fd) != 0)
        goto done;
    rc = 0;
done:
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    return rc;
}

static int parse_mode_oct(const char *s, mode_t *out)
{
    const char *p = s ? s : "";
    unsigned long v;
    char *end = NULL;
    if (p[0] == '0' && (p[1] == 'o' || p[1] == 'O'))
        p += 2;
    v = strtoul(p, &end, 8);
    if (!end || end == p)
        return -1;
    *out = (mode_t)(v & 07777);
    return 0;
}

static int sha256_file_nofollow(const char *path, char outhex[65], int unwrap_packed_macho);
static int split_tabs(char *line, char **cols, int max_cols);

static int join_root_rel(char *out, size_t outlen, const char *root, const char *rel)
{
    if (!rel || !rel[0])
        return snprintf(out, outlen, "%s", root) >= (int)outlen ? -1 : 0;
    return snprintf(out, outlen, "%s/%s", root, rel) >= (int)outlen ? -1 : 0;
}

static int dest_lexically_inside(const char *dest, const char *dst_real)
{
    size_t dl = strlen(dst_real);
    if (strncmp(dest, dst_real, dl) != 0)
        return 0;
    return dest[dl] == '\0' || dest[dl] == '/';
}

/* Prefixes of dest must be real directories under dst_real. lstat, not realpath. */
static int parent_inside_jbroot(const char *dest, const char *dst_real,
                                const char *rel, char *err, size_t errlen)
{
    char prefix[PATH_MAX];
    size_t dl;
    struct stat st;
    if (!dest_lexically_inside(dest, dst_real))
        return set_err(err, errlen, "JBROOT escape %s", rel, NULL);
    dl = strlen(dst_real);
    if (lstat(dst_real, &st) != 0 || S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
        return set_err(err, errlen, "JBROOT escape %s", rel, NULL);
    snprintf(prefix, sizeof(prefix), "%s", dest);
    for (char *p = prefix + dl + 1; *p; p++) {
        char *slash;
        if (*p != '/')
            continue;
        slash = p;
        *slash = '\0';
        if (lstat(prefix, &st) != 0 || S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
            return set_err(err, errlen, "JBROOT escape %s", rel, NULL);
        *slash = '/';
    }
    return 0;
}

/* Replace last component only. lstat first: leftover symlink is unlinked, not followed.
 * Leftover directories (empty or not) are removed as the last name. */
static int replace_dest_last(const char *dest, char *err, size_t errlen, const char *rel)
{
    if (rm_tree_nofollow(dest) != 0)
        return set_err(err, errlen, "copy replace %s", rel, NULL);
    return 0;
}

static int ensure_dest_parent(const char *dest, const char *dst_real, const char *rel,
                              char *err, size_t errlen)
{
    char parent[PATH_MAX];
    char *slash;
    size_t dl;
    if (!dest_lexically_inside(dest, dst_real))
        return set_err(err, errlen, "JBROOT escape %s", rel, NULL);
    snprintf(parent, sizeof(parent), "%s", dest);
    slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return 0;
    *slash = '\0';
    dl = strlen(dst_real);
    if (strlen(parent) < dl)
        return set_err(err, errlen, "JBROOT escape %s", rel, NULL);
    if (mkdir_p_under(parent, dst_real, 0755) != 0)
        return set_err(err, errlen, "copy mkdir %s", rel, NULL);
    if (parent_inside_jbroot(dest, dst_real, rel, err, errlen) != 0)
        return -1;
    return 0;
}

static int kind_is_dir(const char *kind) { return strcmp(kind, "DIRECTORY") == 0; }
static int kind_is_link(const char *kind) { return strcmp(kind, "SYMLINK") == 0; }
static int kind_is_macho(const char *kind) { return strcmp(kind, "MACHO") == 0; }

static int walk_manifest_rows(const char *src_root, const char *dst_root, const char *dst_real,
                              const char *manifest_path, int do_install,
                              dt_rootless_copy_counts_t *counts, char *err, size_t errlen);
static int dest_prune_extras(const char *dst_real, const char *manifest_path,
                             char *err, size_t errlen);
static int dest_count_extras(const char *jbroot, const char *manifest_path,
                             dt_rootless_postverify_counts_t *out);

int dt_rootless_packed_source_verify(const char *src_root, const char *manifest_path,
                                     dt_rootless_copy_counts_t *counts,
                                     char *err, size_t errlen)
{
    char src[PATH_MAX], src_real[PATH_MAX];
    if (!src_root || !src_root[0] || !manifest_path || !manifest_path[0])
        return set_err(err, errlen, "unsafe payload path %s", "(null)", NULL);
    snprintf(src, sizeof(src), "%s", src_root);
    {
        size_t L = strlen(src);
        while (L > 1 && src[L - 1] == '/')
            src[--L] = '\0';
    }
    if (!realpath(src, src_real))
        return set_err(err, errlen, "payload missing: %s", src_root, NULL);
    if (counts)
        memset(counts, 0, sizeof(*counts));
    if (err && errlen)
        err[0] = '\0';
    return walk_manifest_rows(src_real, NULL, NULL, manifest_path, 0, counts, err, errlen);
}

int dt_rootless_copy_payload_tree(const char *src_root, const char *dst_root,
                                  const char *manifest_path,
                                  dt_rootless_copy_counts_t *counts,
                                  char *err, size_t errlen)
{
    char src[PATH_MAX], dst[PATH_MAX];
    char src_real[PATH_MAX], dst_real[PATH_MAX];
    dt_rootless_copy_counts_t local;
    dt_rootless_copy_counts_t *c = counts ? counts : &local;

    if (!src_root || !src_root[0] || !dst_root || !dst_root[0] || !manifest_path || !manifest_path[0])
        return set_err(err, errlen, "unsafe payload path %s", "(null)", NULL);
    snprintf(src, sizeof(src), "%s", src_root);
    snprintf(dst, sizeof(dst), "%s", dst_root);
    {
        size_t L = strlen(src);
        while (L > 1 && src[L - 1] == '/')
            src[--L] = '\0';
        L = strlen(dst);
        while (L > 1 && dst[L - 1] == '/')
            dst[--L] = '\0';
    }
    if (!realpath(src, src_real))
        return set_err(err, errlen, "payload missing: %s", src_root, NULL);
    memset(c, 0, sizeof(*c));
    if (err && errlen)
        err[0] = '\0';
    if (walk_manifest_rows(src_real, NULL, NULL, manifest_path, 0, c, err, errlen) != 0)
        return -1;
    if (c->n_src != 4053 || c->n_src_type_mismatch || c->n_src_tgt_mismatch
            || c->n_src_macho_fail || c->n_src_macho_ok != 397)
        return set_err(err, errlen, "packed source verify %s", src_root, NULL);
    if (ensure_real_dir(dst, 0755) != 0)
        return set_err(err, errlen, "copy mkdir %s", dst_root, NULL);
    {
        struct stat st;
        if (lstat(dst, &st) != 0 || S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
            return set_err(err, errlen, "copy mkdir %s", dst_root, NULL);
    }
    if (!realpath(dst, dst_real))
        return set_err(err, errlen, "copy mkdir %s", dst_root, NULL);
    {
        struct stat st;
        if (lstat(dst_real, &st) != 0 || S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
            return set_err(err, errlen, "copy mkdir %s", dst_root, NULL);
    }
    c->n_symlink_install = 0;
    c->n_symlink_imm_ok = 0;
    c->n_symlink_imm_fail = 0;
    c->n_macho_imm_ok = 0;
    c->n_macho_imm_fail = 0;
    if (walk_manifest_rows(src_real, dst_real, dst_real, manifest_path, 1, c, err, errlen) != 0)
        return -1;
    if (c->n_symlink_install != 150 || c->n_symlink_imm_ok != 150 || c->n_symlink_imm_fail
            || c->n_macho_imm_ok != 397 || c->n_macho_imm_fail)
        return set_err(err, errlen, "manifest install verify %s", dst_root, NULL);
    if (dest_prune_extras(dst_real, manifest_path, err, errlen) != 0)
        return -1;
    return 0;
}

static int src_row_ok(const char *src_path, const char *kind, const char *want_tgt,
                      const char *want_sha, dt_rootless_copy_counts_t *c,
                      char *err, size_t errlen, const char *rel)
{
    struct stat st;
    if (lstat(src_path, &st) != 0)
        return set_err(err, errlen, "payload missing: %s", rel, NULL);
    if (kind_is_dir(kind)) {
        if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
            if (c) c->n_src_type_mismatch++;
            return set_err(err, errlen, "packed type mismatch dir %s", rel, NULL);
        }
        return 0;
    }
    if (kind_is_link(kind)) {
        char got[PATH_MAX];
        ssize_t n;
        if (S_ISLNK(st.st_mode)) {
            n = readlink(src_path, got, sizeof(got) - 1);
            if (n < 0)
                got[0] = '\0';
            else
                got[n] = '\0';
        } else if (S_ISREG(st.st_mode) && want_tgt && want_tgt[0]) {
            size_t wt = strlen(want_tgt);
            int fd;
            if (st.st_size <= 0 || (size_t)st.st_size != wt || wt >= sizeof(got)) {
                if (c) c->n_src_type_mismatch++;
                return set_err(err, errlen, "packed type mismatch symlink %s", rel, NULL);
            }
            fd = open(src_path, O_RDONLY | O_NOFOLLOW);
            if (fd < 0) {
                if (c) c->n_src_type_mismatch++;
                return set_err(err, errlen, "packed type mismatch symlink %s", rel, NULL);
            }
            n = read(fd, got, wt);
            close(fd);
            if (n < 0 || (size_t)n != wt) {
                if (c) c->n_src_type_mismatch++;
                return set_err(err, errlen, "packed type mismatch symlink %s", rel, NULL);
            }
            got[wt] = '\0';
        } else {
            if (c) c->n_src_type_mismatch++;
            return set_err(err, errlen, "packed type mismatch symlink %s", rel, NULL);
        }
        if (want_tgt && want_tgt[0] && strcmp(got, want_tgt) != 0) {
            if (c) c->n_src_tgt_mismatch++;
            return set_err(err, errlen, "packed symlink tgt %s", rel, NULL);
        }
        return 0;
    }
    if (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
        if (c) c->n_src_type_mismatch++;
        return set_err(err, errlen, "packed type mismatch file %s", rel, NULL);
    }
    if (kind_is_macho(kind) && want_sha && strlen(want_sha) == 64) {
        char got[65];
        if (sha256_file_nofollow(src_path, got, 1) != 0 || strcasecmp(got, want_sha) != 0) {
            if (c) c->n_src_macho_fail++;
            return set_err(err, errlen, "packed macho sha %s", rel, NULL);
        }
        if (c) c->n_src_macho_ok++;
    }
    return 0;
}

static int install_row(const char *src_path, const char *dest, const char *dst_real,
                       const char *rel, const char *kind, const char *want_tgt,
                       const char *want_sha, const char *mode_s,
                       dt_rootless_copy_counts_t *c, char *err, size_t errlen)
{
    mode_t mode = 0755;
    struct stat st;

    if (dt_rootless_payload_rel_ok(rel, err, errlen) != 0)
        return -1;
    (void)parse_mode_oct(mode_s, &mode);
    if (ensure_dest_parent(dest, dst_real, rel, err, errlen) != 0)
        return -1;

    if (kind_is_dir(kind)) {
        if (lstat(dest, &st) == 0 && !(S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode))) {
            if (replace_dest_last(dest, err, errlen, rel) != 0)
                return -1;
        }
        if (ensure_real_dir(dest, mode) != 0)
            return set_err(err, errlen, "copy mkdir %s", rel, NULL);
        if (lstat(dest, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
            return set_err(err, errlen, "copied dir is not a dir %s", rel, NULL);
        return 0;
    }

    if (kind_is_link(kind)) {
        char got[PATH_MAX];
        ssize_t n;
        if (c) c->n_symlink_install++;
        if (dt_rootless_symlink_target_ok(rel, want_tgt, err, errlen) != 0)
            return -1;
        if (replace_dest_last(dest, err, errlen, rel) != 0)
            return -1;
        if (symlink(want_tgt, dest) != 0)
            return set_err(err, errlen, "copy symlink %s -> %s", rel, want_tgt);
        if (lstat(dest, &st) != 0 || !S_ISLNK(st.st_mode)) {
            if (c) c->n_symlink_imm_fail++;
            return set_err(err, errlen, "copied symlink is not a symlink %s", rel, NULL);
        }
        n = readlink(dest, got, sizeof(got) - 1);
        if (n < 0)
            got[0] = '\0';
        else
            got[n] = '\0';
        if (strcmp(got, want_tgt) != 0) {
            if (c) c->n_symlink_imm_fail++;
            return set_err(err, errlen, "copied symlink tgt %s", rel, NULL);
        }
        if (c) c->n_symlink_imm_ok++;
        return 0;
    }

    if (replace_dest_last(dest, err, errlen, rel) != 0)
        return -1;
    if (copy_reg_nofollow(src_path, dest, mode, kind_is_macho(kind) ? 1 : 0) != 0)
        return set_err(err, errlen, "copy file %s", rel, NULL);
    if (lstat(dest, &st) != 0 || !S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))
        return set_err(err, errlen, "copied file is not a file %s", rel, NULL);
    if (kind_is_macho(kind) && want_sha && strlen(want_sha) == 64) {
        char got[65];
        if (sha256_file_nofollow(dest, got, 0) != 0 || strcasecmp(got, want_sha) != 0) {
            if (c) c->n_macho_imm_fail++;
            return set_err(err, errlen, "copied macho sha %s", rel, NULL);
        }
        if (c) c->n_macho_imm_ok++;
    }
    return 0;
}

static int walk_manifest_rows(const char *src_root, const char *dst_root, const char *dst_real,
                              const char *manifest_path, int do_install,
                              dt_rootless_copy_counts_t *counts, char *err, size_t errlen)
{
    FILE *f;
    char line[4096];
    char hdrbuf[1024];
    char *hcols[16];
    int nh, iRel = -1, iKind = -1, iTgt = -1, iSha = -1, iMode = -1;

    f = fopen(manifest_path, "r");
    if (!f)
        return set_err(err, errlen, "payload path manifest missing/empty", "", NULL);
    if (!fgets(hdrbuf, sizeof(hdrbuf), f)) {
        fclose(f);
        return set_err(err, errlen, "payload path manifest empty", "", NULL);
    }
    hdrbuf[strcspn(hdrbuf, "\r\n")] = '\0';
    nh = split_tabs(hdrbuf, hcols, 16);
    for (int i = 0; i < nh; i++) {
        if (strcmp(hcols[i], "RELATIVE_PATH") == 0) iRel = i;
        else if (strcmp(hcols[i], "KIND") == 0) iKind = i;
        else if (strcmp(hcols[i], "SYMLINK_TARGET") == 0) iTgt = i;
        else if (strcmp(hcols[i], "SHA256") == 0) iSha = i;
        else if (strcmp(hcols[i], "MODE_OCT") == 0) iMode = i;
    }
    if (iRel < 0 || iKind < 0) {
        fclose(f);
        return set_err(err, errlen, "payload path manifest columns missing", "", NULL);
    }

    while (fgets(line, sizeof(line), f)) {
        char *cols[16];
        int nc;
        const char *rel, *kind, *tgt, *sha, *mode_s;
        char src_path[PATH_MAX], dest[PATH_MAX];

        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0')
            continue;
        nc = split_tabs(line, cols, 16);
        if (nc <= iRel || nc <= iKind)
            continue;
        rel = cols[iRel];
        kind = cols[iKind];
        tgt = (iTgt >= 0 && nc > iTgt) ? cols[iTgt] : "";
        sha = (iSha >= 0 && nc > iSha) ? cols[iSha] : "";
        mode_s = (iMode >= 0 && nc > iMode) ? cols[iMode] : "0o755";
        if (dt_rootless_payload_rel_ok(rel, err, errlen) != 0) {
            fclose(f);
            return -1;
        }
        if (join_root_rel(src_path, sizeof(src_path), src_root, rel) != 0) {
            fclose(f);
            return set_err(err, errlen, "JBROOT escape %s", rel, NULL);
        }
        if (!do_install) {
            if (counts)
                counts->n_src++;
            if (src_row_ok(src_path, kind, tgt, sha, counts, err, errlen, rel) != 0) {
                fclose(f);
                return -1;
            }
            continue;
        }
        if (join_root_rel(dest, sizeof(dest), dst_root, rel) != 0) {
            fclose(f);
            return set_err(err, errlen, "JBROOT escape %s", rel, NULL);
        }
        if (install_row(src_path, dest, dst_real, rel, kind, tgt, sha, mode_s,
                        counts, err, errlen) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

static int sha256_file_nofollow(const char *path, char outhex[65], int unwrap_packed_macho)
{
    int fd;
    CC_SHA256_CTX ctx;
    unsigned char buf[1 << 16];
    unsigned char dig[CC_SHA256_DIGEST_LENGTH];
    ssize_t n;

    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (unwrap_packed_macho && fd_skip_packed_macho_wrap(fd) != 0) {
        close(fd);
        return -1;
    }
    CC_SHA256_Init(&ctx);
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
    if (n < 0) {
        close(fd);
        return -1;
    }
    CC_SHA256_Final(dig, &ctx);
    close(fd);
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        snprintf(outhex + (i * 2), 3, "%02x", dig[i]);
    outhex[64] = '\0';
    return 0;
}

static int split_tabs(char *line, char **cols, int max_cols)
{
    int n = 0;
    char *p = line;
    cols[n++] = p;
    while (*p && n < max_cols) {
        if (*p == '\t') {
            *p = '\0';
            cols[n++] = p + 1;
        }
        p++;
    }
    return n;
}

static int rel_cmp(const void *a, const void *b)
{
    return strcmp(*(char * const *)a, *(char * const *)b);
}

typedef struct {
    char **v;
    int n;
    int cap;
} relset_t;

static void relset_free(relset_t *s)
{
    int i;
    if (!s)
        return;
    for (i = 0; i < s->n; i++)
        free(s->v[i]);
    free(s->v);
    memset(s, 0, sizeof(*s));
}

static int relset_add(relset_t *s, const char *rel)
{
    char **nv;
    int ncap;
    if (s->n == s->cap) {
        ncap = s->cap ? s->cap * 2 : 512;
        nv = realloc(s->v, (size_t)ncap * sizeof(*nv));
        if (!nv)
            return -1;
        s->v = nv;
        s->cap = ncap;
    }
    s->v[s->n] = strdup(rel);
    if (!s->v[s->n])
        return -1;
    s->n++;
    return 0;
}

static int relset_has(const relset_t *s, const char *rel)
{
    return bsearch(&rel, s->v, (size_t)s->n, sizeof(char *), rel_cmp) != NULL;
}

static int relset_load(relset_t *s, const char *manifest_path)
{
    FILE *f;
    char line[4096];
    char hdrbuf[1024];
    char *hcols[16];
    int nh, iRel = -1;

    memset(s, 0, sizeof(*s));
    f = fopen(manifest_path, "r");
    if (!f)
        return -1;
    if (!fgets(hdrbuf, sizeof(hdrbuf), f)) {
        fclose(f);
        return -1;
    }
    hdrbuf[strcspn(hdrbuf, "\r\n")] = '\0';
    nh = split_tabs(hdrbuf, hcols, 16);
    for (int i = 0; i < nh; i++) {
        if (strcmp(hcols[i], "RELATIVE_PATH") == 0)
            iRel = i;
    }
    if (iRel < 0) {
        fclose(f);
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        char *cols[16];
        int nc;
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0])
            continue;
        nc = split_tabs(line, cols, 16);
        if (nc <= iRel)
            continue;
        if (relset_add(s, cols[iRel]) != 0) {
            fclose(f);
            relset_free(s);
            return -1;
        }
    }
    fclose(f);
    qsort(s->v, (size_t)s->n, sizeof(char *), rel_cmp);
    return 0;
}

static int dest_allowed_extra(const char *rel)
{
    /* 22:05 all_logs: OPAINJECT1 PASS (KCALL681_REMOTE_DLOPEN_WORKING) then
     * FRESH dest prune, then OPAINJECT2 dt_opainject516 exit=252.
     * WEXITSTATUS(252) = return -4 in dt_opainject681_main.m: access(dylib,R_OK).
     * argv dylib is dt710_resolve_hook_path() = dest/basebin/launchdhook516.dylib.
     * That path is not a TSV row. Wall2 also staged libjailbreak.dylib and
     * libchoma.dylib next to it. Keep those three plus their parent dir.
     *
     * R16: dest-root ctor marker names are not keep-listed. Packaged hook
     * never writes them (IDA). CTOR2 is this-run Wall1 ctor kv + OPAINJECT2.
     * Do not keep the Wall1 constructor trace file under basebin. */
    return strcmp(rel, ".rootless_r4_incomplete") == 0
        || strcmp(rel, "basebin") == 0
        || strcmp(rel, "basebin/launchdhook516.dylib") == 0
        || strcmp(rel, "basebin/libjailbreak.dylib") == 0
        || strcmp(rel, "basebin/libchoma.dylib") == 0
        || strcmp(rel, "basebin/systemhook.dylib") == 0;
}

static int dest_walk_extras(const char *jbroot, const char *rel, const relset_t *s,
                            int prune, unsigned long *n_extra, char *err, size_t errlen)
{
    char dir[PATH_MAX], child[PATH_MAX], child_rel[PATH_MAX];
    DIR *d;
    struct dirent *de;
    struct stat st;
    char **names = NULL;
    int nn = 0, cap = 0, i, rc = -1;

    if (join_root_rel(dir, sizeof(dir), jbroot, rel) != 0)
        return set_err(err, errlen, "JBROOT escape %s", rel, NULL);
    if (!dest_lexically_inside(dir, jbroot))
        return set_err(err, errlen, "JBROOT escape %s", rel, NULL);
    d = opendir(dir);
    if (!d)
        return set_err(err, errlen, "copy replace %s", rel[0] ? rel : ".", NULL);
    while ((de = readdir(d)) != NULL) {
        char **nv;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (nn == cap) {
            cap = cap ? cap * 2 : 16;
            nv = realloc(names, (size_t)cap * sizeof(*nv));
            if (!nv) {
                closedir(d);
                goto extra_done;
            }
            names = nv;
        }
        names[nn] = strdup(de->d_name);
        if (!names[nn]) {
            closedir(d);
            goto extra_done;
        }
        nn++;
    }
    closedir(d);
    d = NULL;
    for (i = 0; i < nn; i++) {
        if (rel[0]) {
            if (snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, names[i])
                    >= (int)sizeof(child_rel)) {
                set_err(err, errlen, "JBROOT escape %s", names[i], NULL);
                goto extra_done;
            }
        } else if (snprintf(child_rel, sizeof(child_rel), "%s", names[i])
                >= (int)sizeof(child_rel)) {
            set_err(err, errlen, "JBROOT escape %s", names[i], NULL);
            goto extra_done;
        }
        if (join_root_rel(child, sizeof(child), jbroot, child_rel) != 0) {
            set_err(err, errlen, "JBROOT escape %s", child_rel, NULL);
            goto extra_done;
        }
        if (!dest_lexically_inside(child, jbroot)) {
            set_err(err, errlen, "JBROOT escape %s", child_rel, NULL);
            goto extra_done;
        }
        if (lstat(child, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            if (dest_walk_extras(jbroot, child_rel, s, prune, n_extra, err, errlen) != 0)
                goto extra_done;
        }
        if (dest_allowed_extra(child_rel))
            continue;
        if (relset_has(s, child_rel))
            continue;
        if (n_extra)
            (*n_extra)++;
        if (prune) {
            if (rm_tree_nofollow(child) != 0) {
                set_err(err, errlen, "copy replace %s", child_rel, NULL);
                goto extra_done;
            }
        } else if (err && errlen && !err[0]) {
            set_err(err, errlen, "postverify dest extra %s", child_rel, NULL);
        }
    }
    rc = 0;
extra_done:
    for (i = 0; i < nn; i++)
        free(names[i]);
    free(names);
    return rc;
}

static int dest_prune_extras(const char *dst_real, const char *manifest_path,
                             char *err, size_t errlen)
{
    relset_t s;
    unsigned long n_extra = 0;
    if (relset_load(&s, manifest_path) != 0)
        return set_err(err, errlen, "payload path manifest missing/empty", "", NULL);
    if (dest_walk_extras(dst_real, "", &s, 1, &n_extra, err, errlen) != 0) {
        relset_free(&s);
        return -1;
    }
    relset_free(&s);
    return 0;
}

static int dest_count_extras(const char *jbroot, const char *manifest_path,
                             dt_rootless_postverify_counts_t *out)
{
    relset_t s;
    unsigned long n_extra = 0;
    char err[DT_ROOTLESS_POSTVERIFY_ERR_MAX];
    err[0] = 0;
    if (relset_load(&s, manifest_path) != 0)
        return set_err(out->first_err, sizeof(out->first_err),
                       "payload path manifest missing/empty", "", NULL);
    if (dest_walk_extras(jbroot, "", &s, 0, &n_extra, err, sizeof(err)) != 0) {
        relset_free(&s);
        if (!out->first_err[0] && err[0])
            snprintf(out->first_err, sizeof(out->first_err), "%s", err);
        out->n_fail++;
        out->n_extra = n_extra;
        return -1;
    }
    relset_free(&s);
    out->n_extra = n_extra;
    if (n_extra) {
        out->n_fail++;
        if (!out->first_err[0])
            snprintf(out->first_err, sizeof(out->first_err), "%s",
                     err[0] ? err : "postverify dest extra");
        return -1;
    }
    return 0;
}

static int load_bearing_ok(const char *jbroot, dt_rootless_postverify_counts_t *out)
{
    static const char *must[] = {
        "Library/dpkg/status",
        "Library/LaunchDaemons/com.openssh.sshd.plist",
        "etc/ssh/sshd_config",
        "usr/sbin/sshd",
    };
    char path[PATH_MAX];
    struct stat st;
    FILE *f;
    char buf[4096];
    size_t got;
    int has_arch = 0;

    for (size_t i = 0; i < sizeof(must) / sizeof(must[0]); i++) {
        if (snprintf(path, sizeof(path), "%s/%s", jbroot, must[i]) >= (int)sizeof(path))
            return set_err(out->first_err, sizeof(out->first_err),
                           "postverify load-bearing missing %s", must[i], NULL);
        if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode))
            return set_err(out->first_err, sizeof(out->first_err),
                           "postverify load-bearing missing %s", must[i], NULL);
    }
    if (snprintf(path, sizeof(path), "%s/Library/dpkg/status", jbroot) >= (int)sizeof(path))
        return set_err(out->first_err, sizeof(out->first_err),
                       "postverify dpkg status truncated size=%s", "0", NULL);
    memset(&st, 0, sizeof(st));
    if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode) || st.st_size < 64) {
        char sz[32];
        snprintf(sz, sizeof(sz), "%lld", (long long)st.st_size);
        return set_err(out->first_err, sizeof(out->first_err),
                       "postverify dpkg status truncated size=%s", sz, NULL);
    }
    f = fopen(path, "r");
    if (!f)
        return set_err(out->first_err, sizeof(out->first_err),
                       "postverify dpkg status unreadable", "", NULL);
    while ((got = fread(buf, 1, sizeof(buf) - 1, f)) > 0) {
        buf[got] = '\0';
        if (strstr(buf, "Architecture: appletvos-arm64-rootless")) {
            has_arch = 1;
            break;
        }
    }
    fclose(f);
    if (!has_arch)
        return set_err(out->first_err, sizeof(out->first_err),
                       "postverify dpkg status missing appletvos-arm64-rootless", "", NULL);
    return 0;
}

int dt_rootless_postverify_payload_tree_c(const char *jbroot, const char *manifest_path,
                                          dt_rootless_postverify_counts_t *out)
{
    FILE *f;
    char line[4096];
    char hdrbuf[1024];
    char *hcols[16];
    int nh;
    int iRel = -1, iKind = -1, iTgt = -1, iSha = -1;
    char jb[PATH_MAX], man[PATH_MAX];

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (!jbroot || !jbroot[0] || !manifest_path || !manifest_path[0])
        return set_err(out->first_err, sizeof(out->first_err), "postverify args missing", "", NULL);

    snprintf(jb, sizeof(jb), "%s", jbroot);
    snprintf(man, sizeof(man), "%s", manifest_path);
    size_t L = strlen(jb);
    while (L > 1 && jb[L - 1] == '/')
        jb[--L] = '\0';

    f = fopen(man, "r");
    if (!f)
        return set_err(out->first_err, sizeof(out->first_err),
                       "payload path manifest missing/empty", "", NULL);
    if (!fgets(hdrbuf, sizeof(hdrbuf), f)) {
        fclose(f);
        return set_err(out->first_err, sizeof(out->first_err),
                       "payload path manifest empty", "", NULL);
    }
    hdrbuf[strcspn(hdrbuf, "\r\n")] = '\0';
    nh = split_tabs(hdrbuf, hcols, 16);
    for (int i = 0; i < nh; i++) {
        if (strcmp(hcols[i], "RELATIVE_PATH") == 0) iRel = i;
        else if (strcmp(hcols[i], "KIND") == 0) iKind = i;
        else if (strcmp(hcols[i], "SYMLINK_TARGET") == 0) iTgt = i;
        else if (strcmp(hcols[i], "SHA256") == 0) iSha = i;
    }
    if (iRel < 0 || iKind < 0) {
        fclose(f);
        return set_err(out->first_err, sizeof(out->first_err),
                       "payload path manifest columns missing", "", NULL);
    }

    while (fgets(line, sizeof(line), f)) {
        char *cols[16];
        int nc;
        const char *rel, *kind;
        char path[PATH_MAX];
        struct stat st;

        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0')
            continue;
        nc = split_tabs(line, cols, 16);
        if (nc <= iRel || nc <= iKind)
            continue;
        rel = cols[iRel];
        kind = cols[iKind];
        if (snprintf(path, sizeof(path), "%s/%s", jb, rel) >= (int)sizeof(path)) {
            out->n_fail++;
            out->n_missing++;
            if (!out->first_err[0])
                set_err(out->first_err, sizeof(out->first_err), "postverify missing %s", rel, NULL);
            continue;
        }
        if (lstat(path, &st) != 0) {
            out->n_fail++;
            out->n_missing++;
            if (!out->first_err[0])
                set_err(out->first_err, sizeof(out->first_err), "postverify missing %s", rel, NULL);
            continue;
        }
        if (strcmp(kind, "DIRECTORY") == 0) {
            if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
                out->n_fail++;
                if (!out->first_err[0])
                    set_err(out->first_err, sizeof(out->first_err),
                            "postverify type mismatch dir %s", rel, NULL);
            } else {
                out->n_dir++;
            }
        } else if (strcmp(kind, "SYMLINK") == 0) {
            if (!S_ISLNK(st.st_mode)) {
                out->n_fail++;
                out->n_type_symlink++;
                if (!out->first_err[0])
                    set_err(out->first_err, sizeof(out->first_err),
                            "postverify type mismatch symlink %s", rel, NULL);
            } else {
                const char *want = (iTgt >= 0 && nc > iTgt) ? cols[iTgt] : "";
                char got[PATH_MAX];
                ssize_t gn = readlink(path, got, sizeof(got) - 1);
                if (gn < 0)
                    got[0] = '\0';
                else
                    got[gn] = '\0';
                if (want[0] && strcmp(got, want) != 0) {
                    out->n_fail++;
                    if (!out->first_err[0]) {
                        snprintf(out->first_err, sizeof(out->first_err),
                                 "postverify symlink tgt %s -> %s want %s", rel, got, want);
                    }
                } else {
                    out->n_link++;
                }
            }
        } else if (strcmp(kind, "MACHO") == 0) {
            if (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
                out->n_fail++;
                out->n_macho_type++;
                if (!out->first_err[0])
                    set_err(out->first_err, sizeof(out->first_err),
                            "postverify type mismatch macho %s", rel, NULL);
            } else {
                const char *want = (iSha >= 0 && nc > iSha) ? cols[iSha] : "";
                if (strlen(want) == 64) {
                    char got[65];
                    if (sha256_file_nofollow(path, got, 0) != 0
                            || strcasecmp(got, want) != 0) {
                        out->n_fail++;
                        out->n_macho_sha++;
                        if (!out->first_err[0])
                            set_err(out->first_err, sizeof(out->first_err),
                                    "postverify macho sha %s", rel, NULL);
                    } else {
                        out->n_macho++;
                        out->n_file++;
                    }
                } else {
                    out->n_macho++;
                    out->n_file++;
                }
            }
        } else {
            if (S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode)) {
                out->n_fail++;
                if (!out->first_err[0])
                    set_err(out->first_err, sizeof(out->first_err),
                            "postverify type mismatch file %s", rel, NULL);
            } else {
                out->n_file++;
            }
        }
    }
    fclose(f);

    if (dest_count_extras(jb, manifest_path, out) != 0)
        return -1;
    if (out->n_fail)
        return -1;
    return load_bearing_ok(jb, out);
}
