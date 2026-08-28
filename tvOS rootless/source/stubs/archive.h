#pragma once
/* Stub — libarchive only used by util.c tar helpers; phys-rw path does not call them. */
typedef struct archive archive;
typedef struct archive_entry archive_entry;
typedef struct archive_write_disk archive_write_disk;

static inline struct archive *archive_read_new(void) { return 0; }
static inline int archive_read_support_format_all(struct archive *a) { (void)a; return 0; }
static inline int archive_read_support_filter_all(struct archive *a) { (void)a; return 0; }
static inline struct archive_write_disk *archive_write_disk_new(void) { return 0; }
static inline int archive_write_disk_set_options(struct archive_write_disk *a, int f) { (void)a; (void)f; return 0; }
static inline int archive_write_disk_set_standard_lookup(struct archive_write_disk *a) { (void)a; return 0; }
static inline int archive_read_open_filename(struct archive *a, const char *p, int s) { (void)a; (void)p; (void)s; return -1; }
static inline int archive_read_next_header(struct archive *a, struct archive_entry **e) { (void)a; (void)e; return 1; }
static inline const char *archive_entry_pathname(struct archive_entry *e) { (void)e; return ""; }
static inline void archive_entry_set_pathname(struct archive_entry *e, const char *p) { (void)e; (void)p; }
static inline int archive_write_header(struct archive_write_disk *a, struct archive_entry *e) { (void)a; (void)e; return -1; }
static inline long long archive_entry_size(struct archive_entry *e) { (void)e; return 0; }
static inline int archive_read_data_block(struct archive *a, const void **b, size_t *s, long long *o) { (void)a; (void)b; (void)s; (void)o; return 1; }
static inline int archive_write_data_block(struct archive_write_disk *a, const void *b, size_t s, long long o) { (void)a; (void)b; (void)s; (void)o; return -1; }
static inline int archive_write_finish_entry(struct archive_write_disk *a) { (void)a; return 0; }
static inline int archive_read_close(struct archive *a) { (void)a; return 0; }
static inline int archive_read_free(struct archive *a) { (void)a; return 0; }
static inline int archive_write_close(struct archive_write_disk *a) { (void)a; return 0; }
static inline int archive_write_free(struct archive_write_disk *a) { (void)a; return 0; }
static inline const char *archive_error_string(void *a) { (void)a; return "archive stub"; }
