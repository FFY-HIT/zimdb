/*
 * Pass A zone range scanner (C). Matches Python _scan_zone_range semantics.
 *
 * Build: gcc -O3 -march=native -o zone_scan zone_scan.c
 *
 * Usage:
 *   zone_scan <zone> <origin> <start> <end> <owners_dir> <spills_dir> \
 *             <worker_id> <spill_owners> <sort_chunk>
 *
 * Emits framed owner spills + RDATA spills (sorted by raw). Prints:
 *   owners=.. rrsets=.. refs=.. lines=.. skipped=.. spills=..
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blake2b16.h"

#define HASH_LEN 16
#define MAX_KEY 253
#define NTYPES 12
#define TYPE_MASK_BYTES 2

static const char *TYPE_NAMES[NTYPES] = {
    "A", "NS", "CNAME", "SOA", "MX", "TXT", "AAAA",
    "DS", "RRSIG", "NSEC3", "DNSKEY", "NSEC3PARAM"};

static void die(const char *msg) {
  perror(msg);
  exit(1);
}

static size_t encode_uleb(uint32_t v, uint8_t *out) {
  size_t n = 0;
  while (v >= 0x80) {
    out[n++] = (uint8_t)((v & 0x7f) | 0x80);
    v >>= 7;
  }
  out[n++] = (uint8_t)v;
  return n;
}

/* BOGI key: labels of relative name, reversed, each byte +1 (ASCII), 0 sep. */
static int owner_to_key(const char *owner, const char *origin, uint8_t *key,
                        size_t *key_len) {
  size_t olen = strlen(origin);
  size_t owlen = strlen(owner);
  if (owlen == olen && memcmp(owner, origin, olen) == 0) {
    *key_len = 0;
    return 0;
  }
  /* owner must end with "." + origin */
  if (owlen < olen + 1 || owner[owlen - olen - 1] != '.' ||
      memcmp(owner + owlen - olen, origin, olen) != 0)
    return -1;
  size_t rel_len = owlen - olen - 1;
  const char *rel = owner;
  /* collect labels */
  const char *labels[128];
  size_t llens[128];
  int nlab = 0;
  size_t i = 0;
  while (i < rel_len) {
    size_t j = i;
    while (j < rel_len && rel[j] != '.') j++;
    if (j == i || j - i > 63 || nlab >= 128) return -1;
    labels[nlab] = rel + i;
    llens[nlab] = j - i;
    nlab++;
    if (j >= rel_len) break;
    i = j + 1;
  }
  size_t pos = 0;
  for (int li = nlab - 1; li >= 0; li--) {
    for (size_t k = 0; k < llens[li]; k++) {
      unsigned char b = (unsigned char)labels[li][k];
      if (b >= 0x80 || (b >= 'A' && b <= 'Z')) return -1;
      if (pos >= MAX_KEY) return -1;
      key[pos++] = (uint8_t)(b + 1);
    }
    if (pos >= MAX_KEY) return -1;
    key[pos++] = 0;
  }
  *key_len = pos;
  return 0;
}

static int type_index(const char *up, size_t n) {
  for (int t = 0; t < NTYPES; t++) {
    size_t m = strlen(TYPE_NAMES[t]);
    if (m == n && memcmp(TYPE_NAMES[t], up, n) == 0) return t;
  }
  return -1;
}

typedef struct {
  uint8_t *data;
  size_t len, cap;
} Buf;

static void buf_init(Buf *b) {
  b->data = NULL;
  b->len = b->cap = 0;
}
static void buf_free(Buf *b) {
  free(b->data);
  buf_init(b);
}
static void buf_grow(Buf *b, size_t need) {
  if (need <= b->cap) return;
  size_t ncap = b->cap ? b->cap : 4096;
  while (ncap < need) ncap *= 2;
  uint8_t *p = realloc(b->data, ncap);
  if (!p) die("realloc");
  b->data = p;
  b->cap = ncap;
}
static void buf_append(Buf *b, const void *p, size_t n) {
  buf_grow(b, b->len + n);
  memcpy(b->data + b->len, p, n);
  b->len += n;
}
static void buf_clear(Buf *b) { b->len = 0; }

typedef struct {
  uint8_t *ptr;
  uint32_t len;
} Slice;

typedef struct {
  uint32_t ttl;
  int has;
  Slice *items;
  size_t n, cap;
} TypeBag;

typedef struct {
  char owner[512];
  int has_owner;
  uint8_t key[MAX_KEY];
  size_t key_len;
  TypeBag types[NTYPES];
} OwnerState;

static void owner_clear_rr(OwnerState *o) {
  for (int t = 0; t < NTYPES; t++) {
    TypeBag *tb = &o->types[t];
    for (size_t i = 0; i < tb->n; i++) free(tb->items[i].ptr);
    free(tb->items);
    tb->items = NULL;
    tb->n = tb->cap = 0;
    tb->has = 0;
    tb->ttl = 0;
  }
}

static void type_add(TypeBag *tb, uint32_t ttl, const uint8_t *raw, size_t raw_len) {
  if (!tb->has) {
    tb->has = 1;
    tb->ttl = ttl;
  }
  if (tb->n + 1 > tb->cap) {
    size_t ncap = tb->cap ? tb->cap * 2 : 4;
    Slice *p = realloc(tb->items, ncap * sizeof(Slice));
    if (!p) die("realloc items");
    tb->items = p;
    tb->cap = ncap;
  }
  uint8_t *copy = malloc(raw_len ? raw_len : 1);
  if (!copy) die("malloc raw");
  if (raw_len) memcpy(copy, raw, raw_len);
  tb->items[tb->n].ptr = copy;
  tb->items[tb->n].len = (uint32_t)raw_len;
  tb->n++;
}

static int cmp_slice(const void *a, const void *b) {
  const Slice *x = a, *y = b;
  uint32_t n = x->len < y->len ? x->len : y->len;
  int c = memcmp(x->ptr, y->ptr, n);
  if (c) return c;
  return (x->len > y->len) - (x->len < y->len);
}

/* Spill writer: framed recs, sort by raw on flush */
typedef struct {
  char dir[512];
  char prefix[64];
  Buf buf;
  Buf type_buf;
  size_t count;
  size_t sort_chunk;
  size_t nfiles;
  size_t ntype_files;
  char paths[512][512];
  size_t npaths;
} SpillW;

static void spill_init(SpillW *s, const char *dir, const char *prefix, size_t chunk) {
  memset(s, 0, sizeof(*s));
  snprintf(s->dir, sizeof(s->dir), "%s", dir);
  snprintf(s->prefix, sizeof(s->prefix), "%s", prefix);
  buf_init(&s->buf);
  buf_init(&s->type_buf);
  s->sort_chunk = chunk;
}

typedef struct {
  const uint8_t *frame;
  uint32_t frame_bytes;
  const uint8_t *raw;
  uint32_t raw_len;
} SpillPtr;

static int cmp_spill(const void *a, const void *b) {
  const SpillPtr *x = a, *y = b;
  uint32_t n = x->raw_len < y->raw_len ? x->raw_len : y->raw_len;
  int c = memcmp(x->raw, y->raw, n);
  if (c) return c;
  return (x->raw_len > y->raw_len) - (x->raw_len < y->raw_len);
}

static void spill_flush_types(SpillW *s) {
  if (!s->type_buf.len) return;
  char tpath[512];
  snprintf(tpath, sizeof(tpath), "%s/%s.type_%05zu.bin", s->dir, s->prefix,
           s->ntype_files);
  FILE *tout = fopen(tpath, "wb");
  if (!tout) die(tpath);
  if (fwrite(s->type_buf.data, 1, s->type_buf.len, tout) != s->type_buf.len)
    die("type spill write");
  fclose(tout);
  s->ntype_files++;
  buf_clear(&s->type_buf);
}

static void spill_flush(SpillW *s) {
  if (!s->buf.len && !s->type_buf.len) return;
  if (!s->buf.len) {
    spill_flush_types(s);
    return;
  }
  char path[512];
  snprintf(path, sizeof(path), "%s/%s_%05zu.bin", s->dir, s->prefix, s->nfiles);
  size_t ncap = s->count + 8;
  SpillPtr *ptrs = malloc(ncap * sizeof(SpillPtr));
  if (!ptrs) die("malloc spill ptrs");
  size_t n = 0, off = 0;
  const uint8_t *data = s->buf.data;
  size_t len = s->buf.len;
  const size_t RAW_OFF = HASH_LEN + 12;
  while (off + 4 <= len) {
    uint32_t ln;
    memcpy(&ln, data + off, 4);
    if (off + 4 + ln > len) break;
    uint32_t raw_len;
    memcpy(&raw_len, data + off + 4 + HASH_LEN + 8, 4);
    ptrs[n].frame = data + off;
    ptrs[n].frame_bytes = 4 + ln;
    ptrs[n].raw = data + off + 4 + RAW_OFF;
    ptrs[n].raw_len = raw_len;
    n++;
    off += 4 + ln;
  }
  qsort(ptrs, n, sizeof(SpillPtr), cmp_spill);
  FILE *out = fopen(path, "wb");
  if (!out) die(path);
  setvbuf(out, NULL, _IOFBF, 8 << 20);
  for (size_t i = 0; i < n; i++) {
    if (fwrite(ptrs[i].frame, 1, ptrs[i].frame_bytes, out) != ptrs[i].frame_bytes)
      die("spill write");
  }
  fclose(out);
  free(ptrs);
  if (s->npaths < 512)
    snprintf(s->paths[s->npaths++], sizeof(s->paths[0]), "%s", path);
  s->nfiles++;
  buf_clear(&s->buf);
  s->count = 0;
  spill_flush_types(s);
}

static void spill_add(SpillW *s, const uint8_t *h, uint32_t rrset_ord, uint32_t rdata_ord,
                      const uint8_t *raw, uint32_t raw_len, int type_idx) {
  uint32_t ln = HASH_LEN + 12 + raw_len;
  uint8_t hdr[4 + HASH_LEN + 12];
  memcpy(hdr, &ln, 4);
  memcpy(hdr + 4, h, HASH_LEN);
  memcpy(hdr + 4 + HASH_LEN, &rrset_ord, 4);
  memcpy(hdr + 4 + HASH_LEN + 4, &rdata_ord, 4);
  memcpy(hdr + 4 + HASH_LEN + 8, &raw_len, 4);
  buf_append(&s->buf, hdr, sizeof(hdr));
  buf_append(&s->buf, raw, raw_len);
  if (type_idx >= 0 && type_idx < NTYPES) {
    uint8_t tip[HASH_LEN + 1];
    memcpy(tip, h, HASH_LEN);
    tip[HASH_LEN] = (uint8_t)type_idx;
    buf_append(&s->type_buf, tip, sizeof(tip));
  }
  s->count++;
  if (s->count >= s->sort_chunk) spill_flush(s);
}

typedef struct {
  char dir[512];
  int worker_id;
  size_t spill_owners;
  FILE *fp;
  size_t owners_in_file;
  size_t file_index;
  char paths[1024][512];
  size_t npaths;
} OwnerW;

static void owner_open(OwnerW *w) {
  if (w->fp) fclose(w->fp);
  char path[512];
  snprintf(path, sizeof(path), "%s/w%02d_own_%05zu.bin", w->dir, w->worker_id,
           w->file_index);
  w->fp = fopen(path, "wb");
  if (!w->fp) die(path);
  setvbuf(w->fp, NULL, _IOFBF, 4 << 20);
  if (w->npaths < 1024)
    snprintf(w->paths[w->npaths++], sizeof(w->paths[0]), "%s", path);
  w->file_index++;
  w->owners_in_file = 0;
}

static void flush_owner(OwnerState *st, OwnerW *ow, SpillW *sw, uint32_t *rrset_count,
                        uint64_t *rdata_ref_count, uint64_t *owner_count) {
  if (!st->has_owner) return;
  uint8_t body[1 << 20];
  size_t body_len = 0;
  uint16_t mask = 0;
  int present[NTYPES];
  int np = 0;
  for (int t = 0; t < NTYPES; t++) {
    if (!st->types[t].has) continue;
    mask |= (uint16_t)(1u << t);
    present[np++] = t;
  }
  memcpy(body + body_len, &mask, TYPE_MASK_BYTES);
  body_len += TYPE_MASK_BYTES;

  uint8_t hash_blob[1 << 22];
  size_t hblen = 0;
  uint32_t local_rr = 0;
  for (int pi = 0; pi < np; pi++) {
    int t = present[pi];
    TypeBag *tb = &st->types[t];
    qsort(tb->items, tb->n, sizeof(Slice), cmp_slice);
    /* unique */
    size_t u = 0;
    for (size_t i = 0; i < tb->n; i++) {
      if (u > 0 && tb->items[u - 1].len == tb->items[i].len &&
          memcmp(tb->items[u - 1].ptr, tb->items[i].ptr, tb->items[i].len) == 0) {
        free(tb->items[i].ptr);
        tb->items[i].ptr = NULL;
        continue;
      }
      tb->items[u++] = tb->items[i];
    }
    tb->n = u;
    body_len += encode_uleb(tb->ttl, body + body_len);
    body_len += encode_uleb((uint32_t)tb->n, body + body_len);
    if (body_len > sizeof(body) - 64) {
      fprintf(stderr, "body overflow\n");
      exit(1);
    }
    for (size_t j = 0; j < tb->n; j++) {
      uint8_t h[HASH_LEN];
      blake2b16(tb->items[j].ptr, tb->items[j].len, h);
      if (hblen + HASH_LEN > sizeof(hash_blob)) {
        fprintf(stderr, "hash_blob overflow\n");
        exit(1);
      }
      memcpy(hash_blob + hblen, h, HASH_LEN);
      hblen += HASH_LEN;
      spill_add(sw, h, *rrset_count + local_rr, (uint32_t)j, tb->items[j].ptr,
                tb->items[j].len, t);
    }
    local_rr++;
    *rdata_ref_count += tb->n;
  }

  uint32_t klen = (uint32_t)st->key_len;
  uint32_t blen = (uint32_t)body_len;
  uint32_t hlen = (uint32_t)hblen;
  uint32_t rec_len = 12 + klen + blen + hlen;
  uint8_t hdr[12];
  memcpy(hdr, &klen, 4);
  memcpy(hdr + 4, &blen, 4);
  memcpy(hdr + 8, &hlen, 4);
  if (fwrite(&rec_len, 4, 1, ow->fp) != 1) die("owner write");
  if (fwrite(hdr, 12, 1, ow->fp) != 1) die("owner write");
  if (klen && fwrite(st->key, 1, klen, ow->fp) != klen) die("owner write");
  if (fwrite(body, 1, blen, ow->fp) != blen) die("owner write");
  if (hlen && fwrite(hash_blob, 1, hlen, ow->fp) != hlen) die("owner write");

  ow->owners_in_file++;
  if (ow->owners_in_file >= ow->spill_owners) owner_open(ow);
  (*owner_count)++;
  *rrset_count += local_rr;

  owner_clear_rr(st);
  st->has_owner = 0;
  st->owner[0] = 0;
}

/* uppercase ASCII in place into out; returns length */
static size_t tok_upper(const char *in, size_t n, char *out, size_t outcap) {
  if (n >= outcap) n = outcap - 1;
  for (size_t i = 0; i < n; i++) {
    char c = in[i];
    out[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
  }
  out[n] = 0;
  return n;
}

static int is_digits(const char *s, size_t n) {
  if (!n) return 0;
  for (size_t i = 0; i < n; i++)
    if (s[i] < '0' || s[i] > '9') return 0;
  return 1;
}

/*
 * Parse one RR line. owner_buf holds current/new owner (normalized lowercase + dot).
 * Returns 1 if RR, 0 if skip. Sets *rtype, *ttl, raw pointer into line buffer.
 */
static int parse_line(char *line, size_t linelen, char *owner_buf, size_t owner_cap,
                      int *has_owner, int *rtype, uint32_t *ttl, char **raw_out,
                      size_t *raw_len) {
  if (!linelen || line[0] == ';' || line[0] == '$') return 0;
  if (line[linelen - 1] == '\r') {
    line[--linelen] = 0;
    if (!linelen) return 0;
  }
  char *tokens[64];
  size_t tlen[64];
  int nt = 0;
  size_t i = 0;
  int cont = (line[0] == ' ' || line[0] == '\t');
  while (i < linelen && nt < 64) {
    while (i < linelen && (line[i] == ' ' || line[i] == '\t')) i++;
    if (i >= linelen) break;
    size_t j = i;
    while (j < linelen && line[j] != ' ' && line[j] != '\t') j++;
    tokens[nt] = line + i;
    tlen[nt] = j - i;
    nt++;
    i = j;
  }
  if (!nt) return 0;
  int ti = 0;
  if (!cont) {
    /* owner token */
    size_t n = tlen[0];
    if (n + 2 > owner_cap) return 0;
    for (size_t k = 0; k < n; k++) {
      char c = tokens[0][k];
      owner_buf[k] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    owner_buf[n] = 0;
    if (n == 0 || owner_buf[n - 1] != '.') {
      owner_buf[n++] = '.';
      owner_buf[n] = 0;
    }
    *has_owner = 1;
    ti = 1;
  } else {
    if (!*has_owner) return 0;
  }
  if (ti >= nt) return 0;
  *ttl = 0;
  int got_ttl = 0;
  while (ti < nt) {
    char up[64];
    size_t ul = tok_upper(tokens[ti], tlen[ti], up, sizeof(up));
    if (!got_ttl && is_digits(tokens[ti], tlen[ti])) {
      uint32_t v = 0;
      for (size_t k = 0; k < tlen[ti]; k++) v = v * 10 + (tokens[ti][k] - '0');
      *ttl = v;
      got_ttl = 1;
      ti++;
      continue;
    }
    if (ul == 2 && (memcmp(up, "IN", 2) == 0 || memcmp(up, "CH", 2) == 0 ||
                    memcmp(up, "HS", 2) == 0)) {
      ti++;
      continue;
    }
    int ti_idx = type_index(up, ul);
    if (ti_idx < 0) return 0;
    *rtype = ti_idx;
    ti++;
    /* rdata = " ".join(tokens[ti:]) — match Python split/join */
    if (ti >= nt) {
      *raw_out = line;
      *raw_len = 0;
      return 0;
    }
    /* reuse line buffer tail: build joined rdata at end of linebuf capacity —
     * caller provides line as writable buffer; write join into a scratch
     * region after the NUL. We instead join in-place overwriting from token0
     * area via memmove into a compact form at tokens[ti]. */
    static char rbuf[1 << 20];
    size_t rp = 0;
    for (int k = ti; k < nt; k++) {
      /* stop at comment token starting with ; */
      if (tlen[k] && tokens[k][0] == ';') break;
      if (rp && rp + 1 < sizeof(rbuf)) rbuf[rp++] = ' ';
      if (rp + tlen[k] >= sizeof(rbuf)) return 0;
      memcpy(rbuf + rp, tokens[k], tlen[k]);
      rp += tlen[k];
    }
    /* Python also strips " ;" inside joined string */
    for (size_t p = 0; p + 1 < rp; p++) {
      if (rbuf[p] == ' ' && rbuf[p + 1] == ';') {
        rp = p;
        break;
      }
    }
    while (rp > 0 && (rbuf[rp - 1] == ' ' || rbuf[rp - 1] == '\t')) rp--;
    rbuf[rp] = 0;
    *raw_out = rbuf;
    *raw_len = rp;
    return 1;
  }
  return 0;
}

static size_t align_start(const uint8_t *data, size_t size, size_t start) {
  if (start == 0) return 0;
  if (start > size) start = size;
  size_t p = start;
  if (p > 0) p--; /* look at prior byte */
  /* skip to after newline */
  while (p < size && data[p] != '\n') p++;
  if (p < size && data[p] == '\n') p++;
  return p;
}

int main(int argc, char **argv) {
  if (argc != 10) {
    fprintf(stderr,
            "usage: %s zone origin start end owners_dir spills_dir worker_id "
            "spill_owners sort_chunk\n",
            argv[0]);
    return 2;
  }
  const char *zone_path = argv[1];
  const char *origin = argv[2];
  size_t start = (size_t)strtoull(argv[3], NULL, 10);
  size_t end = (size_t)strtoull(argv[4], NULL, 10);
  const char *owners_dir = argv[5];
  const char *spills_dir = argv[6];
  int worker_id = atoi(argv[7]);
  size_t spill_owners = (size_t)strtoull(argv[8], NULL, 10);
  size_t sort_chunk = (size_t)strtoull(argv[9], NULL, 10);

  int fd = open(zone_path, O_RDONLY);
  if (fd < 0) die(zone_path);
  struct stat zst;
  if (fstat(fd, &zst) < 0) die("fstat");
  size_t zsize = (size_t)zst.st_size;
  uint8_t *zdata = mmap(NULL, zsize ? zsize : 1, PROT_READ, MAP_PRIVATE, fd, 0);
  if (zdata == MAP_FAILED) die("mmap");
  close(fd);

  size_t pos = align_start(zdata, zsize, start);

  OwnerW ow;
  memset(&ow, 0, sizeof(ow));
  snprintf(ow.dir, sizeof(ow.dir), "%s", owners_dir);
  ow.worker_id = worker_id;
  ow.spill_owners = spill_owners;
  owner_open(&ow);

  SpillW sw;
  char prefix[64];
  snprintf(prefix, sizeof(prefix), "w%02d_rdata", worker_id);
  spill_init(&sw, spills_dir, prefix, sort_chunk);

  OwnerState ost;
  memset(&ost, 0, sizeof(ost));
  uint32_t rrset_count = 0;
  uint64_t rdata_ref_count = 0, owner_count = 0;
  uint64_t lines = 0, skipped = 0;

  char linebuf[1 << 20];
  while (pos < zsize) {
    size_t line_start = pos;
    while (pos < zsize && zdata[pos] != '\n') pos++;
    size_t linelen = pos - line_start;
    if (pos < zsize) pos++; /* skip \n */
    lines++;

    if (linelen >= sizeof(linebuf)) {
      skipped++;
      continue;
    }
    memcpy(linebuf, zdata + line_start, linelen);
    linebuf[linelen] = 0;

    int rtype = -1;
    uint32_t ttl = 0;
    char *raw = NULL;
    size_t raw_len = 0;
    int had = ost.has_owner;
    char new_owner[512];
    if (had) snprintf(new_owner, sizeof(new_owner), "%s", ost.owner);
    else new_owner[0] = 0;
    int has = had;
    if (!parse_line(linebuf, linelen, new_owner, sizeof(new_owner), &has, &rtype,
                    &ttl, &raw, &raw_len)) {
      continue;
    }
    if (!raw_len) {
      skipped++;
      continue;
    }

    int new_own = had && strcmp(ost.owner, new_owner) != 0;
    /* A crossing line belongs to the range containing its first byte.
     * Finish the current owner beyond end; A2 coalesces overlap. */
    if (line_start >= end && new_own) break;
    if (line_start >= end && !had) break;

    if (new_own) {
      flush_owner(&ost, &ow, &sw, &rrset_count, &rdata_ref_count, &owner_count);
    }
    if (!ost.has_owner || strcmp(ost.owner, new_owner) != 0) {
      snprintf(ost.owner, sizeof(ost.owner), "%s", new_owner);
      ost.has_owner = 1;
      if (owner_to_key(ost.owner, origin, ost.key, &ost.key_len) != 0) {
        skipped++;
        ost.has_owner = 0;
        owner_clear_rr(&ost);
        continue;
      }
    }
    type_add(&ost.types[rtype], ttl, (const uint8_t *)raw, raw_len);
  }
  flush_owner(&ost, &ow, &sw, &rrset_count, &rdata_ref_count, &owner_count);
  spill_flush(&sw);
  if (ow.fp) fclose(ow.fp);
  buf_free(&sw.buf);
  munmap(zdata, zsize ? zsize : 1);

  printf("owners=%llu rrsets=%u refs=%llu lines=%llu skipped=%llu spills=%zu\n",
         (unsigned long long)owner_count, rrset_count,
         (unsigned long long)rdata_ref_count, (unsigned long long)lines,
         (unsigned long long)skipped, sw.nfiles);
  return 0;
}
