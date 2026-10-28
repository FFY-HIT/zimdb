/* Scatter (owner,j,rid) → flat u32[prefix[owner]+j] = rid.
 * Also: merge-sorted hash-ref join helper.
 *
 * Build: gcc -O3 -march=native -o join_scatter join_scatter.c
 *
 * Usage:
 *   join_scatter scatter <ids_flat.bin> <counts.bin> <out_ids_u32.bin>
 *   join_scatter sort16 <in.bin> <out.bin> <rec_size>   # sort by first 16 bytes
 *   join_scatter sort8  <in.bin> <out.bin> <rec_size>   # sort by first 8 bytes as u64 LE
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void die(const char *msg) {
  perror(msg);
  exit(1);
}

static void *map_file(const char *path, size_t *out_len, int writeable) {
  int fd = open(path, writeable ? O_RDWR : O_RDONLY);
  if (fd < 0) die(path);
  struct stat st;
  if (fstat(fd, &st) < 0) die("fstat");
  *out_len = (size_t)st.st_size;
  int prot = PROT_READ | (writeable ? PROT_WRITE : 0);
  void *p = mmap(NULL, *out_len ? *out_len : 1, prot, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) die("mmap");
  close(fd);
  return p;
}

static int cmp16_rec(const void *a, const void *b) {
  return memcmp(a, b, 16);
}

/* qsort on uint8_t* array: compare the 16-byte records pointed to */
static int cmp16_ptr(const void *a, const void *b) {
  const uint8_t *x = *(const uint8_t *const *)a;
  const uint8_t *y = *(const uint8_t *const *)b;
  return memcmp(x, y, 16);
}

typedef struct {
  uint64_t key;
  uint32_t idx;
} KeyIdx;

static int cmp_keyidx(const void *a, const void *b) {
  const KeyIdx *x = a, *y = b;
  if (x->key < y->key) return -1;
  if (x->key > y->key) return 1;
  return (x->idx > y->idx) - (x->idx < y->idx);
}

/* Parallel merge-sort of uint8_t* array by first 16 bytes. */
typedef struct {
  uint8_t **a;
  uint8_t **tmp;
  size_t lo, hi;
  int depth;
} PSortArg;

static void merge_ptrs(uint8_t **a, uint8_t **tmp, size_t lo, size_t mid, size_t hi) {
  size_t i = lo, j = mid, k = lo;
  while (i < mid && j < hi) {
    if (memcmp(a[i], a[j], 16) <= 0) tmp[k++] = a[i++];
    else tmp[k++] = a[j++];
  }
  while (i < mid) tmp[k++] = a[i++];
  while (j < hi) tmp[k++] = a[j++];
  for (k = lo; k < hi; k++) a[k] = tmp[k];
}

static void *psort_worker(void *arg);

static void psort_rec(uint8_t **a, uint8_t **tmp, size_t lo, size_t hi, int depth) {
  if (hi - lo <= 1) return;
  if (hi - lo < 100000 || depth <= 0) {
    qsort(a + lo, hi - lo, sizeof(uint8_t *), cmp16_ptr);
    return;
  }
  size_t mid = lo + (hi - lo) / 2;
  if (depth >= 1) {
    PSortArg left = {a, tmp, lo, mid, depth - 1};
    pthread_t th;
    if (pthread_create(&th, NULL, psort_worker, &left) == 0) {
      psort_rec(a, tmp, mid, hi, depth - 1);
      pthread_join(th, NULL);
    } else {
      psort_rec(a, tmp, lo, mid, depth - 1);
      psort_rec(a, tmp, mid, hi, depth - 1);
    }
  } else {
    psort_rec(a, tmp, lo, mid, 0);
    psort_rec(a, tmp, mid, hi, 0);
  }
  merge_ptrs(a, tmp, lo, mid, hi);
}

static void *psort_worker(void *arg) {
  PSortArg *p = arg;
  psort_rec(p->a, p->tmp, p->lo, p->hi, p->depth);
  return NULL;
}

/* In-memory sort of fixed records by first 16 bytes (parallel). */
static int sort_by_prefix16(const char *in_path, const char *out_path, size_t rec_size) {
  size_t len = 0;
  uint8_t *data = map_file(in_path, &len, 0);
  if (len % rec_size) {
    fprintf(stderr, "truncated: %zu %% %zu\n", len, rec_size);
    return 2;
  }
  size_t n = len / rec_size;
  uint8_t **ptrs = malloc(n * sizeof(uint8_t *));
  uint8_t **tmp = malloc(n * sizeof(uint8_t *));
  if (!ptrs || !tmp) die("malloc ptrs");
  for (size_t i = 0; i < n; i++) ptrs[i] = data + i * rec_size;
  long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
  int depth = 0;
  for (long c = ncpu > 0 ? ncpu : 1; c > 1; c >>= 1) depth++;
  if (depth > 4) depth = 4;
  fprintf(stderr, "sort16 parallel n=%zu rec=%zu depth=%d\n", n, rec_size, depth);
  psort_rec(ptrs, tmp, 0, n, depth);

  int out_fd = open(out_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (out_fd < 0) die(out_path);
  const size_t BUF = 16 << 20;
  uint8_t *buf = malloc(BUF);
  if (!buf) die("malloc buf");
  size_t used = 0;
  for (size_t i = 0; i < n; i++) {
    if (used + rec_size > BUF) {
      if (write(out_fd, buf, used) != (ssize_t)used) die("write");
      used = 0;
    }
    memcpy(buf + used, ptrs[i], rec_size);
    used += rec_size;
  }
  if (used && write(out_fd, buf, used) != (ssize_t)used) die("write");
  close(out_fd);
  free(buf);
  free(ptrs);
  free(tmp);
  munmap(data, len ? len : 1);
  return 0;
}

static int sort_by_u64(const char *in_path, const char *out_path, size_t rec_size) {
  size_t len = 0;
  uint8_t *data = map_file(in_path, &len, 0);
  if (len % rec_size) {
    fprintf(stderr, "truncated: %zu %% %zu\n", len, rec_size);
    return 2;
  }
  size_t n = len / rec_size;
  KeyIdx *keys = malloc(n * sizeof(KeyIdx));
  if (!keys) die("malloc keys");
  for (size_t i = 0; i < n; i++) {
    uint64_t k;
    memcpy(&k, data + i * rec_size, 8);
    keys[i].key = k;
    keys[i].idx = (uint32_t)i;
  }
  qsort(keys, n, sizeof(KeyIdx), cmp_keyidx);

  int out_fd = open(out_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (out_fd < 0) die(out_path);
  const size_t BUF = 8 << 20;
  uint8_t *buf = malloc(BUF);
  if (!buf) die("malloc buf");
  size_t used = 0;
  for (size_t i = 0; i < n; i++) {
    if (used + rec_size > BUF) {
      if (write(out_fd, buf, used) != (ssize_t)used) die("write");
      used = 0;
    }
    memcpy(buf + used, data + (size_t)keys[i].idx * rec_size, rec_size);
    used += rec_size;
  }
  if (used && write(out_fd, buf, used) != (ssize_t)used) die("write");
  close(out_fd);
  free(buf);
  free(keys);
  munmap(data, len ? len : 1);
  return 0;
}

typedef struct {
  const uint8_t *raw;
  uint32_t *flat;
  const uint32_t *counts;
  const uint32_t *prefix;
  size_t n_owners, lo, hi;
  int err;
} ScatterArg;

static void *scatter_worker(void *arg) {
  ScatterArg *a = arg;
  for (size_t i = a->lo; i < a->hi; i++) {
    uint32_t owner, j, rid;
    memcpy(&owner, a->raw + i * 12 + 0, 4);
    memcpy(&j, a->raw + i * 12 + 4, 4);
    memcpy(&rid, a->raw + i * 12 + 8, 4);
    if (owner >= a->n_owners || j >= a->counts[owner]) {
      a->err = 1;
      return NULL;
    }
    a->flat[a->prefix[owner] + j] = rid;
  }
  return NULL;
}

static int do_scatter(const char *ids_path, const char *counts_path, const char *out_path) {
  size_t ids_len = 0, counts_len = 0;
  const uint32_t *ids = map_file(ids_path, &ids_len, 0);
  const uint32_t *counts = map_file(counts_path, &counts_len, 0);
  if (ids_len % 12) {
    fprintf(stderr, "ids_flat not multiple of 12\n");
    return 2;
  }
  if (counts_len % 4) {
    fprintf(stderr, "counts not multiple of 4\n");
    return 2;
  }
  size_t n_owners = counts_len / 4;
  size_t n_recs = ids_len / 12;

  uint64_t total = 0;
  for (size_t i = 0; i < n_owners; i++) total += counts[i];
  if (total != n_recs) {
    fprintf(stderr, "total counts %llu != n_recs %zu\n",
            (unsigned long long)total, n_recs);
    return 2;
  }

  uint32_t *prefix = malloc(n_owners * sizeof(uint32_t));
  if (!prefix) die("malloc prefix");
  uint32_t run = 0;
  for (size_t i = 0; i < n_owners; i++) {
    prefix[i] = run;
    run += counts[i];
  }

  int out_fd = open(out_path, O_CREAT | O_RDWR | O_TRUNC, 0644);
  if (out_fd < 0) die(out_path);
  size_t out_bytes = (size_t)total * 4;
  if (ftruncate(out_fd, (off_t)out_bytes) < 0) die("ftruncate");
  uint32_t *flat = mmap(NULL, out_bytes ? out_bytes : 1, PROT_READ | PROT_WRITE,
                        MAP_SHARED, out_fd, 0);
  if (flat == MAP_FAILED) die("mmap out");
  close(out_fd);

  /* ids layout: owner u32, j u32, rid u32 — packed triples; parallel fill. */
  {
    const uint8_t *raw = (const uint8_t *)ids;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int nt = (int)(ncpu > 0 ? ncpu : 1);
    if (nt > 16) nt = 16;
    if (n_recs < 1000000) nt = 1;
    pthread_t th[16];
    ScatterArg args[16];
    size_t chunk = (n_recs + (size_t)nt - 1) / (size_t)nt;
    int launched = 0;
    for (int t = 0; t < nt; t++) {
      size_t lo = (size_t)t * chunk;
      if (lo >= n_recs) break;
      size_t hi = lo + chunk;
      if (hi > n_recs) hi = n_recs;
      args[t].raw = raw;
      args[t].flat = flat;
      args[t].counts = counts;
      args[t].prefix = prefix;
      args[t].n_owners = n_owners;
      args[t].lo = lo;
      args[t].hi = hi;
      args[t].err = 0;
      if (nt == 1) {
        scatter_worker(&args[t]);
      } else if (pthread_create(&th[t], NULL, scatter_worker, &args[t]) != 0) {
        scatter_worker(&args[t]);
      } else {
        launched++;
      }
    }
    for (int t = 0; t < launched; t++) pthread_join(th[t], NULL);
    for (int t = 0; t < nt && (size_t)t * chunk < n_recs; t++) {
      if (args[t].err) {
        fprintf(stderr, "bad owner/j in scatter\n");
        return 2;
      }
    }
  }

  /* Skip MS_SYNC — OS writeback; avoids multi-second sync of ~1.7 GiB. */
  munmap(flat, out_bytes ? out_bytes : 1);
  munmap((void *)ids, ids_len ? ids_len : 1);
  munmap((void *)counts, counts_len ? counts_len : 1);
  free(prefix);
  fprintf(stderr, "scatter ok owners=%zu refs=%zu\n", n_owners, n_recs);
  return 0;
}

/* Streaming k-way merge of pre-sorted runs (rec_size, key_len=16). */
static int merge_runs(char **run_paths, int n_runs, size_t rec_size, const char *out_path) {
  FILE **fps = calloc((size_t)n_runs, sizeof(FILE *));
  uint8_t **cur = calloc((size_t)n_runs, sizeof(uint8_t *));
  int *alive = calloc((size_t)n_runs, sizeof(int));
  if (!fps || !cur || !alive) die("calloc");
  for (int i = 0; i < n_runs; i++) {
    fps[i] = fopen(run_paths[i], "rb");
    if (!fps[i]) die(run_paths[i]);
    cur[i] = malloc(rec_size);
    if (!cur[i]) die("malloc rec");
    alive[i] = fread(cur[i], 1, rec_size, fps[i]) == rec_size;
  }
  FILE *out = fopen(out_path, "wb");
  if (!out) die(out_path);
  setvbuf(out, NULL, _IOFBF, 8 << 20);

  for (;;) {
    int best = -1;
    for (int i = 0; i < n_runs; i++) {
      if (!alive[i]) continue;
      if (best < 0 || memcmp(cur[i], cur[best], 16) < 0) best = i;
    }
    if (best < 0) break;
    if (fwrite(cur[best], 1, rec_size, out) != rec_size) die("fwrite");
    alive[best] = fread(cur[best], 1, rec_size, fps[best]) == rec_size;
  }
  for (int i = 0; i < n_runs; i++) {
    fclose(fps[i]);
    free(cur[i]);
  }
  fclose(out);
  free(fps);
  free(cur);
  free(alive);
  return 0;
}

/* External sort: split into ~512MB runs, qsort each, merge. */
static int external_sort16(const char *in_path, const char *out_path, size_t rec_size,
                           const char *tmpdir) {
  const size_t RUN_BYTES = 512ULL << 20;
  size_t run_recs = RUN_BYTES / rec_size;
  if (run_recs < 1) run_recs = 1;

  FILE *in = fopen(in_path, "rb");
  if (!in) die(in_path);
  char **runs = NULL;
  int n_runs = 0, cap = 0;
  uint8_t *buf = malloc(run_recs * rec_size);
  if (!buf) die("malloc run buf");

  for (;;) {
    size_t got = fread(buf, rec_size, run_recs, in);
    if (got == 0) break;
    uint8_t **ptrs = malloc(got * sizeof(uint8_t *));
    if (!ptrs) die("malloc ptrs");
    for (size_t i = 0; i < got; i++) ptrs[i] = buf + i * rec_size;
    qsort(ptrs, got, sizeof(uint8_t *), cmp16_ptr);

    if (n_runs + 1 > cap) {
      cap = cap ? cap * 2 : 16;
      runs = realloc(runs, (size_t)cap * sizeof(char *));
      if (!runs) die("realloc runs");
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/run_%05d.bin", tmpdir, n_runs);
    runs[n_runs] = strdup(path);
    FILE *rf = fopen(path, "wb");
    if (!rf) die(path);
    for (size_t i = 0; i < got; i++) {
      if (fwrite(ptrs[i], 1, rec_size, rf) != rec_size) die("run write");
    }
    fclose(rf);
    free(ptrs);
    n_runs++;
    fprintf(stderr, "sorted run %d (%zu recs)\n", n_runs, got);
  }
  fclose(in);
  free(buf);

  if (n_runs == 0) {
    FILE *out = fopen(out_path, "wb");
    if (!out) die(out_path);
    fclose(out);
    return 0;
  }
  if (n_runs == 1) {
    if (rename(runs[0], out_path) != 0) {
      /* cross-device: copy */
      FILE *a = fopen(runs[0], "rb");
      FILE *b = fopen(out_path, "wb");
      if (!a || !b) die("rename fallback");
      uint8_t tmp[1 << 20];
      size_t n;
      while ((n = fread(tmp, 1, sizeof(tmp), a)) > 0) {
        if (fwrite(tmp, 1, n, b) != n) die("copy");
      }
      fclose(a);
      fclose(b);
      unlink(runs[0]);
    }
    free(runs[0]);
    free(runs);
    return 0;
  }
  int rc = merge_runs(runs, n_runs, rec_size, out_path);
  for (int i = 0; i < n_runs; i++) {
    unlink(runs[i]);
    free(runs[i]);
  }
  free(runs);
  return rc;
}

/* Expand hash_refs.bin → ref_rows.bin
 * Input: repeated (owner u32, count u32, hash16 * count)
 * Output: repeated (hash16, owner u32, j u32, pad u32=0)  = 28 bytes
 */
static int expand_refs(const char *in_path, const char *out_path, const char *counts_out) {
  FILE *in = fopen(in_path, "rb");
  if (!in) die(in_path);
  FILE *out = fopen(out_path, "wb");
  if (!out) die(out_path);
  setvbuf(in, NULL, _IOFBF, 16 << 20);
  setvbuf(out, NULL, _IOFBF, 16 << 20);

  FILE *cf = fopen(counts_out, "wb");
  if (!cf) die(counts_out);
  setvbuf(cf, NULL, _IOFBF, 4 << 20);

  uint32_t owner_i = 0;
  uint8_t hdr[8];
  uint8_t *hashbuf = NULL;
  size_t hashcap = 0;
  uint8_t row[28];
  memset(row + 24, 0, 4); /* pad */

  while (fread(hdr, 1, 8, in) == 8) {
    uint32_t owner, count;
    memcpy(&owner, hdr, 4);
    memcpy(&count, hdr + 4, 4);
    if (owner != owner_i) {
      fprintf(stderr, "owner order %u != %u\n", owner, owner_i);
      return 2;
    }
    size_t need = (size_t)count * 16;
    if (need > hashcap) {
      hashcap = need < (1 << 20) ? (1 << 20) : need;
      hashbuf = realloc(hashbuf, hashcap);
      if (!hashbuf) die("realloc hashbuf");
    }
    if (fread(hashbuf, 1, need, in) != need) {
      fprintf(stderr, "truncated hashes owner=%u\n", owner);
      return 2;
    }
    if (fwrite(&count, 4, 1, cf) != 1) die("counts write");
    for (uint32_t j = 0; j < count; j++) {
      memcpy(row, hashbuf + (size_t)j * 16, 16);
      memcpy(row + 16, &owner, 4);
      memcpy(row + 20, &j, 4);
      if (fwrite(row, 1, 28, out) != 28) die("row write");
    }
    owner_i++;
    if ((owner_i % 10000000u) == 0)
      fprintf(stderr, "expand owners=%u\n", owner_i);
  }
  free(hashbuf);
  fclose(in);
  fclose(out);
  fclose(cf);
  fprintf(stderr, "expand done owners=%u\n", owner_i);
  return 0;
}

/* Decode/encode unsigned LEB128. Returns bytes consumed; -1 on error. */
static int rd_uleb(const uint8_t *p, const uint8_t *end, uint64_t *out) {
  uint64_t v = 0;
  unsigned shift = 0;
  int n = 0;
  while (p < end) {
    uint8_t b = *p++;
    n++;
    v |= (uint64_t)(b & 0x7f) << shift;
    if ((b & 0x80) == 0) {
      *out = v;
      return n;
    }
    shift += 7;
    if (shift > 63) return -1;
  }
  return -1;
}

static int wr_uleb(uint8_t *dst, uint64_t v) {
  int n = 0;
  do {
    uint8_t b = (uint8_t)(v & 0x7f);
    v >>= 7;
    if (v) b |= 0x80;
    dst[n++] = b;
  } while (v);
  return n;
}

/* bodies.bin: repeated <III klen,blen,pad> + key + body
 * counts.bin: uint32 n_ids per owner
 * ids_u32.bin: flat uint32 pool ids
 * Writes owner_stream.bin + owner_restarts.bin (uint64 LE offsets every 16).
 * stdout: single line "stream_len=<n> owners=<n>"
 */
static int stream_rewrite(const char *bodies_path, const char *counts_path,
                          const char *ids_path, const char *stream_path,
                          const char *restarts_path) {
  const size_t MASK_BYTES = 2;
  const size_t NTYPES = 12;
  const size_t BLOCK = 16;
  size_t blen = 0, clen = 0, ilen = 0;
  uint8_t *bodies = map_file(bodies_path, &blen, 0);
  uint32_t *counts = map_file(counts_path, &clen, 0);
  uint32_t *ids = map_file(ids_path, &ilen, 0);
  if (clen % 4 || ilen % 4) {
    fprintf(stderr, "counts/ids size\n");
    return 2;
  }
  size_t n_owners = clen / 4;
  FILE *out = fopen(stream_path, "wb");
  FILE *rst = fopen(restarts_path, "wb");
  if (!out || !rst) die("fopen stream");
  uint8_t *obuf = malloc(1 << 20);
  if (!obuf) die("malloc obuf");
  size_t ocap = 1 << 20;
  size_t stream_len = 0;
  size_t id_cursor = 0;
  size_t bpos = 0;
  for (size_t seen = 0; seen < n_owners; seen++) {
    if (bpos + 12 > blen) {
      fprintf(stderr, "bodies trunc at owner %zu\n", seen);
      return 2;
    }
    uint32_t klen, body_len, pad;
    memcpy(&klen, bodies + bpos, 4);
    memcpy(&body_len, bodies + bpos + 4, 4);
    memcpy(&pad, bodies + bpos + 8, 4);
    (void)pad;
    bpos += 12;
    if (bpos + klen + body_len > blen) {
      fprintf(stderr, "bodies trunc payload owner %zu\n", seen);
      return 2;
    }
    const uint8_t *key = bodies + bpos;
    bpos += klen;
    const uint8_t *body = bodies + bpos;
    bpos += body_len;
    uint32_t n_ids = counts[seen];
    if ((seen % BLOCK) == 0) {
      uint64_t off = (uint64_t)stream_len;
      if (fwrite(&off, 8, 1, rst) != 1) die("restart write");
    }
    if (body_len < MASK_BYTES) {
      fprintf(stderr, "short body %zu\n", seen);
      return 2;
    }
    /* out_body grows: mask + ttl/count ulebs + id ulebs */
    size_t need = body_len + (size_t)n_ids * 10 + 16;
    if (need > ocap) {
      ocap = need + (1 << 20);
      obuf = realloc(obuf, ocap);
      if (!obuf) die("realloc obuf");
    }
    size_t o = 0;
    memcpy(obuf, body, MASK_BYTES);
    o = MASK_BYTES;
    size_t ip = 0;
    size_t bp = MASK_BYTES;
    uint16_t mask;
    memcpy(&mask, body, 2);
    for (size_t bit = 0; bit < NTYPES; bit++) {
      if ((mask & (uint16_t)(1u << bit)) == 0) continue;
      uint64_t ttl = 0, count = 0;
      int u1 = rd_uleb(body + bp, body + body_len, &ttl);
      if (u1 < 0) return 2;
      bp += (size_t)u1;
      o += (size_t)wr_uleb(obuf + o, ttl);
      int u2 = rd_uleb(body + bp, body + body_len, &count);
      if (u2 < 0) return 2;
      bp += (size_t)u2;
      o += (size_t)wr_uleb(obuf + o, count);
      for (uint64_t j = 0; j < count; j++) {
        if (id_cursor + ip >= ilen / 4) {
          fprintf(stderr, "ids underrun owner=%zu\n", seen);
          return 2;
        }
        o += (size_t)wr_uleb(obuf + o, ids[id_cursor + ip]);
        ip++;
      }
    }
    if (ip != n_ids || bp != body_len) {
      fprintf(stderr, "body/id mismatch owner=%zu ip=%zu n_ids=%u bp=%zu blen=%u\n",
              seen, ip, n_ids, bp, body_len);
      return 2;
    }
    id_cursor += n_ids;
    /* piece = key + uleb(len(out_body)) + out_body */
    uint8_t lenbuf[10];
    int ln = wr_uleb(lenbuf, (uint64_t)o);
    if (fwrite(key, 1, klen, out) != klen) die("key write");
    if (fwrite(lenbuf, 1, (size_t)ln, out) != (size_t)ln) die("len write");
    if (fwrite(obuf, 1, o, out) != o) die("body write");
    stream_len += klen + (size_t)ln + o;
    if ((seen + 1) % 5000000u == 0)
      fprintf(stderr, "stream owners=%zu bytes=%zu\n", seen + 1, stream_len);
  }
  if (bpos != blen) {
    fprintf(stderr, "bodies trailing %zu / %zu\n", bpos, blen);
    return 2;
  }
  free(obuf);
  fclose(out);
  fclose(rst);
  munmap(bodies, blen ? blen : 1);
  munmap(counts, clen ? clen : 1);
  munmap(ids, ilen ? ilen : 1);
  printf("stream_len=%zu owners=%zu\n", stream_len, n_owners);
  return 0;
}

/* ---- MemAvailable (kB) ---- */
static long mem_available_kb(void) {
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f) return 8L << 20;
  char line[256];
  long v = 8L << 20;
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "MemAvailable: %ld kB", &v) == 1) break;
  }
  fclose(f);
  return v;
}

/* ---- coalesce: merge same-key fragments + front-code into own_*.bin ----
 * Args: coalesce <sorted_framed> <out_dir> <block_size> <spill_owners> <mask_bytes>
 * stdout: owners=N rrsets=N refs=N front=N uncomp=N fragments=N merges=N
 *
 * Fast path (no merge): copy body/hashes, only rewrite key as front-coded.
 * Merges are rare on .com (~4); full parse/merge implemented for correctness.
 */
typedef struct {
  uint8_t *key;
  uint32_t klen;
  uint8_t *body;
  uint32_t blen;
  uint8_t *hashes;
  uint32_t hlen;
  int owned; /* if 1, free key/body/hashes on clear */
} OwnRec;

static void own_clear(OwnRec *r) {
  if (r->owned) {
    free(r->key);
    free(r->body);
    free(r->hashes);
  }
  memset(r, 0, sizeof(*r));
}

static size_t common_prefix(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
  size_t n = na < nb ? na : nb;
  size_t i = 0;
  while (i < n && a[i] == b[i]) i++;
  return i;
}

/* popcount16 */
static int popcount16(uint16_t x) {
  int n = 0;
  while (x) {
    n += x & 1;
    x >>= 1;
  }
  return n;
}

/* Merge two owner bodies (same key). Allocates new body+hashes into *out.
 * Returns 0 ok, -1 on parse error. */
static int merge_owner_bodies(const OwnRec *a, const OwnRec *b, OwnRec *out,
                              size_t mask_bytes, size_t hash_len) {
  if (a->blen < mask_bytes || b->blen < mask_bytes) return -1;
  uint16_t ma = 0, mb = 0;
  memcpy(&ma, a->body, mask_bytes > 2 ? 2 : mask_bytes);
  memcpy(&mb, b->body, mask_bytes > 2 ? 2 : mask_bytes);
  /* Decode into per-type (ttl, hash list). Max 16 types. */
  typedef struct {
    int present;
    uint64_t ttl;
    uint8_t *hs;
    uint32_t n;
    uint32_t cap;
  } Slot;
  Slot slots[16];
  memset(slots, 0, sizeof(slots));

  for (int pass = 0; pass < 2; pass++) {
    const OwnRec *src = pass == 0 ? a : b;
    uint16_t mask = 0;
    memcpy(&mask, src->body, 2);
    size_t bp = mask_bytes;
    size_t hp = 0;
    for (int bit = 0; bit < 16; bit++) {
      if ((mask & (uint16_t)(1u << bit)) == 0) continue;
      uint64_t ttl = 0, count = 0;
      int u1 = rd_uleb(src->body + bp, src->body + src->blen, &ttl);
      if (u1 < 0) return -1;
      bp += (size_t)u1;
      int u2 = rd_uleb(src->body + bp, src->body + src->blen, &count);
      if (u2 < 0) return -1;
      bp += (size_t)u2;
      if (hp + count * hash_len > src->hlen) return -1;
      if (!slots[bit].present) {
        slots[bit].present = 1;
        slots[bit].ttl = ttl;
        slots[bit].cap = (uint32_t)count + 8;
        slots[bit].hs = malloc(slots[bit].cap * hash_len);
        if (!slots[bit].hs) die("malloc hs");
        memcpy(slots[bit].hs, src->hashes + hp, count * hash_len);
        slots[bit].n = (uint32_t)count;
      } else {
        /* union hashes (keep first ttl) */
        for (uint64_t j = 0; j < count; j++) {
          const uint8_t *h = src->hashes + hp + j * hash_len;
          int found = 0;
          for (uint32_t k = 0; k < slots[bit].n; k++) {
            if (memcmp(slots[bit].hs + k * hash_len, h, hash_len) == 0) {
              found = 1;
              break;
            }
          }
          if (!found) {
            if (slots[bit].n + 1 > slots[bit].cap) {
              slots[bit].cap *= 2;
              slots[bit].hs = realloc(slots[bit].hs, slots[bit].cap * hash_len);
              if (!slots[bit].hs) die("realloc hs");
            }
            memcpy(slots[bit].hs + slots[bit].n * hash_len, h, hash_len);
            slots[bit].n++;
          }
        }
        /* sort hashes lexicographically to match Python sorted(set(...)) */
        for (uint32_t i = 0; i + 1 < slots[bit].n; i++) {
          for (uint32_t j = i + 1; j < slots[bit].n; j++) {
            if (memcmp(slots[bit].hs + i * hash_len, slots[bit].hs + j * hash_len,
                       hash_len) > 0) {
              uint8_t tmp[64];
              if (hash_len > sizeof(tmp)) return -1;
              memcpy(tmp, slots[bit].hs + i * hash_len, hash_len);
              memcpy(slots[bit].hs + i * hash_len, slots[bit].hs + j * hash_len,
                     hash_len);
              memcpy(slots[bit].hs + j * hash_len, tmp, hash_len);
            }
          }
        }
      }
      hp += (size_t)count * hash_len;
    }
    if (bp != src->blen || hp != src->hlen) return -1;
  }

  /* Pack */
  uint16_t out_mask = 0;
  size_t total_refs = 0;
  for (int bit = 0; bit < 16; bit++) {
    if (slots[bit].present) {
      out_mask |= (uint16_t)(1u << bit);
      total_refs += slots[bit].n;
    }
  }
  uint8_t *body = malloc(64 + total_refs * 16);
  uint8_t *hashes = malloc(total_refs * hash_len + 1);
  if (!body || !hashes) die("malloc merge out");
  size_t bo = 0, ho = 0;
  memcpy(body, &out_mask, 2);
  bo = 2;
  for (int bit = 0; bit < 16; bit++) {
    if (!slots[bit].present) continue;
    bo += (size_t)wr_uleb(body + bo, slots[bit].ttl);
    bo += (size_t)wr_uleb(body + bo, slots[bit].n);
    memcpy(hashes + ho, slots[bit].hs, slots[bit].n * hash_len);
    ho += slots[bit].n * hash_len;
    free(slots[bit].hs);
  }
  out->key = malloc(a->klen);
  if (!out->key) die("malloc key");
  memcpy(out->key, a->key, a->klen);
  out->klen = a->klen;
  out->body = body;
  out->blen = (uint32_t)bo;
  out->hashes = hashes;
  out->hlen = (uint32_t)ho;
  out->owned = 1;
  return 0;
}

static int do_coalesce(const char *sorted_path, const char *out_dir, size_t block_size,
                       size_t spill_owners, size_t mask_bytes) {
  const size_t HASH_LEN = 16;
  FILE *in = fopen(sorted_path, "rb");
  if (!in) die(sorted_path);
  setvbuf(in, NULL, _IOFBF, 16 << 20);

  char pathbuf[512];
  int shard = 0;
  size_t owners_in_file = 0;
  snprintf(pathbuf, sizeof(pathbuf), "%s/own_%05d.bin", out_dir, shard);
  FILE *out = fopen(pathbuf, "wb");
  if (!out) die(pathbuf);
  setvbuf(out, NULL, _IOFBF, 8 << 20);

  OwnRec pending;
  memset(&pending, 0, sizeof(pending));
  uint8_t *prior_key = NULL;
  uint32_t prior_klen = 0;

  uint64_t owner_count = 0, rrset_count = 0, rdata_ref_count = 0;
  uint64_t front_coded = 0, uncompressed = 0, fragments = 0, merges = 0;

  uint8_t *recbuf = NULL;
  size_t reccap = 0;
  uint8_t keyenc[512];
  uint8_t hdr4[4];

  for (;;) {
    if (fread(hdr4, 1, 4, in) != 4) break;
    uint32_t ln;
    memcpy(&ln, hdr4, 4);
    if (ln > reccap) {
      reccap = ln + (1 << 20);
      recbuf = realloc(recbuf, reccap);
      if (!recbuf) die("realloc rec");
    }
    if (fread(recbuf, 1, ln, in) != ln) {
      fprintf(stderr, "framed truncate\n");
      return 2;
    }
    fragments++;
    if (ln < 12) return 2;
    uint32_t klen, blen, hlen;
    memcpy(&klen, recbuf + 0, 4);
    memcpy(&blen, recbuf + 4, 4);
    memcpy(&hlen, recbuf + 8, 4);
    if (12u + klen + blen + hlen != ln) {
      fprintf(stderr, "bad owner rec lens\n");
      return 2;
    }
    uint8_t *key = recbuf + 12;
    uint8_t *body = key + klen;
    uint8_t *hashes = body + blen;

    OwnRec cur;
    cur.key = key;
    cur.klen = klen;
    cur.body = body;
    cur.blen = blen;
    cur.hashes = hashes;
    cur.hlen = hlen;
    cur.owned = 0;

    if (!pending.key) {
      /* take ownership copy so buffer can be reused */
      pending.key = malloc(klen);
      pending.body = malloc(blen);
      pending.hashes = malloc(hlen ? hlen : 1);
      if (!pending.key || !pending.body || !pending.hashes) die("malloc pending");
      memcpy(pending.key, key, klen);
      memcpy(pending.body, body, blen);
      if (hlen) memcpy(pending.hashes, hashes, hlen);
      pending.klen = klen;
      pending.blen = blen;
      pending.hlen = hlen;
      pending.owned = 1;
      continue;
    }

    if (pending.klen == klen && memcmp(pending.key, key, klen) == 0) {
      OwnRec merged;
      memset(&merged, 0, sizeof(merged));
      if (merge_owner_bodies(&pending, &cur, &merged, mask_bytes, HASH_LEN) != 0) {
        fprintf(stderr, "merge failed at fragment %llu\n",
                (unsigned long long)fragments);
        return 2;
      }
      own_clear(&pending);
      pending = merged;
      merges++;
      continue;
    }

    /* emit pending */
    {
      /* front-code key */
      uint8_t full[512];
      int flen = wr_uleb(full, pending.klen);
      if (pending.klen + (size_t)flen > sizeof(full)) return 2;
      memcpy(full + flen, pending.key, pending.klen);
      flen += (int)pending.klen;
      uncompressed += (uint64_t)flen;

      int elen = 0;
      if ((owner_count % block_size) == 0) {
        memcpy(keyenc, full, (size_t)flen);
        elen = flen;
      } else {
        size_t shared = common_prefix(prior_key, prior_klen, pending.key, pending.klen);
        size_t suffix = pending.klen - shared;
        elen = wr_uleb(keyenc, shared);
        elen += wr_uleb(keyenc + elen, suffix);
        memcpy(keyenc + elen, pending.key + shared, suffix);
        elen += (int)suffix;
      }
      front_coded += (uint64_t)elen;
      free(prior_key);
      prior_key = malloc(pending.klen);
      if (!prior_key) die("prior");
      memcpy(prior_key, pending.key, pending.klen);
      prior_klen = pending.klen;

      uint16_t mask = 0;
      if (pending.blen >= 2) memcpy(&mask, pending.body, 2);
      uint32_t n_rr = (uint32_t)popcount16(mask);
      uint32_t n_ref = pending.hlen / (uint32_t)HASH_LEN;
      rrset_count += n_rr;
      rdata_ref_count += n_ref;

      uint32_t ek = (uint32_t)elen;
      uint32_t rec_len = 12 + ek + pending.blen + pending.hlen;
      uint8_t rh[4];
      memcpy(rh, &rec_len, 4);
      if (fwrite(rh, 1, 4, out) != 4) die("write");
      uint8_t lens[12];
      memcpy(lens + 0, &ek, 4);
      memcpy(lens + 4, &pending.blen, 4);
      memcpy(lens + 8, &pending.hlen, 4);
      if (fwrite(lens, 1, 12, out) != 12) die("write");
      if (fwrite(keyenc, 1, ek, out) != ek) die("write");
      if (fwrite(pending.body, 1, pending.blen, out) != pending.blen) die("write");
      if (pending.hlen &&
          fwrite(pending.hashes, 1, pending.hlen, out) != pending.hlen)
        die("write");

      owner_count++;
      owners_in_file++;
      if (owners_in_file >= spill_owners) {
        fclose(out);
        shard++;
        owners_in_file = 0;
        snprintf(pathbuf, sizeof(pathbuf), "%s/own_%05d.bin", out_dir, shard);
        out = fopen(pathbuf, "wb");
        if (!out) die(pathbuf);
        setvbuf(out, NULL, _IOFBF, 8 << 20);
      }
      if (owner_count % 5000000ull == 0)
        fprintf(stderr, "coalesce owners=%llu merges=%llu\n",
                (unsigned long long)owner_count, (unsigned long long)merges);
    }
    own_clear(&pending);
    pending.key = malloc(klen);
    pending.body = malloc(blen);
    pending.hashes = malloc(hlen ? hlen : 1);
    if (!pending.key || !pending.body || !pending.hashes) die("malloc pending2");
    memcpy(pending.key, key, klen);
    memcpy(pending.body, body, blen);
    if (hlen) memcpy(pending.hashes, hashes, hlen);
    pending.klen = klen;
    pending.blen = blen;
    pending.hlen = hlen;
    pending.owned = 1;
  }

  /* flush last */
  if (pending.key) {
    uint8_t full[512];
    int flen = wr_uleb(full, pending.klen);
    memcpy(full + flen, pending.key, pending.klen);
    flen += (int)pending.klen;
    uncompressed += (uint64_t)flen;
    int elen = 0;
    if ((owner_count % block_size) == 0) {
      memcpy(keyenc, full, (size_t)flen);
      elen = flen;
    } else {
      size_t shared = common_prefix(prior_key, prior_klen, pending.key, pending.klen);
      size_t suffix = pending.klen - shared;
      elen = wr_uleb(keyenc, shared);
      elen += wr_uleb(keyenc + elen, suffix);
      memcpy(keyenc + elen, pending.key + shared, suffix);
      elen += (int)suffix;
    }
    front_coded += (uint64_t)elen;
    uint16_t mask = 0;
    if (pending.blen >= 2) memcpy(&mask, pending.body, 2);
    rrset_count += (uint64_t)popcount16(mask);
    rdata_ref_count += pending.hlen / HASH_LEN;
    uint32_t ek = (uint32_t)elen;
    uint32_t rec_len = 12 + ek + pending.blen + pending.hlen;
    uint8_t rh[4];
    memcpy(rh, &rec_len, 4);
    fwrite(rh, 1, 4, out);
    uint8_t lens[12];
    memcpy(lens + 0, &ek, 4);
    memcpy(lens + 4, &pending.blen, 4);
    memcpy(lens + 8, &pending.hlen, 4);
    fwrite(lens, 1, 12, out);
    fwrite(keyenc, 1, ek, out);
    fwrite(pending.body, 1, pending.blen, out);
    if (pending.hlen) fwrite(pending.hashes, 1, pending.hlen, out);
    owner_count++;
    own_clear(&pending);
  }

  fclose(out);
  fclose(in);
  free(recbuf);
  free(prior_key);
  printf("owners=%llu rrsets=%llu refs=%llu front=%llu uncomp=%llu fragments=%llu "
         "merges=%llu\n",
         (unsigned long long)owner_count, (unsigned long long)rrset_count,
         (unsigned long long)rdata_ref_count, (unsigned long long)front_coded,
         (unsigned long long)uncompressed, (unsigned long long)fragments,
         (unsigned long long)merges);
  return 0;
}

/* d1_split: paths_file (one owner spill path per line) → bodies.bin + hash_refs.bin
 * stdout: owners=N
 */
static int do_d1_split(const char *paths_file, const char *bodies_path,
                       const char *hash_refs_path) {
  FILE *list = fopen(paths_file, "r");
  if (!list) die(paths_file);
  FILE *bodies = fopen(bodies_path, "wb");
  FILE *hrefs = fopen(hash_refs_path, "wb");
  if (!bodies || !hrefs) die("d1 out");
  setvbuf(bodies, NULL, _IOFBF, 16 << 20);
  setvbuf(hrefs, NULL, _IOFBF, 16 << 20);

  char line[1024];
  uint64_t seen = 0;
  uint8_t *recbuf = NULL;
  size_t reccap = 0;
  while (fgets(line, sizeof(line), list)) {
    size_t L = strlen(line);
    while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
    if (!L) continue;
    FILE *in = fopen(line, "rb");
    if (!in) die(line);
    setvbuf(in, NULL, _IOFBF, 8 << 20);
    uint8_t hdr4[4];
    while (fread(hdr4, 1, 4, in) == 4) {
      uint32_t ln;
      memcpy(&ln, hdr4, 4);
      if (ln > reccap) {
        reccap = ln + (1 << 20);
        recbuf = realloc(recbuf, reccap);
        if (!recbuf) die("realloc");
      }
      if (fread(recbuf, 1, ln, in) != ln) {
        fprintf(stderr, "d1 trunc %s\n", line);
        return 2;
      }
      uint32_t klen, blen, hlen;
      memcpy(&klen, recbuf + 0, 4);
      memcpy(&blen, recbuf + 4, 4);
      memcpy(&hlen, recbuf + 8, 4);
      if (12u + klen + blen + hlen != ln) return 2;
      uint8_t *key = recbuf + 12;
      uint8_t *body = key + klen;
      uint8_t *hashes = body + blen;
      uint32_t zero = 0;
      fwrite(&klen, 4, 1, bodies);
      fwrite(&blen, 4, 1, bodies);
      fwrite(&zero, 4, 1, bodies);
      fwrite(key, 1, klen, bodies);
      fwrite(body, 1, blen, bodies);
      uint32_t owner = (uint32_t)seen;
      uint32_t count = hlen / 16;
      fwrite(&owner, 4, 1, hrefs);
      fwrite(&count, 4, 1, hrefs);
      if (hlen) fwrite(hashes, 1, hlen, hrefs);
      seen++;
      if (seen % 5000000ull == 0)
        fprintf(stderr, "d1 owners=%llu\n", (unsigned long long)seen);
    }
    fclose(in);
  }
  fclose(list);
  fclose(bodies);
  fclose(hrefs);
  free(recbuf);
  printf("owners=%llu\n", (unsigned long long)seen);
  return 0;
}

/* join_merge: sorted ref_rows (28B) ⋈ hash_id (20B) → ids_flat (12B) */
static int do_join_merge(const char *refs_path, const char *hash_id_path,
                         const char *out_path) {
  FILE *left = fopen(refs_path, "rb");
  FILE *right = fopen(hash_id_path, "rb");
  FILE *out = fopen(out_path, "wb");
  if (!left || !right || !out) die("join_merge open");
  setvbuf(left, NULL, _IOFBF, 16 << 20);
  setvbuf(right, NULL, _IOFBF, 16 << 20);
  setvbuf(out, NULL, _IOFBF, 16 << 20);

  uint8_t lrec[28], rrec[20];
  int have_r = fread(rrec, 1, 20, right) == 20;
  uint64_t matched = 0;
  while (fread(lrec, 1, 28, left) == 28) {
    while (have_r && memcmp(rrec, lrec, 16) < 0)
      have_r = fread(rrec, 1, 20, right) == 20;
    if (!have_r || memcmp(rrec, lrec, 16) != 0) {
      fprintf(stderr, "hash ref missing at matched=%llu\n",
              (unsigned long long)matched);
      return 2;
    }
    uint32_t rid, owner, j;
    memcpy(&rid, rrec + 16, 4);
    memcpy(&owner, lrec + 16, 4);
    memcpy(&j, lrec + 20, 4);
    uint8_t o[12];
    memcpy(o + 0, &owner, 4);
    memcpy(o + 4, &j, 4);
    memcpy(o + 8, &rid, 4);
    if (fwrite(o, 1, 12, out) != 12) die("write");
    matched++;
    if (matched % 50000000ull == 0)
      fprintf(stderr, "join matched=%llu\n", (unsigned long long)matched);
  }
  fclose(left);
  fclose(right);
  fclose(out);
  printf("matched=%llu\n", (unsigned long long)matched);
  return 0;
}

/* owner_sort: paths_file → single framed file sorted by full BOGI key */
typedef struct {
  const uint8_t *rec; /* points into arena: [u32 ln][payload] */
  uint32_t klen;
  const uint8_t *key;
} OwnPtr;

static int cmp_ownptr(const void *a, const void *b) {
  const OwnPtr *x = a, *y = b;
  uint32_t n = x->klen < y->klen ? x->klen : y->klen;
  int c = memcmp(x->key, y->key, n);
  if (c) return c;
  return (x->klen > y->klen) - (x->klen < y->klen);
}

typedef struct {
  OwnPtr *p;
  size_t off, len;
} OwnerSeg;

static void *owner_seg_worker(void *arg) {
  OwnerSeg *s = arg;
  qsort(s->p + s->off, s->len, sizeof(OwnPtr), cmp_ownptr);
  return NULL;
}

static void owner_sort_parallel(OwnPtr *ptrs, size_t n) {
  long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
  int nthreads = (int)(ncpu > 0 ? ncpu : 1);
  if (nthreads > 16) nthreads = 16;
  if (n < 100000 || nthreads <= 1) {
    qsort(ptrs, n, sizeof(OwnPtr), cmp_ownptr);
    return;
  }
  size_t seg = (n + (size_t)nthreads - 1) / (size_t)nthreads;
  pthread_t th[16];
  OwnerSeg segs[16];
  int nt = 0;
  for (int t = 0; t < nthreads; t++) {
    size_t off = (size_t)t * seg;
    if (off >= n) break;
    size_t len = seg;
    if (off + len > n) len = n - off;
    segs[nt].p = ptrs;
    segs[nt].off = off;
    segs[nt].len = len;
    nt++;
  }
  for (int t = 0; t < nt; t++) {
    if (pthread_create(&th[t], NULL, owner_seg_worker, &segs[t]) != 0)
      qsort(ptrs + segs[t].off, segs[t].len, sizeof(OwnPtr), cmp_ownptr);
  }
  for (int t = 0; t < nt; t++) pthread_join(th[t], NULL);

  OwnPtr *buf_a = ptrs;
  OwnPtr *buf_b = malloc(n * sizeof(OwnPtr));
  if (!buf_b) die("owner merge buf");
  int a_is_ptrs = 1;
  size_t runs = (size_t)nt;
  size_t runlen = seg;
  while (runs > 1) {
    size_t out_runs = 0;
    for (size_t r = 0; r + 1 < runs; r += 2) {
      size_t lo = r * runlen;
      size_t mid = lo + runlen;
      size_t hi = mid + runlen;
      if (mid > n) mid = n;
      if (hi > n) hi = n;
      size_t i = lo, j = mid, k = lo;
      while (i < mid && j < hi) {
        if (cmp_ownptr(&buf_a[i], &buf_a[j]) <= 0) buf_b[k++] = buf_a[i++];
        else buf_b[k++] = buf_a[j++];
      }
      while (i < mid) buf_b[k++] = buf_a[i++];
      while (j < hi) buf_b[k++] = buf_a[j++];
      out_runs++;
    }
    if (runs % 2 == 1) {
      size_t lo = (runs - 1) * runlen;
      if (lo < n) memcpy(buf_b + lo, buf_a + lo, (n - lo) * sizeof(OwnPtr));
      out_runs++;
    }
    OwnPtr *swap = buf_a;
    buf_a = buf_b;
    buf_b = swap;
    a_is_ptrs = !a_is_ptrs;
    runlen *= 2;
    runs = out_runs;
  }
  if (!a_is_ptrs) {
    memcpy(ptrs, buf_a, n * sizeof(OwnPtr));
    free(buf_a);
  } else {
    free(buf_b);
  }
  fprintf(stderr, "owner_sort parallel threads=%d\n", nt);
}

static int do_owner_sort(const char *paths_file, const char *out_path) {
  /* Pass 1: sum sizes. Pass 2: load into one arena, index, qsort, write. */
  FILE *list = fopen(paths_file, "r");
  if (!list) die(paths_file);
  char line[1024];
  size_t total = 0;
  size_t nfiles = 0;
  while (fgets(line, sizeof(line), list)) {
    size_t L = strlen(line);
    while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
    if (!L) continue;
    struct stat st;
    if (stat(line, &st) != 0) die(line);
    total += (size_t)st.st_size;
    nfiles++;
  }
  rewind(list);
  fprintf(stderr, "owner_sort: %zu files, %zu bytes\n", nfiles, total);
  long avail_kb = mem_available_kb();
  if (total + (1ULL << 30) > (size_t)avail_kb * 1024ull / 2ull) {
    fprintf(stderr, "owner_sort: not enough RAM (need ~%zu, avail %ld kB)\n",
            total, avail_kb);
    fclose(list);
    return 3;
  }
  uint8_t *arena = malloc(total ? total : 1);
  if (!arena) die("arena");
  OwnPtr *ptrs = malloc((total / 32 + 16) * sizeof(OwnPtr)); /* upper bound guess */
  if (!ptrs) die("ptrs");
  size_t n = 0, ncap = total / 32 + 16;
  size_t arena_len = 0;

  while (fgets(line, sizeof(line), list)) {
    size_t L = strlen(line);
    while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
    if (!L) continue;
    FILE *in = fopen(line, "rb");
    if (!in) die(line);
    struct stat st;
    fstat(fileno(in), &st);
    size_t sz = (size_t)st.st_size;
    if (fread(arena + arena_len, 1, sz, in) != sz) die("read");
    size_t off = arena_len;
    size_t end = arena_len + sz;
    while (off + 4 <= end) {
      uint32_t ln;
      memcpy(&ln, arena + off, 4);
      if (off + 4 + ln > end) break;
      uint32_t klen;
      memcpy(&klen, arena + off + 4, 4);
      if (n + 1 > ncap) {
        ncap = ncap * 2;
        ptrs = realloc(ptrs, ncap * sizeof(OwnPtr));
        if (!ptrs) die("realloc ptrs");
      }
      ptrs[n].rec = arena + off;
      ptrs[n].klen = klen;
      ptrs[n].key = arena + off + 4 + 12;
      n++;
      off += 4 + ln;
    }
    arena_len = end;
    fclose(in);
  }
  fclose(list);

  fprintf(stderr, "owner_sort sorting %zu records\n", n);
  owner_sort_parallel(ptrs, n);

  FILE *out = fopen(out_path, "wb");
  if (!out) die(out_path);
  setvbuf(out, NULL, _IOFBF, 16 << 20);
  for (size_t i = 0; i < n; i++) {
    uint32_t ln;
    memcpy(&ln, ptrs[i].rec, 4);
    if (fwrite(ptrs[i].rec, 1, 4 + ln, out) != 4 + ln) die("write");
  }
  fclose(out);
  free(ptrs);
  free(arena);
  printf("records=%zu\n", n);
  return 0;
}

/* Improved esort16: use large in-memory sort when file fits comfortably. */
static int external_sort16_auto(const char *in_path, const char *out_path, size_t rec_size,
                                const char *tmpdir) {
  struct stat st;
  if (stat(in_path, &st) != 0) die(in_path);
  long avail_kb = mem_available_kb();
  /* ptr array + data ≈ 1.3×; leave 8 GiB headroom */
  uint64_t need = (uint64_t)st.st_size + (uint64_t)st.st_size / 4 + (8ULL << 30);
  if ((uint64_t)avail_kb * 1024 > need) {
    fprintf(stderr, "esort16: in-memory sort16 (%lld bytes)\n",
            (long long)st.st_size);
    return sort_by_prefix16(in_path, out_path, rec_size);
  }
  return external_sort16(in_path, out_path, rec_size, tmpdir);
}

/* ---- spill_sort: framed variable records sorted by raw RDATA ----
 * Layout: u32 ln | hash16 | u32 rrset | u32 rdata_ord | u32 raw_len | raw
 * Usage: spill_sort <in.bin> [out.bin]   (out defaults to in via temp)
 */
typedef struct {
  const uint8_t *frame; /* → u32 ln */
  uint32_t frame_bytes; /* 4+ln */
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

static int do_spill_sort(const char *in_path, const char *out_path) {
  const size_t HASH_LEN = 16;
  const size_t RAW_OFF = HASH_LEN + 12; /* 28 */
  size_t len = 0;
  uint8_t *data = map_file(in_path, &len, 0);
  size_t ncap = len / 64 + 16;
  SpillPtr *ptrs = malloc(ncap * sizeof(SpillPtr));
  if (!ptrs) die("malloc spill ptrs");
  size_t n = 0, off = 0;
  while (off + 4 <= len) {
    uint32_t ln;
    memcpy(&ln, data + off, 4);
    if (off + 4 + ln > len) break;
    if (ln < RAW_OFF + 0) {
      fprintf(stderr, "spill rec too short\n");
      return 2;
    }
    uint32_t raw_len;
    memcpy(&raw_len, data + off + 4 + HASH_LEN + 8, 4);
    if (raw_len != ln - (uint32_t)RAW_OFF) {
      fprintf(stderr, "spill raw_len mismatch\n");
      return 2;
    }
    if (n + 1 > ncap) {
      ncap *= 2;
      ptrs = realloc(ptrs, ncap * sizeof(SpillPtr));
      if (!ptrs) die("realloc");
    }
    ptrs[n].frame = data + off;
    ptrs[n].frame_bytes = 4 + ln;
    ptrs[n].raw = data + off + 4 + RAW_OFF;
    ptrs[n].raw_len = raw_len;
    n++;
    off += 4 + ln;
  }
  fprintf(stderr, "spill_sort %zu recs (%zu bytes)\n", n, len);
  qsort(ptrs, n, sizeof(SpillPtr), cmp_spill);

  char tmp_path[512];
  int use_tmp = 0;
  const char *dest = out_path;
  if (!out_path || strcmp(out_path, in_path) == 0) {
    snprintf(tmp_path, sizeof(tmp_path), "%s.sorted", in_path);
    dest = tmp_path;
    use_tmp = 1;
  }
  FILE *out = fopen(dest, "wb");
  if (!out) die(dest);
  setvbuf(out, NULL, _IOFBF, 16 << 20);
  for (size_t i = 0; i < n; i++) {
    if (fwrite(ptrs[i].frame, 1, ptrs[i].frame_bytes, out) != ptrs[i].frame_bytes)
      die("write");
  }
  fclose(out);
  munmap(data, len ? len : 1);
  free(ptrs);
  if (use_tmp) {
    if (rename(dest, in_path) != 0) die("rename spill_sort");
  }
  printf("recs=%zu\n", n);
  return 0;
}

/* ---- unique_merge: k-way merge sorted spill runs, emit unique by raw ----
 * rec buffer layout: [u32 ln][hash16|III|raw...]
 * raw starts at rec + 4 + 28 = rec + 32.
 */
typedef struct {
  FILE *fp;
  uint8_t *rec;
  uint32_t rec_cap;
  uint32_t rec_len;
  uint32_t raw_len;
  int alive;
} URun;

#define URUN_RAW_OFF 32u /* 4 (frame len) + 16 (hash) + 12 (III) */

static int cmp_urun_raw(const URun *a, const URun *b) {
  uint32_t n = a->raw_len < b->raw_len ? a->raw_len : b->raw_len;
  int c = memcmp(a->rec + URUN_RAW_OFF, b->rec + URUN_RAW_OFF, n);
  if (c) return c;
  return (a->raw_len > b->raw_len) - (a->raw_len < b->raw_len);
}

static int urun_next(URun *r) {
  uint8_t hdr[4];
  if (fread(hdr, 1, 4, r->fp) != 4) {
    r->alive = 0;
    return 0;
  }
  uint32_t ln;
  memcpy(&ln, hdr, 4);
  if (ln + 4 > r->rec_cap) {
    r->rec_cap = ln + 4 + (1 << 20);
    r->rec = realloc(r->rec, r->rec_cap);
    if (!r->rec) die("realloc urun");
  }
  memcpy(r->rec, hdr, 4);
  if (fread(r->rec + 4, 1, ln, r->fp) != ln) {
    r->alive = 0;
    return 0;
  }
  r->rec_len = 4 + ln;
  uint32_t raw_len;
  memcpy(&raw_len, r->rec + 4 + 16 + 8, 4);
  if (raw_len != ln - 28u) {
    fprintf(stderr, "unique_merge raw_len mismatch\n");
    return -1;
  }
  r->raw_len = raw_len;
  r->alive = 1;
  return 1;
}

static int do_unique_merge(const char *paths_file, const char *out_path) {
  FILE *list = fopen(paths_file, "r");
  if (!list) die(paths_file);
  char line[1024];
  URun *runs = NULL;
  int n = 0, cap = 0;
  while (fgets(line, sizeof(line), list)) {
    size_t L = strlen(line);
    while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
    if (!L) continue;
    if (n + 1 > cap) {
      cap = cap ? cap * 2 : 64;
      runs = realloc(runs, (size_t)cap * sizeof(URun));
      if (!runs) die("realloc runs");
    }
    memset(&runs[n], 0, sizeof(URun));
    runs[n].fp = fopen(line, "rb");
    if (!runs[n].fp) die(line);
    setvbuf(runs[n].fp, NULL, _IOFBF, 4 << 20);
    runs[n].rec_cap = 1 << 20;
    runs[n].rec = malloc(runs[n].rec_cap);
    if (!runs[n].rec) die("malloc rec");
    if (urun_next(&runs[n]) < 0) return 2;
    n++;
  }
  fclose(list);

  /* binary heap of alive run indices */
  int *heap = malloc((size_t)n * sizeof(int));
  int hsz = 0;
  if (!heap) die("heap");
  for (int i = 0; i < n; i++) {
    if (!runs[i].alive) continue;
    int idx = hsz++;
    heap[idx] = i;
    while (idx > 0) {
      int p = (idx - 1) / 2;
      if (cmp_urun_raw(&runs[heap[p]], &runs[heap[idx]]) <= 0) break;
      int t = heap[p];
      heap[p] = heap[idx];
      heap[idx] = t;
      idx = p;
    }
  }

  FILE *out = fopen(out_path, "wb");
  if (!out) die(out_path);
  setvbuf(out, NULL, _IOFBF, 16 << 20);
  uint64_t unique = 0;
  uint8_t *prev = NULL;
  uint32_t prev_len = 0, prev_cap = 0;

  while (hsz > 0) {
    int bi = heap[0];
    URun *r = &runs[bi];
    int same = 0;
    if (prev && prev_len == r->raw_len &&
        memcmp(prev, r->rec + URUN_RAW_OFF, r->raw_len) == 0)
      same = 1;
    if (!same) {
      if (fwrite(r->rec, 1, r->rec_len, out) != r->rec_len) die("write");
      unique++;
      if (r->raw_len > prev_cap) {
        prev_cap = r->raw_len + 1024;
        prev = realloc(prev, prev_cap);
        if (!prev) die("prev");
      }
      memcpy(prev, r->rec + URUN_RAW_OFF, r->raw_len);
      prev_len = r->raw_len;
      if (unique % 5000000ull == 0)
        fprintf(stderr, "unique=%llu\n", (unsigned long long)unique);
    }
    /* pop heap */
    heap[0] = heap[--hsz];
    int idx = 0;
    for (;;) {
      int l = idx * 2 + 1, ri = l + 1, best = idx;
      if (l < hsz && cmp_urun_raw(&runs[heap[l]], &runs[heap[best]]) < 0) best = l;
      if (ri < hsz && cmp_urun_raw(&runs[heap[ri]], &runs[heap[best]]) < 0) best = ri;
      if (best == idx) break;
      int t = heap[idx];
      heap[idx] = heap[best];
      heap[best] = t;
      idx = best;
    }
    if (urun_next(r) < 0) return 2;
    if (r->alive) {
      idx = hsz++;
      heap[idx] = bi;
      while (idx > 0) {
        int p = (idx - 1) / 2;
        if (cmp_urun_raw(&runs[heap[p]], &runs[heap[idx]]) <= 0) break;
        int t = heap[p];
        heap[p] = heap[idx];
        heap[idx] = t;
        idx = p;
      }
    }
  }

  for (int i = 0; i < n; i++) {
    fclose(runs[i].fp);
    free(runs[i].rec);
  }
  free(runs);
  free(heap);
  free(prev);
  fclose(out);
  printf("unique=%llu\n", (unsigned long long)unique);
  return 0;
}

/* Pass C: one pass over unique_sorted → pool_data + restarts + hash_id_sorted */
static size_t uleb_enc(uint32_t v, uint8_t *out) {
  size_t n = 0;
  while (v >= 0x80) {
    out[n++] = (uint8_t)((v & 0x7f) | 0x80);
    v >>= 7;
  }
  out[n++] = (uint8_t)v;
  return n;
}

static int do_pool_build(const char *sorted_path, const char *pool_path,
                         const char *restarts_path, const char *hash_id_path) {
  const size_t HASH_LEN = 16;
  const size_t BLOCK = 16;
  FILE *in = fopen(sorted_path, "rb");
  if (!in) die(sorted_path);
  FILE *pool = fopen(pool_path, "wb");
  if (!pool) die(pool_path);
  FILE *rst = fopen(restarts_path, "wb");
  if (!rst) die(restarts_path);
  FILE *hid = fopen(hash_id_path, "wb");
  if (!hid) die(hash_id_path);
  setvbuf(in, NULL, _IOFBF, 16 << 20);
  setvbuf(pool, NULL, _IOFBF, 16 << 20);
  setvbuf(hid, NULL, _IOFBF, 16 << 20);

  uint64_t ordinal = 0, pool_off = 0;
  uint8_t *rec = NULL;
  size_t rec_cap = 0;
  uint8_t uleb[16];
  for (;;) {
    uint32_t ln;
    if (fread(&ln, 4, 1, in) != 1) break;
    if (ln < HASH_LEN + 12) {
      fprintf(stderr, "pool_build short rec\n");
      return 2;
    }
    if (ln > rec_cap) {
      rec_cap = ln + 64;
      rec = realloc(rec, rec_cap);
      if (!rec) die("realloc");
    }
    if (fread(rec, 1, ln, in) != ln) {
      fprintf(stderr, "pool_build truncated\n");
      return 2;
    }
    uint32_t rrset_ord, rdata_ord, raw_len;
    memcpy(&rrset_ord, rec + HASH_LEN, 4);
    memcpy(&rdata_ord, rec + HASH_LEN + 4, 4);
    memcpy(&raw_len, rec + HASH_LEN + 8, 4);
    if (raw_len != ln - HASH_LEN - 12) {
      fprintf(stderr, "pool_build raw_len mismatch\n");
      return 2;
    }
    if (ordinal % BLOCK == 0) {
      if (fwrite(&pool_off, 8, 1, rst) != 1) die("restart write");
    }
    size_t n = 0;
    n += uleb_enc(rrset_ord, uleb + n);
    n += uleb_enc(rdata_ord, uleb + n);
    n += uleb_enc(raw_len, uleb + n);
    if (fwrite(uleb, 1, n, pool) != n) die("pool write");
    if (raw_len && fwrite(rec + HASH_LEN + 12, 1, raw_len, pool) != raw_len)
      die("pool write");
    pool_off += n + raw_len;
    if (fwrite(rec, 1, HASH_LEN, hid) != HASH_LEN) die("hid write");
    uint32_t ord32 = (uint32_t)ordinal;
    if (fwrite(&ord32, 4, 1, hid) != 1) die("hid write");
    ordinal++;
    if (ordinal % 5000000ull == 0)
      fprintf(stderr, "pool_build ids=%llu\n", (unsigned long long)ordinal);
  }
  free(rec);
  fclose(in);
  fclose(pool);
  fclose(rst);
  fclose(hid);
  printf("entries=%llu pool_bytes=%llu\n", (unsigned long long)ordinal,
         (unsigned long long)pool_off);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr,
            "usage:\n"
            "  %s scatter <ids_flat.bin> <counts.bin> <out_u32.bin>\n"
            "  %s expand_refs <hash_refs.bin> <ref_rows.bin> <counts.bin>\n"
            "  %s sort16 <in.bin> <out.bin> <rec_size>\n"
            "  %s esort16 <in.bin> <out.bin> <rec_size> <tmpdir>\n"
            "  %s sort8 <in.bin> <out.bin> <rec_size>\n"
            "  %s stream <bodies.bin> <counts.bin> <ids_u32.bin> <stream.bin> <restarts.bin>\n"
            "  %s coalesce <sorted_framed> <out_dir> <block> <spill> <mask_bytes>\n"
            "  %s d1_split <paths_file> <bodies.bin> <hash_refs.bin>\n"
            "  %s join_merge <ref_rows_sorted> <hash_id_by_hash> <ids_flat.bin>\n"
            "  %s owner_sort <paths_file> <out_framed.bin>\n"
            "  %s spill_sort <in.bin> [out.bin]\n"
            "  %s unique_merge <paths_file> <out.bin>\n"
            "  %s pool_build <unique_sorted> <pool> <restarts> <hash_id_sorted>\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0],
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
    return 1;
  }
  if (strcmp(argv[1], "scatter") == 0) {
    if (argc != 5) return 1;
    return do_scatter(argv[2], argv[3], argv[4]);
  }
  if (strcmp(argv[1], "expand_refs") == 0) {
    if (argc != 5) return 1;
    return expand_refs(argv[2], argv[3], argv[4]);
  }
  if (strcmp(argv[1], "sort16") == 0) {
    if (argc != 5) return 1;
    return sort_by_prefix16(argv[2], argv[3], (size_t)atoi(argv[4]));
  }
  if (strcmp(argv[1], "esort16") == 0) {
    if (argc != 6) return 1;
    return external_sort16_auto(argv[2], argv[3], (size_t)atoi(argv[4]), argv[5]);
  }
  if (strcmp(argv[1], "sort8") == 0) {
    if (argc != 5) return 1;
    return sort_by_u64(argv[2], argv[3], (size_t)atoi(argv[4]));
  }
  if (strcmp(argv[1], "stream") == 0) {
    if (argc != 7) return 1;
    return stream_rewrite(argv[2], argv[3], argv[4], argv[5], argv[6]);
  }
  if (strcmp(argv[1], "coalesce") == 0) {
    if (argc != 7) return 1;
    return do_coalesce(argv[2], argv[3], (size_t)atol(argv[4]), (size_t)atol(argv[5]),
                       (size_t)atol(argv[6]));
  }
  if (strcmp(argv[1], "d1_split") == 0) {
    if (argc != 5) return 1;
    return do_d1_split(argv[2], argv[3], argv[4]);
  }
  if (strcmp(argv[1], "join_merge") == 0) {
    if (argc != 5) return 1;
    return do_join_merge(argv[2], argv[3], argv[4]);
  }
  if (strcmp(argv[1], "owner_sort") == 0) {
    if (argc != 4) return 1;
    return do_owner_sort(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "spill_sort") == 0) {
    if (argc < 3 || argc > 4) return 1;
    return do_spill_sort(argv[2], argc == 4 ? argv[3] : NULL);
  }
  if (strcmp(argv[1], "unique_merge") == 0) {
    if (argc != 4) return 1;
    return do_unique_merge(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "pool_build") == 0) {
    if (argc != 6) return 1;
    return do_pool_build(argv[2], argv[3], argv[4], argv[5]);
  }
  fprintf(stderr, "unknown cmd %s\n", argv[1]);
  return 1;
}
