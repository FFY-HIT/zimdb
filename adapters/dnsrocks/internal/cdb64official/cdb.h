/* Public domain. */

#ifndef CDB_H
#define CDB_H

#include "num.h"

#ifdef CDB64
#define CDB_LIMIT     0xfffffffffffffffLL
#define CDB_HASHMASK 0xffffffffffffffffULL
#define CDB_HASHTOP(h) (((h)>>8)&0xffffffffffffffLL)
#define CDB_NUMBYTES 8
#define cdb_unpacknum num_from8bytes
#define cdb_packnum num_to8bytes_allowoverflow
#else
#define CDB_LIMIT            0xffffffffLL
#define CDB_HASHMASK         0xffffffffLL
#define CDB_HASHTOP(h) ((h)>>8)
#define CDB_NUMBYTES 4
#define cdb_unpacknum num_from4bytes
#define cdb_packnum num_to4bytes_allowoverflow
#endif

#ifdef CDB64
#define cdb cdb64
#define cdb_hashadd cdb64_hashadd
#define cdb_hash cdb64_hash
#define cdb_free cdb64_free
#define cdb_init cdb64_init
#define cdb_read cdb64_read
#define cdb_findstart cdb64_findstart
#define cdb_findnext cdb64_findnext
#define cdb_find cdb64_find
#endif

#define CDB_HASHSTART 5381
extern num cdb_hashadd(num,unsigned char);
extern num cdb_hash(const char *,num);

struct cdb {
  char *map; /* 0 if no map is available */
  num fd;
  num size; /* initialized if map is nonzero */
  num loop; /* number of hash slots searched under this key */
  num khash; /* initialized if loop is nonzero */
  num kpos; /* initialized if loop is nonzero */
  num hpos; /* initialized if loop is nonzero */
  num hslots; /* initialized if loop is nonzero */
  num dpos; /* initialized if cdb_findnext() returns 1 */
  num dlen; /* initialized if cdb_findnext() returns 1 */
} ;

extern void cdb_free(struct cdb *);
extern void cdb_init(struct cdb *,num);

extern num cdb_read(struct cdb *,char *,num,num);

extern void cdb_findstart(struct cdb *);
extern num cdb_findnext(struct cdb *,const char *,num);
extern num cdb_find(struct cdb *,const char *,num);

#define cdb_datapos(c) ((c)->dpos)
#define cdb_datalen(c) ((c)->dlen)

#endif
