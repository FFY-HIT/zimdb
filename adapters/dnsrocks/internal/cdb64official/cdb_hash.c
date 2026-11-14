/* Public domain. */

#include "cdb.h"

num cdb_hashadd(num h,unsigned char c)
{
  h += (h << 5);
  return (h ^ c) & CDB_HASHMASK;
}

num cdb_hash(const char *buf,num len)
{
  num h;

  h = CDB_HASHSTART;
  while (len > 0) {
    h = cdb_hashadd(h,*buf++);
    --len;
  }
  return h;
}
